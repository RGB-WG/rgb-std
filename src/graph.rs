// RGB Standard Library: high-level API to RGB smart contracts.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::BTreeSet;

use bitcoin::{OutPoint, Txid};
use bp::seals::txout::TxoSeal;

use crate::schema::OwnedRightType;
use crate::{
    BundleId, ConsistencyError, Extension, FullConsignment, GraphApi, Node, NodeId, Transition,
    TransitionBundle,
};

impl GraphApi for FullConsignment {
    fn node_by_id(&self, node_id: NodeId) -> Option<&dyn Node> {
        if self.genesis.node_id() == node_id {
            return Some(&self.genesis);
        }
        self.state_extensions
            .iter()
            .find(|extension| extension.node_id() == node_id)
            .map(|extension| extension as &dyn Node)
            .or_else(|| {
                self.anchored_bundles
                    .iter()
                    .flat_map(|(_, bundle)| bundle.known_transitions())
                    .find(|transition| transition.node_id() == node_id)
                    .map(|transition| transition as &dyn Node)
            })
    }

    fn known_transitions_by_bundle_id(
        &self,
        bundle_id: BundleId,
    ) -> Result<Vec<&Transition>, ConsistencyError> {
        Ok(self.bundle_by_id(bundle_id)?.known_transitions().collect())
    }

    fn bundle_by_id(&self, bundle_id: BundleId) -> Result<&TransitionBundle, ConsistencyError> {
        self.anchored_bundles
            .iter()
            .map(|(_, bundle)| bundle)
            .find(|bundle| bundle.bundle_id() == bundle_id)
            .ok_or(ConsistencyError::BundleIdAbsent(bundle_id))
    }

    fn transition_by_id(&self, node_id: NodeId) -> Result<&Transition, ConsistencyError> {
        Ok(self.transition_witness_by_id(node_id)?.0)
    }

    fn extension_by_id(&self, node_id: NodeId) -> Result<&Extension, ConsistencyError> {
        self.state_extensions
            .iter()
            .find(|extension| extension.node_id() == node_id)
            .ok_or(ConsistencyError::ExtensionAbsent(node_id))
    }

    fn transition_witness_by_id(
        &self,
        node_id: NodeId,
    ) -> Result<(&Transition, Txid), ConsistencyError> {
        self.anchored_bundles
            .iter()
            .find_map(|(anchor, bundle)| {
                bundle
                    .known_transitions()
                    .into_iter()
                    .find(|transition| transition.node_id() == node_id)
                    .map(|transition| (transition, anchor.txid))
            })
            .ok_or(ConsistencyError::TransitionAbsent(node_id))
    }

    fn seals_closed_with(
        &self,
        node_id: NodeId,
        owned_right_type: impl Into<OwnedRightType>,
        witness: Txid,
    ) -> Result<BTreeSet<OutPoint>, ConsistencyError> {
        let owned_right_type = owned_right_type.into();
        let transition = self.transition_by_id(node_id)?;
        let mut closed_seals = bset!();
        for output in transition.parent_outputs_by_type(owned_right_type) {
            let parent = self.transition_by_id(output.node_id)?;
            let outpoint = parent
                .owned_rights_by_type(owned_right_type)
                .ok_or(ConsistencyError::NoSealsClosed(owned_right_type, node_id))?
                .revealed_seal_at(output.output_no)
                .map_err(|_| ConsistencyError::OutputNotPresent(output))?
                .ok_or(ConsistencyError::ConfidentialSeal(output))?
                .outpoint_or(witness);
            closed_seals.insert(outpoint);
        }
        Ok(closed_seals)
    }
}
