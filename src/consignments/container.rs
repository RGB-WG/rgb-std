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
use std::io;
use std::marker::PhantomData;

use bitcoin::Txid;
use commit_verify::{commit_encode, ConsensusCommit};
use rgb_core::{
    schema, BundleId, ConsistencyError, Extension, Genesis, GraphApi, Node, NodeId, Schema,
    Transition, TransitionBundle,
};
use strict_encoding::StrictDecode;

use super::{AnchoredBundles, ConsignmentEndpoints, ConsignmentType, ExtensionList};
use crate::ConsignmentId;

pub const RGB_INMEM_CONSIGNMENT_VERSION: u8 = 0;

/// Consignment represents contract-specific data, always starting with genesis,
/// which must be valid under client-side-validation rules (i.e. internally
/// consistent and properly committed into the commitment layer, like bitcoin
/// blockchain or current state of the lightning channel).
///
/// All consignments-related procedures, including validation or merging
/// consignments data into stash or schema-specific data storage, must start with
/// `endpoints` and process up to the genesis. If any of the nodes within the
/// consignments are not part of the paths connecting endpoints with the genesis,
/// consignments validation will return
/// [`crate::validation::Warning::ExcessiveNode`] warning
#[cfg_attr(
    all(feature = "cli", feature = "serde"),
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Clone, PartialEq, Eq, Debug, StrictEncode)]
pub struct InmemConsignment<T>
where T: ConsignmentType
{
    /// Version, used internally
    version: u8,

    pub schema: Schema,

    pub root_schema: Option<Schema>,

    /// Genesis data
    pub genesis: Genesis,

    /// The final state ("endpoints") provided by this consignments.
    ///
    /// There are two reasons for having endpoints:
    /// - navigation towards genesis from the final state is more
    ///   computationally efficient, since state transition/extension graph is
    ///   directed towards genesis (like bitcoin transaction graph)
    /// - if the consignments contains concealed state (known by the receiver),
    ///   it will be computationally inefficient to understand which of the
    ///   state transitions represent the final state
    pub endpoints: ConsignmentEndpoints,

    /// Data on all anchored state transitions contained in the consignments
    pub anchored_bundles: AnchoredBundles,

    /// Data on all state extensions contained in the consignments
    pub state_extensions: ExtensionList,

    #[strict_encoding(skip)]
    _phantom: PhantomData<T>,
}

impl<T> commit_encode::Strategy for InmemConsignment<T>
where T: ConsignmentType
{
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl<T> ConsensusCommit for InmemConsignment<T>
where T: ConsignmentType
{
    type Commitment = ConsignmentId;
}

impl<T> StrictDecode for InmemConsignment<T>
where T: ConsignmentType
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        let consignment = Self {
            version: StrictDecode::strict_decode(&mut d)?,
            schema: StrictDecode::strict_decode(&mut d)?,
            root_schema: StrictDecode::strict_decode(&mut d)?,
            genesis: StrictDecode::strict_decode(&mut d)?,
            endpoints: StrictDecode::strict_decode(&mut d)?,
            anchored_bundles: StrictDecode::strict_decode(&mut d)?,
            state_extensions: StrictDecode::strict_decode(&mut d)?,
            _phantom: none!(),
        };
        if consignment.version != RGB_INMEM_CONSIGNMENT_VERSION {
            return Err(strict_encoding::Error::UnsupportedDataStructure(
                "State transfer versions above 0 are not supported",
            ));
        }
        Ok(consignment)
    }
}

impl<T> InmemConsignment<T>
where T: ConsignmentType
{
    #[inline]
    pub fn with(
        schema: Schema,
        root_schema: Option<Schema>,
        genesis: Genesis,
        endpoints: ConsignmentEndpoints,
        anchored_bundles: AnchoredBundles,
        state_extensions: ExtensionList,
    ) -> Self {
        Self {
            version: RGB_INMEM_CONSIGNMENT_VERSION,
            schema,
            root_schema,
            genesis,
            endpoints,
            state_extensions,
            anchored_bundles,
            _phantom: none!(),
        }
    }

    #[inline]
    pub fn id(&self) -> ConsignmentId { self.clone().consensus_commit() }

    #[inline]
    pub fn version(&self) -> u8 { self.version }

    #[inline]
    pub fn txids(&self) -> BTreeSet<Txid> {
        self.anchored_bundles
            .iter()
            .map(|(anchor, _)| anchor.txid)
            .collect()
    }

    #[inline]
    pub fn node_ids(&self) -> BTreeSet<NodeId> {
        let mut set = bset![self.genesis.node_id()];
        set.extend(
            self.anchored_bundles
                .iter()
                .flat_map(|(_, bundle)| bundle.known_node_ids()),
        );
        set.extend(self.state_extensions.iter().map(Extension::node_id));
        set
    }

    #[inline]
    pub fn endpoint_bundle_ids(&self) -> BTreeSet<BundleId> {
        self.endpoints
            .iter()
            .map(|(bundle_id, _)| bundle_id)
            .copied()
            .collect()
    }

    #[inline]
    pub fn endpoint_bundles(&self) -> Vec<&TransitionBundle> {
        self.endpoint_bundle_ids()
            .into_iter()
            .filter_map(|bundle_id| self.bundle_by_id(bundle_id).ok())
            .collect()
    }

    #[inline]
    pub fn endpoint_transition_by_id(
        &self,
        node_id: NodeId,
    ) -> Result<&Transition, ConsistencyError> {
        if self
            .endpoints
            .iter()
            .filter_map(|(id, _)| self.bundle_by_id(*id).ok())
            .flat_map(|bundle| bundle.known_node_ids())
            .any(|id| id == node_id)
        {
            return Err(ConsistencyError::NotEndpoint(node_id));
        }

        self.transition_by_id(node_id)
    }

    #[inline]
    pub fn endpoint_transitions_by_type(
        &self,
        transition_type: schema::TransitionType,
    ) -> Vec<&Transition> {
        self.endpoint_transitions_by_types(&[transition_type])
    }

    #[inline]
    pub fn endpoint_transitions_by_types(
        &self,
        types: &[schema::TransitionType],
    ) -> Vec<&Transition> {
        self.endpoint_bundle_ids()
            .into_iter()
            .filter_map(|bundle_id| self.known_transitions_by_bundle_id(bundle_id).ok())
            .flat_map(Vec::into_iter)
            .filter(|node| types.contains(&node.transition_type()))
            .collect()
    }
}
