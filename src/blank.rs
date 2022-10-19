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

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::OutPoint;
use bp::seals::txout::CloseMethod;
use rgb_core::bundle::NoDataError;
use rgb_core::schema::OwnedRightType;
use rgb_core::vm::embedded::constants::TRANSITION_TYPE_VALUE_TRANSFER;
use rgb_core::{
    seal, NodeId, NodeOutpoint, OwnedRights, ParentOwnedRights, Transition, TransitionBundle,
    TypedAssignments,
};

use crate::state::OutpointState;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// no seal definition outpoint provided for an owned right type {0}
    NoOutpoint(OwnedRightType),

    /// duplicate assignments at {0}
    DuplicateAssignments(NodeOutpoint, TypedAssignments),

    /// unable to construct blank state transition bundle from empty previous state
    #[from(NoDataError)]
    EmptyData,
}

pub trait BlankBundle {
    fn blank(
        prev_state: &BTreeMap<OutPoint, BTreeSet<OutpointState>>,
        new_outpoints: &BTreeMap<OwnedRightType, (OutPoint, CloseMethod)>,
    ) -> Result<TransitionBundle, Error>;
}

impl BlankBundle for TransitionBundle {
    fn blank(
        prev_state: &BTreeMap<OutPoint, BTreeSet<OutpointState>>,
        new_outpoints: &BTreeMap<OwnedRightType, (OutPoint, CloseMethod)>,
    ) -> Result<TransitionBundle, Error> {
        let mut transitions: BTreeMap<Transition, BTreeSet<u16>> = bmap! {};

        for (tx_outpoint, inputs) in prev_state {
            let mut parent_owned_rights: BTreeMap<NodeId, BTreeMap<OwnedRightType, Vec<u16>>> =
                bmap! {};
            let mut owned_rights: BTreeMap<OwnedRightType, TypedAssignments> = bmap! {};
            for OutpointState {
                node_outpoint: input,
                state,
            } in inputs
            {
                parent_owned_rights
                    .entry(input.node_id)
                    .or_default()
                    .entry(input.ty)
                    .or_default()
                    .push(input.no);
                let (op, close_method) = new_outpoints
                    .get(&input.ty)
                    .ok_or(Error::NoOutpoint(input.ty))?;
                let new_seal = seal::Revealed::new(*close_method, *op);
                let new_assignments = state.to_revealed_assignment_vec(new_seal);
                owned_rights.insert(input.ty, new_assignments);
            }
            let transition = Transition::with(
                TRANSITION_TYPE_VALUE_TRANSFER,
                empty!(),
                empty!(),
                OwnedRights::from(owned_rights),
                empty!(),
                ParentOwnedRights::from(parent_owned_rights),
            );
            transitions.insert(transition, bset! { tx_outpoint.vout as u16 });
        }

        TransitionBundle::try_from(transitions).map_err(Error::from)
    }
}
