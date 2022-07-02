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

use bitcoin::{OutPoint, Txid};
use bp::seals::txout::CloseMethod;
use rgb_core::schema::OwnedRightType;
use rgb_core::{
    seal, Assignment, AssignmentVec, Extension, Genesis, Node, NodeId, NodeOutpoint, OwnedRights,
    ParentOwnedRights, Transition, TransitionBundle,
};

pub const BLANK_TRANSITION_TYPE: u16 = 0x8000;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum Error {
    /// no seal definition outpoint provided for an owned right type {0}
    NoOutpoint(OwnedRightType),

    /// duplicate assignments at {0}
    DuplicateAssignments(NodeOutpoint, AssignmentVec),
}

pub trait BlankBundle {
    fn blank<'nodes>(
        genesis: Option<&'nodes Genesis>,
        prev_transitions: impl IntoIterator<Item = (&'nodes Transition, Txid)>,
        prev_extensions: impl IntoIterator<Item = &'nodes Extension>,
        prev_outpoints: impl IntoIterator<Item = OutPoint>,
        new_outpoints: &BTreeMap<OwnedRightType, (OutPoint, CloseMethod)>,
    ) -> Result<TransitionBundle, Error>;
}

impl BlankBundle for TransitionBundle {
    fn blank<'nodes>(
        genesis: Option<&'nodes Genesis>,
        prev_transitions: impl IntoIterator<Item = (&'nodes Transition, Txid)>,
        prev_extensions: impl IntoIterator<Item = &'nodes Extension>,
        prev_outpoints: impl IntoIterator<Item = OutPoint>,
        new_outpoints: &BTreeMap<OwnedRightType, (OutPoint, CloseMethod)>,
    ) -> Result<TransitionBundle, Error> {
        let mut inputs: BTreeMap<OutPoint, BTreeSet<NodeOutpoint>> = bmap! {};
        let mut assignments: BTreeMap<NodeOutpoint, &AssignmentVec> = bmap! {};
        if let Some(genesis) = genesis {
            for (node_outpoint, tx_outpoint) in genesis.node_outputs(zero!()) {
                inputs.entry(tx_outpoint).or_default().insert(node_outpoint);
                if let Some(vec) = genesis.owned_rights_by_type(node_outpoint.ty) {
                    if assignments.insert(node_outpoint, vec).is_some() {
                        return Err(Error::DuplicateAssignments(node_outpoint, vec.clone()));
                    }
                }
            }
        }
        for (transition, txid) in prev_transitions {
            for (node_outpoint, tx_outpoint) in transition.node_outputs(txid) {
                inputs.entry(tx_outpoint).or_default().insert(node_outpoint);
                if let Some(vec) = transition.owned_rights_by_type(node_outpoint.ty) {
                    if assignments.insert(node_outpoint, vec).is_some() {
                        return Err(Error::DuplicateAssignments(node_outpoint, vec.clone()));
                    }
                }
            }
        }
        for extension in prev_extensions {
            for (node_outpoint, tx_outpoint) in extension.node_outputs(empty!()) {
                inputs.entry(tx_outpoint).or_default().insert(node_outpoint);
                if let Some(vec) = extension.owned_rights_by_type(node_outpoint.ty) {
                    if assignments.insert(node_outpoint, vec).is_some() {
                        return Err(Error::DuplicateAssignments(node_outpoint, vec.clone()));
                    }
                }
            }
        }

        let mut transitions: BTreeMap<Transition, BTreeSet<u16>> = bmap! {};
        for (tx_outpoint, input_outpoints) in prev_outpoints
            .into_iter()
            .filter_map(|outpoint| inputs.get(&outpoint).map(|set| (outpoint, set)))
        {
            let mut parent_owned_rights: BTreeMap<NodeId, BTreeMap<OwnedRightType, Vec<u16>>> =
                bmap! {};
            let mut owned_rights: BTreeMap<OwnedRightType, AssignmentVec> = bmap! {};
            for input in input_outpoints {
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
                let new_assignments = match assignments
                    .get(input)
                    .expect("blank transition algorithm broken")
                {
                    AssignmentVec::Declarative(vec) => AssignmentVec::Declarative(
                        vec.iter()
                            .map(|a| Assignment::with_seal_replaced(a, new_seal))
                            .collect(),
                    ),
                    AssignmentVec::Fungible(vec) => AssignmentVec::Fungible(
                        vec.iter()
                            .map(|a| Assignment::with_seal_replaced(a, new_seal))
                            .collect(),
                    ),
                    AssignmentVec::NonFungible(vec) => AssignmentVec::NonFungible(
                        vec.iter()
                            .map(|a| Assignment::with_seal_replaced(a, new_seal))
                            .collect(),
                    ),
                    AssignmentVec::Attachment(vec) => AssignmentVec::Attachment(
                        vec.iter()
                            .map(|a| Assignment::with_seal_replaced(a, new_seal))
                            .collect(),
                    ),
                };
                owned_rights.insert(input.ty, new_assignments);
            }
            let transition = Transition::with(
                BLANK_TRANSITION_TYPE,
                empty!(),
                empty!(),
                OwnedRights::from(owned_rights),
                empty!(),
                ParentOwnedRights::from(parent_owned_rights),
            );
            transitions.insert(transition, bset! { tx_outpoint.vout as u16 });
        }
        Ok(TransitionBundle::from(transitions))
    }
}
