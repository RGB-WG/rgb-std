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
use std::fmt::{Debug, Display};
use std::hash::Hash;

use bitcoin::{OutPoint, Txid};
use bp::seals::txout::TxoSeal;
use commit_verify::CommitConceal;
use rgb_core::contract::attachment;
use rgb_core::schema::{FieldType, OwnedRightType};
use rgb_core::{
    data, seal, Assignment, AssignmentVec, AtomicValue, AttachmentStrategy, ContractId,
    DeclarativeStrategy, Extension, Genesis, HashStrategy, Node, NodeId, NodeOutpoint,
    PedersenStrategy, State, Transition,
};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use strict_encoding::{StrictDecode, StrictEncode};

pub trait StateAtom:
    Clone
    + Eq
    + Ord
    + Hash
    + Debug
    + Display
    + StrictEncode
    + StrictDecode
    + From<<Self::StateType as State>::Revealed>
{
    type StateType: State;
}
impl StateAtom for data::Void {
    type StateType = DeclarativeStrategy;
}
impl StateAtom for AtomicValue {
    type StateType = PedersenStrategy;
}
impl StateAtom for data::Revealed {
    type StateType = HashStrategy;
}
impl StateAtom for attachment::Revealed {
    type StateType = AttachmentStrategy;
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[display("{state}@{seal}")]
pub struct AssignedState<State>
where State: StateAtom
{
    pub outpoint: NodeOutpoint,
    pub seal: OutPoint,
    pub state: State,
}

impl<State> AssignedState<State>
where State: StateAtom
{
    pub fn with(
        seal: seal::Revealed,
        witness_txid: Txid,
        state: State,
        node_id: NodeId,
        ty: OwnedRightType,
        no: u16,
    ) -> Self {
        AssignedState {
            outpoint: NodeOutpoint::new(node_id, ty, no),
            seal: seal.outpoint_or(witness_txid),
            state,
        }
    }
}

pub type OwnedRight = AssignedState<data::Void>;
pub type OwnedValue = AssignedState<AtomicValue>;
pub type OwnedData = AssignedState<data::Revealed>;
pub type OwnedAttachment = AssignedState<attachment::Revealed>;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize), serde(crate = "serde_crate"))]
pub struct ContractState {
    pub contract_id: ContractId,
    pub metadata: BTreeMap<FieldType, Vec<data::Revealed>>,
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub owned_rights: BTreeSet<OwnedRight>,
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub owned_values: BTreeSet<OwnedValue>,
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub owned_data: BTreeSet<OwnedData>,
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub owned_attachments: BTreeSet<OwnedAttachment>,
}

impl ContractState {
    pub fn with(contract_id: ContractId, genesis: &Genesis) -> Self {
        let mut state = ContractState {
            contract_id,
            metadata: empty!(),
            owned_rights: empty!(),
            owned_values: empty!(),
            owned_data: empty!(),
            owned_attachments: empty!(),
        };
        state.add_node(zero!(), genesis);
        state
    }

    pub fn add_transition(&mut self, txid: Txid, transition: &Transition) {
        self.add_node(txid, transition);
    }

    pub fn add_extension(&mut self, extension: &Extension) { self.add_node(zero!(), extension); }

    fn add_node(&mut self, txid: Txid, node: &impl Node) {
        let node_id = node.node_id();

        for (ty, meta) in node.metadata() {
            self.metadata
                .entry(*ty)
                .or_default()
                .extend(meta.iter().cloned());
        }

        fn process<S: StateAtom>(
            contract_state: &mut BTreeSet<AssignedState<S>>,
            assignments: &[Assignment<S::StateType>],
            node_id: NodeId,
            ty: OwnedRightType,
            txid: Txid,
        ) where
            <S::StateType as State>::Confidential: Eq
                + From<<<S::StateType as State>::Revealed as CommitConceal>::ConcealedCommitment>,
        {
            for (no, seal, state) in assignments
                .iter()
                .enumerate()
                .filter_map(|(n, a)| a.to_revealed().map(|(seal, state)| (n, seal, state)))
            {
                let assigned_state =
                    AssignedState::with(seal, txid, state.into(), node_id, ty, no as u16);
                contract_state.insert(assigned_state);
            }
        }

        // Remove invalidated state
        for output in node.parent_outputs() {
            if let Some(o) = self.owned_rights.iter().find(|r| r.outpoint == output) {
                let o = o.clone(); // need this b/c of borrow checker
                self.owned_rights.remove(&o);
            }
            if let Some(o) = self.owned_values.iter().find(|r| r.outpoint == output) {
                let o = o.clone();
                self.owned_values.remove(&o);
            }
            if let Some(o) = self.owned_data.iter().find(|r| r.outpoint == output) {
                let o = o.clone();
                self.owned_data.remove(&o);
            }
            if let Some(o) = self.owned_attachments.iter().find(|r| r.outpoint == output) {
                let o = o.clone();
                self.owned_attachments.remove(&o);
            }
        }

        for (ty, assignments) in node.owned_rights().iter() {
            match assignments {
                AssignmentVec::Declarative(assignments) => {
                    process(&mut self.owned_rights, assignments, node_id, *ty, txid)
                }
                AssignmentVec::Fungible(assignments) => {
                    process(&mut self.owned_values, assignments, node_id, *ty, txid)
                }
                AssignmentVec::NonFungible(assignments) => {
                    process(&mut self.owned_data, assignments, node_id, *ty, txid)
                }
                AssignmentVec::Attachment(assignments) => {
                    process(&mut self.owned_attachments, assignments, node_id, *ty, txid)
                }
            }
        }
    }
}
