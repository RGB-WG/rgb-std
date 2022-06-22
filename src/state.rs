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

use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::Deref;
use std::slice;

use bitcoin::{OutPoint, Txid};
use bp::seals::txout::TxoSeal;
use commit_verify::CommitConceal;
use rgb_core::contract::attachment;
use rgb_core::schema::{FieldType, OwnedRightType};
use rgb_core::{
    data, seal, Assignment, AssignmentVec, AtomicValue, AttachmentStrategy, ContractId,
    DeclarativeStrategy, Genesis, HashStrategy, Node, NodeId, NodeOutpoint, PedersenStrategy,
    State,
};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr, Same};
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
    pub seal: OutPoint,
    pub state: State,
    pub outpoint: NodeOutpoint,
}

impl<State> AssignedState<State>
where State: StateAtom
{
    pub fn with(
        seal: seal::Revealed,
        witness_txid: Txid,
        state: State,
        node_id: NodeId,
        no: u16,
    ) -> Self {
        AssignedState {
            seal: seal.outpoint_or(witness_txid),
            state,
            outpoint: NodeOutpoint::new(node_id, no),
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
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeMap<Same, Vec<DisplayFromStr>>>"))]
    pub owned_rights: BTreeMap<OwnedRightType, Vec<OwnedRight>>,
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeMap<Same, Vec<DisplayFromStr>>>"))]
    pub owned_values: BTreeMap<OwnedRightType, Vec<OwnedValue>>,
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeMap<Same, Vec<DisplayFromStr>>>"))]
    pub owned_data: BTreeMap<OwnedRightType, Vec<OwnedData>>,
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeMap<Same, Vec<DisplayFromStr>>>"))]
    pub owned_attachments: BTreeMap<OwnedRightType, Vec<OwnedAttachment>>,
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
        state.extend(zero!(), genesis);
        state
    }

    pub fn extend(&mut self, txid: Txid, node: &impl Node) {
        let node_id = node.node_id();

        for (ty, meta) in node.metadata() {
            self.metadata
                .entry(*ty)
                .or_default()
                .extend(meta.iter().cloned());
        }

        fn process<S: StateAtom>(
            fields: &mut Vec<AssignedState<S>>,
            assignments: &[Assignment<S::StateType>],
            node_id: NodeId,
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
                    AssignedState::with(seal, txid, state.into(), node_id, no as u16);
                fields.push(assigned_state);
            }
        }

        for (ty, assignments) in node.owned_rights().iter() {
            match assignments {
                AssignmentVec::Declarative(assignments) => {
                    let fields = self.owned_rights.entry(*ty).or_default();
                    process(fields, assignments, node_id, txid)
                }
                AssignmentVec::Fungible(assignments) => {
                    let fields = self.owned_values.entry(*ty).or_default();
                    process(fields, assignments, node_id, txid)
                }
                AssignmentVec::NonFungible(assignments) => {
                    let fields = self.owned_data.entry(*ty).or_default();
                    process(fields, assignments, node_id, txid)
                }
                AssignmentVec::Attachment(assignments) => {
                    let fields = self.owned_attachments.entry(*ty).or_default();
                    process(fields, assignments, node_id, txid)
                }
            }
        }
    }

    pub fn metadata(&self, ty: FieldType) -> slice::Iter<data::Revealed> {
        self.metadata
            .get(&ty)
            .map(Vec::deref)
            .map(<[_]>::iter)
            .unwrap_or_else(|| [].iter())
    }

    pub fn owned_rights(&self, ty: OwnedRightType) -> slice::Iter<OwnedRight> {
        self.owned_rights
            .get(&ty)
            .map(Vec::deref)
            .map(<[_]>::iter)
            .unwrap_or_else(|| [].iter())
    }

    pub fn owned_values(&self, ty: OwnedRightType) -> slice::Iter<OwnedValue> {
        self.owned_values
            .get(&ty)
            .map(Vec::deref)
            .map(<[_]>::iter)
            .unwrap_or_else(|| [].iter())
    }

    pub fn owned_data(&self, ty: OwnedRightType) -> slice::Iter<OwnedData> {
        self.owned_data
            .get(&ty)
            .map(Vec::deref)
            .map(<[_]>::iter)
            .unwrap_or_else(|| [].iter())
    }

    pub fn owned_attachments(&self, ty: OwnedRightType) -> slice::Iter<OwnedAttachment> {
        self.owned_attachments
            .get(&ty)
            .map(Vec::deref)
            .map(<[_]>::iter)
            .unwrap_or_else(|| [].iter())
    }
}
