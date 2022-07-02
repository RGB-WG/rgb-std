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
    data, seal, value, Assignment, AttachmentStrategy, ContractId, DeclarativeStrategy, Extension,
    Genesis, HashStrategy, Node, NodeId, NodeOutpoint, PedersenStrategy, SchemaId, State,
    Transition, TypedAssignments,
};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr, Same};
use strict_encoding::{StrictDecode, StrictEncode};

pub type OutpointStateMap = BTreeMap<OutPoint, BTreeSet<OutpointState>>;
pub type ContractStateMap = BTreeMap<ContractId, OutpointStateMap>;

pub trait StateTrait:
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
impl StateTrait for data::Void {
    type StateType = DeclarativeStrategy;
}
impl StateTrait for value::Revealed {
    type StateType = PedersenStrategy;
}
impl StateTrait for data::Revealed {
    type StateType = HashStrategy;
}
impl StateTrait for attachment::Revealed {
    type StateType = AttachmentStrategy;
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[derive(StrictEncode, StrictDecode)]
#[display(inner)]
pub enum StateAtom {
    #[display("void")]
    #[from(data::Void)]
    Void,

    #[from]
    Value(value::Revealed),

    #[from]
    Data(data::Revealed),

    #[from]
    Attachment(attachment::Revealed),
}

impl StateAtom {
    pub fn to_revealed_assignment_vec(&self, seal: seal::Revealed) -> TypedAssignments {
        match self {
            StateAtom::Void => TypedAssignments::Void(vec![Assignment::Revealed {
                seal,
                state: data::Void(),
            }]),
            StateAtom::Value(state) => TypedAssignments::Value(vec![Assignment::Revealed {
                seal,
                state: *state,
            }]),
            StateAtom::Data(state) => TypedAssignments::Data(vec![Assignment::Revealed {
                seal,
                state: state.clone(),
            }]),
            StateAtom::Attachment(state) => {
                TypedAssignments::Attachment(vec![Assignment::Revealed {
                    seal,
                    state: state.clone(),
                }])
            }
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[display("{state}@{seal}")]
pub struct AssignedState<State>
where State: StateTrait
{
    pub outpoint: NodeOutpoint,
    pub seal: OutPoint,
    pub state: State,
}

impl<State> AssignedState<State>
where State: StateTrait
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
pub type OwnedValue = AssignedState<value::Revealed>;
pub type OwnedData = AssignedState<data::Revealed>;
pub type OwnedAttachment = AssignedState<attachment::Revealed>;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize), serde(crate = "serde_crate"))]
#[display("{state}@{node_outpoint}")]
pub struct OutpointState {
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    pub node_outpoint: NodeOutpoint,
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    pub state: StateAtom,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize), serde(crate = "serde_crate"))]
pub struct ContractState {
    pub schema_id: SchemaId,
    pub root_schema_id: Option<SchemaId>,
    pub contract_id: ContractId,
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeMap<Same, Vec<DisplayFromStr>>>"))]
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
    pub fn with(
        schema_id: SchemaId,
        root_schema_id: Option<SchemaId>,
        contract_id: ContractId,
        genesis: &Genesis,
    ) -> Self {
        let mut state = ContractState {
            schema_id,
            root_schema_id,
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

    pub fn outpoint_state(&self, outpoint: OutPoint) -> BTreeSet<OutpointState> {
        let mut state: BTreeSet<OutpointState> = bset! {};
        for owned_right in &self.owned_rights {
            if owned_right.seal == outpoint {
                state.insert(OutpointState {
                    node_outpoint: owned_right.outpoint,
                    state: StateAtom::Void,
                });
            }
        }
        for owned_value in &self.owned_values {
            if owned_value.seal == outpoint {
                state.insert(OutpointState {
                    node_outpoint: owned_value.outpoint,
                    state: owned_value.state.clone().into(),
                });
            }
        }
        for owned_data in &self.owned_data {
            if owned_data.seal == outpoint {
                state.insert(OutpointState {
                    node_outpoint: owned_data.outpoint,
                    state: owned_data.state.clone().into(),
                });
            }
        }
        for owned_attachment in &self.owned_attachments {
            if owned_attachment.seal == outpoint {
                state.insert(OutpointState {
                    node_outpoint: owned_attachment.outpoint,
                    state: owned_attachment.clone().state.into(),
                });
            }
        }
        state
    }

    pub fn all_outpoint_state(&self) -> OutpointStateMap {
        let mut state: BTreeMap<OutPoint, BTreeSet<OutpointState>> = bmap! {};
        for owned_right in &self.owned_rights {
            state
                .entry(owned_right.seal)
                .or_default()
                .insert(OutpointState {
                    node_outpoint: owned_right.outpoint,
                    state: StateAtom::Void,
                });
        }
        for owned_value in &self.owned_values {
            state
                .entry(owned_value.seal)
                .or_default()
                .insert(OutpointState {
                    node_outpoint: owned_value.outpoint,
                    state: owned_value.state.clone().into(),
                });
        }
        for owned_data in &self.owned_data {
            state
                .entry(owned_data.seal)
                .or_default()
                .insert(OutpointState {
                    node_outpoint: owned_data.outpoint,
                    state: owned_data.state.clone().into(),
                });
        }
        for owned_attachment in &self.owned_attachments {
            state
                .entry(owned_attachment.seal)
                .or_default()
                .insert(OutpointState {
                    node_outpoint: owned_attachment.outpoint,
                    state: owned_attachment.state.clone().into(),
                });
        }
        state
    }

    pub fn filter_outpoint_state(&self, outpoints: &BTreeSet<OutPoint>) -> OutpointStateMap {
        let mut state: BTreeMap<OutPoint, BTreeSet<OutpointState>> = bmap! {};
        for owned_right in &self.owned_rights {
            if outpoints.contains(&owned_right.seal) {
                state
                    .entry(owned_right.seal)
                    .or_default()
                    .insert(OutpointState {
                        node_outpoint: owned_right.outpoint,
                        state: StateAtom::Void,
                    });
            }
        }
        for owned_value in &self.owned_values {
            if outpoints.contains(&owned_value.seal) {
                state
                    .entry(owned_value.seal)
                    .or_default()
                    .insert(OutpointState {
                        node_outpoint: owned_value.outpoint,
                        state: owned_value.state.clone().into(),
                    });
            }
        }
        for owned_data in &self.owned_data {
            if outpoints.contains(&owned_data.seal) {
                state
                    .entry(owned_data.seal)
                    .or_default()
                    .insert(OutpointState {
                        node_outpoint: owned_data.outpoint,
                        state: owned_data.state.clone().into(),
                    });
            }
        }
        for owned_attachment in &self.owned_attachments {
            if outpoints.contains(&owned_attachment.seal) {
                state
                    .entry(owned_attachment.seal)
                    .or_default()
                    .insert(OutpointState {
                        node_outpoint: owned_attachment.outpoint,
                        state: owned_attachment.state.clone().into(),
                    });
            }
        }
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

        fn process<S: StateTrait>(
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
                TypedAssignments::Void(assignments) => {
                    process(&mut self.owned_rights, assignments, node_id, *ty, txid)
                }
                TypedAssignments::Value(assignments) => {
                    process(&mut self.owned_values, assignments, node_id, *ty, txid)
                }
                TypedAssignments::Data(assignments) => {
                    process(&mut self.owned_data, assignments, node_id, *ty, txid)
                }
                TypedAssignments::Attachment(assignments) => {
                    process(&mut self.owned_attachments, assignments, node_id, *ty, txid)
                }
            }
        }
    }
}
