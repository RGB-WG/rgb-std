// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::iter::Sum;

use invoice::{Allocation, Amount};
use rgb::{
    AttachState, ContractId, DataState, OpId, RevealedAttach, RevealedData, RevealedValue, Schema,
    VoidState, XOutpoint, XOutputSeal, XWitnessId,
};
use strict_encoding::{FieldName, StrictDecode, StrictDumb, StrictEncode};
use strict_types::{StrictVal, TypeSystem};

use crate::contract::{KnownState, OutputAssignment, WitnessInfo};
use crate::info::ContractInfo;
use crate::interface::{AssignmentsFilter, IfaceImpl};
use crate::persistence::ContractStateRead;
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ContractError {
    /// field name {0} is unknown to the contract interface
    FieldNameUnknown(FieldName),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[display(inner)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AllocatedState {
    #[from(())]
    #[from(VoidState)]
    #[display("~")]
    #[strict_type(tag = 0, dumb)]
    Void,

    #[from]
    #[from(RevealedValue)]
    #[strict_type(tag = 1)]
    Amount(Amount),

    #[from]
    #[from(RevealedData)]
    #[from(Allocation)]
    #[strict_type(tag = 2)]
    Data(DataState),

    #[from]
    #[from(RevealedAttach)]
    #[strict_type(tag = 3)]
    Attachment(AttachState),
}

impl KnownState for AllocatedState {}

pub type OwnedAllocation = OutputAssignment<AllocatedState>;
pub type RightsAllocation = OutputAssignment<VoidState>;
pub type FungibleAllocation = OutputAssignment<Amount>;
pub type DataAllocation = OutputAssignment<DataState>;
pub type AttachAllocation = OutputAssignment<AttachState>;

pub trait StateChange: Clone + Eq + StrictDumb + StrictEncode + StrictDecode {
    type State: KnownState;
    fn from_spent(state: Self::State) -> Self;
    fn from_received(state: Self::State) -> Self;
    fn merge_spent(&mut self, state: Self::State);
    fn merge_received(&mut self, state: Self::State);
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AmountChange {
    #[display("-{0}")]
    #[strict_type(tag = 0xFF)]
    Dec(Amount),

    #[display("0")]
    #[strict_type(tag = 0, dumb)]
    Zero,

    #[display("+{0}")]
    #[strict_type(tag = 0x01)]
    Inc(Amount),
}

impl StateChange for AmountChange {
    type State = Amount;

    fn from_spent(state: Self::State) -> Self { AmountChange::Dec(state) }

    fn from_received(state: Self::State) -> Self { AmountChange::Inc(state) }

    fn merge_spent(&mut self, sub: Self::State) {
        *self = match self {
            AmountChange::Dec(neg) => AmountChange::Dec(*neg + sub),
            AmountChange::Zero => AmountChange::Dec(sub),
            AmountChange::Inc(pos) => match sub.cmp(pos) {
                Ordering::Less => AmountChange::Inc(*pos - sub),
                Ordering::Equal => AmountChange::Zero,
                Ordering::Greater => AmountChange::Dec(sub - *pos),
            },
        };
    }

    fn merge_received(&mut self, add: Self::State) {
        *self = match self {
            AmountChange::Inc(pos) => AmountChange::Inc(*pos + add),
            AmountChange::Zero => AmountChange::Inc(add),
            AmountChange::Dec(neg) => match add.cmp(neg) {
                Ordering::Less => AmountChange::Dec(*neg - add),
                Ordering::Equal => AmountChange::Zero,
                Ordering::Greater => AmountChange::Inc(add - *neg),
            },
        };
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractOp<S: StateChange> {
    pub opids: BTreeSet<OpId>, // may come from multiple bundles
    pub state_change: S,
    pub seals: BTreeSet<XOutputSeal>,
    pub witness: Option<WitnessInfo>,
}

impl<S: StateChange> ContractOp<S> {
    fn new_genesis(our_allocations: &HashSet<OutputAssignment<S::State>>) -> Self
    where S::State: Sum {
        let opids = our_allocations.iter().map(|a| a.opout.op).collect();
        let seals = our_allocations.iter().map(|a| a.seal).collect();
        let state_change =
            StateChange::from_received(our_allocations.iter().map(|a| a.state.clone()).sum());
        Self {
            opids,
            state_change,
            seals,
            witness: None,
        }
    }

    fn new_sent(
        witness: WitnessInfo,
        ext_allocations: &HashSet<OutputAssignment<S::State>>,
        our_allocations: &HashSet<OutputAssignment<S::State>>,
    ) -> Self
    where
        S::State: Sum,
    {
        let opids = our_allocations.iter().map(|a| a.opout.op).collect();
        let seals = ext_allocations.iter().map(|a| a.seal).collect();
        let mut state_change = S::from_spent(ext_allocations.iter().map(|a| a.state.clone()).sum());
        state_change.merge_received(our_allocations.iter().map(|a| a.state.clone()).sum());
        Self {
            opids,
            state_change,
            seals,
            witness: Some(witness),
        }
    }

    fn new_received(
        witness: WitnessInfo,
        our_allocations: &HashSet<OutputAssignment<S::State>>,
    ) -> Self
    where
        S::State: Sum,
    {
        let opids = our_allocations.iter().map(|a| a.opout.op).collect();
        let seals = our_allocations.iter().map(|a| a.seal).collect();
        let state_change =
            StateChange::from_received(our_allocations.iter().map(|a| a.state.clone()).sum());
        Self {
            opids,
            state_change,
            seals,
            witness: Some(witness),
        }
    }
}

/// Contract state is an in-memory structure providing API to read structured
/// data from the [`rgb::ContractHistory`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ContractIface<S: ContractStateRead> {
    pub state: S,
    pub schema: Schema,
    pub iface: IfaceImpl,
    pub types: TypeSystem,
    pub info: ContractInfo,
}

impl<S: ContractStateRead> ContractIface<S> {
    pub fn contract_id(&self) -> ContractId { self.state.contract_id() }

    /// # Panics
    ///
    /// If data are corrupted and contract schema doesn't match interface
    /// implementations.
    pub fn global(
        &self,
        name: impl Into<FieldName>,
    ) -> Result<impl Iterator<Item = StrictVal> + '_, ContractError> {
        let name = name.into();
        let type_id = self
            .iface
            .global_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))?;
        let global_schema = self
            .schema
            .global_types
            .get(&type_id)
            .expect("schema doesn't match interface");
        Ok(self
            .state
            .global(type_id)
            .expect("schema doesn't match interface")
            .map(|data| {
                self.types
                    .strict_deserialize_type(global_schema.sem_id, data.borrow().as_slice())
                    .expect("unvalidated contract data in stash")
                    .unbox()
            }))
    }

    fn extract_state<'c, A, U>(
        &'c self,
        state: impl IntoIterator<Item = &'c OutputAssignment<A>> + 'c,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = OutputAssignment<U>> + 'c, ContractError>
    where
        A: Clone + KnownState + 'c,
        U: From<A> + KnownState + 'c,
    {
        Ok(self
            .extract_state_unfiltered(state, name)?
            .filter(move |outp| filter.should_include(outp.seal, outp.witness)))
    }

    fn extract_state_unfiltered<'c, A, U>(
        &'c self,
        state: impl IntoIterator<Item = &'c OutputAssignment<A>> + 'c,
        name: impl Into<FieldName>,
    ) -> Result<impl Iterator<Item = OutputAssignment<U>> + 'c, ContractError>
    where
        A: Clone + KnownState + 'c,
        U: From<A> + KnownState + 'c,
    {
        let name = name.into();
        let type_id = self
            .iface
            .assignments_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))?;
        Ok(state
            .into_iter()
            .filter(move |outp| outp.opout.ty == type_id)
            .cloned()
            .map(OutputAssignment::<A>::transmute))
    }

    pub fn rights<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = RightsAllocation> + 'c, ContractError> {
        self.extract_state(self.state.rights_all(), name, filter)
    }

    pub fn fungible<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = FungibleAllocation> + 'c, ContractError> {
        self.extract_state(self.state.fungible_all(), name, filter)
    }

    pub fn data<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = DataAllocation> + 'c, ContractError> {
        self.extract_state(self.state.data_all(), name, filter)
    }

    pub fn attachments<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = AttachAllocation> + 'c, ContractError> {
        self.extract_state(self.state.attach_all(), name, filter)
    }

    pub fn allocations<'c>(
        &'c self,
        filter: impl AssignmentsFilter + Copy + 'c,
    ) -> impl Iterator<Item = OwnedAllocation> + 'c {
        fn f<'a, S, U>(
            filter: impl AssignmentsFilter + 'a,
            state: impl IntoIterator<Item = &'a OutputAssignment<S>> + 'a,
        ) -> impl Iterator<Item = OutputAssignment<U>> + 'a
        where
            S: Clone + KnownState + 'a,
            U: From<S> + KnownState + 'a,
        {
            state
                .into_iter()
                .filter(move |outp| filter.should_include(outp.seal, outp.witness))
                .cloned()
                .map(OutputAssignment::<S>::transmute)
        }

        f(filter, self.state.rights_all())
            .map(OwnedAllocation::from)
            .chain(f(filter, self.state.fungible_all()).map(OwnedAllocation::from))
            .chain(f(filter, self.state.data_all()).map(OwnedAllocation::from))
            .chain(f(filter, self.state.attach_all()).map(OwnedAllocation::from))
    }

    pub fn outpoint_allocations(
        &self,
        outpoint: XOutpoint,
    ) -> impl Iterator<Item = OwnedAllocation> + '_ {
        self.allocations(outpoint)
    }

    pub fn fungible_operations(
        &self,
        state_name: impl Into<FieldName>,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Result<Vec<ContractOp<AmountChange>>, ContractError> {
        let state_name = state_name.into();

        // get all allocations which ever belonged to this wallet and store them by witness id
        let allocations_our_outpoint = self.fungible(state_name.clone(), filter_outpoints)?.fold(
            HashMap::<_, HashSet<_>>::new(),
            |mut map, a| {
                map.entry(a.witness).or_default().insert(a);
                map
            },
        );
        // get all allocations which has a witness transaction belonging to this wallet
        let allocations_our_witness = self.fungible(state_name, filter_witnesses)?.fold(
            HashMap::<_, HashSet<_>>::new(),
            |mut map, a| {
                let witness = a.witness.expect(
                    "all empty witnesses must be already filtered out by wallet.filter_witness()",
                );
                map.entry(witness).or_default().insert(a);
                map
            },
        );

        // gather all witnesses from both sets
        let mut witness_ids = allocations_our_witness
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        witness_ids.extend(allocations_our_outpoint.keys().filter_map(|x| *x));

        // reconstruct contract history from the wallet perspective
        let mut ops = Vec::with_capacity(witness_ids.len() + 1);
        // add allocations with no witness to the beginning of the history
        if let Some(genesis_allocations) = allocations_our_outpoint.get(&None) {
            ops.push(ContractOp::new_genesis(genesis_allocations));
        }
        for witness_id in witness_ids {
            let our_outpoint = allocations_our_outpoint.get(&Some(witness_id));
            let our_witness = allocations_our_witness.get(&witness_id);
            let witness_info = self.witness_info(witness_id).expect(
                "witness id was returned from the contract state above, so it must be there",
            );
            let op = match (our_outpoint, our_witness) {
                // we own both allocation and witness transaction: these allocations are changes and
                // outgoing payments. The difference between the change and the payments are whether
                // a specific allocation is listed in the first tuple pattern field.
                (Some(our_allocations), Some(all_allocations)) => {
                    // all_allocations - our_allocations = external payments
                    let ext_allocations = all_allocations.difference(our_allocations);
                    ContractOp::new_sent(
                        witness_info,
                        &ext_allocations.copied().collect(),
                        our_allocations,
                    )
                }
                // the same as above, but the payment has no change
                (None, Some(ext_allocations)) => {
                    ContractOp::new_sent(witness_info, ext_allocations, &set![])
                }
                // we own allocation but the witness transaction was made by other wallet:
                // this is an incoming payment to us.
                (Some(our_allocations), None) => {
                    ContractOp::new_received(witness_info, our_allocations)
                }
                // these can't get into the `witness_ids` due to the used filters
                (None, None) => unreachable!("broken allocation filters"),
            };
            ops.push(op);
        }

        Ok(ops)
    }

    pub fn witness_info(&self, witness_id: XWitnessId) -> Option<WitnessInfo> {
        let ord = self.state.witness_ord(witness_id)?;
        Some(WitnessInfo {
            id: witness_id,
            ord,
        })
    }
}
