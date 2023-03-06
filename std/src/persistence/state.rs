// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

// Owned type -> { (NodeId, U16) -> (Outpoint, StateAtom) } -- for each 4 state
// types Global type -> { (Txid, Height) -> [StateAtom] } -- global state

use std::cmp::Ordering;

use amplify::confinement::{
    LargeOrdMap, LargeOrdSet, LargeVec, SmallOrdMap, SmallVec, TinyOrdMap, TinyVec,
};
use bp::{Outpoint, Txid};
use rgb::{
    attachment, fungible, AttachId, ContractId, FungibleState, GlobalStateType, OpId,
    OwnedStateType, SubSchema,
};
use strict_types::StrictVal;

// TODO: RGB Core
#[derive(Copy, Eq, PartialEq, Hash, Display)]
#[display("{height}/{txid}")]
pub struct TimeChainPos {
    pub height: u32,
    pub txid: Txid,
}

impl PartialOrd for TimeChainPos {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for TimeChainPos {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        if self.height == other.height {
            return self.txid.cmp(&other.txid);
        }
        self.height.cmp(&other.height)
    }
}

// TODO: RGB Core
#[derive(Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Display)]
#[display("{pos}/{idx}")]
pub struct GlobalIdx {
    pub pos: TimeChainPos,
    pub idx: u16,
}

// TODO: RGB Core
#[derive(Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Display)]
#[display("{op}/{no}")]
pub struct OpOut {
    pub op: OpId,
    pub no: u16,
}

// TODO: RGB Core
pub struct StateEntry<State, Seal = Outpoint> {
    pub seal: Seal,
    pub witness: Txid,
    pub opout: OpOut,
    pub value: State,
}

impl<State, Seal> PartialEq for StateEntry<State, Seal> {
    fn eq(&self, other: &Self) -> bool {
        if self.opout == other.opout {
            debug_assert_eq!(self.seal, other.seal);
            debug_assert_eq!(self.witness, other.witness);
            debug_assert_eq!(self.value, other.value);
        }
        self.opout == other.opout
    }
}
impl<State, Seal> Ord for StateEntry<State, Seal> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.opout == other.opout {
            debug_assert_eq!(self.seal, other.seal);
            debug_assert_eq!(self.witness, other.witness);
            debug_assert_eq!(self.value, other.value);
        }
        self.opout.cmp(&other.opout)
    }
}

// TODO: RGB Core
pub type RightsEntry = StateEntry<()>;
pub type ConcealedEntry = StateEntry<(), ()>;
pub type ValueEntry = StateEntry<fungible::Revealed>;
pub type DataEntry = StateEntry<StrictVal>;
pub type AttachEntry = StateEntry<attachment::Revealed>;

pub struct ContractState {
    id: ContractId,
    schema: SubSchema,
    global: TinyOrdMap<GlobalStateType, SmallOrdMap<GlobalIdx, StrictVal>>,
    global_history: TinyOrdMap<GlobalStateType, SmallOrdMap<GlobalIdx, StrictVal>>,
    known_rights: LargeOrdSet<RightsEntry>,
    unknown_rights: LargeOrdSet<ConcealedEntry>,
    known_values: LargeOrdSet<ConcealedEntry>,
    known_data: LargeOrdSet<ConcealedEntry>,
    known_attach: LargeOrdSet<ConcealedEntry>,
}

pub enum TypedState {
    Right,
    Value(fungible::Revealed),
    Data(StrictVal),
    Attach(AttachId),
}

// TODO: RGB Core
impl ContractState {
    pub fn extend_global(
        &mut self,
        ty: GlobalStateType,
        state: impl IntoIterator<Item = (GlobalIdx, StrictVal)>,
    ) {
    }
    pub fn extend_rights(
        &mut self,
        ty: OwnedStateType,
        entries: impl IntoIterator<Item = RightsEntry>,
    ) {
    }
    pub fn extend_values(
        &mut self,
        ty: OwnedStateType,
        entries: impl IntoIterator<Item = ValueEntry>,
    ) {
    }
    pub fn extend_data(
        &mut self,
        ty: OwnedStateType,
        entries: impl IntoIterator<Item = DataEntry>,
    ) {
    }
    pub fn extend_attach(
        &mut self,
        ty: OwnedStateType,
        entries: impl IntoIterator<Item = AttachEntry>,
    ) {
    }
}

impl ContractState {
    pub fn global(&self, ty: GlobalStateType) -> Result<SmallVec<StrictVal>, Error> {}
    pub fn values(&self, ty: OwnedStateType) -> Result<ValueEntry, Error> {}
    pub fn state(
        &self,
        seals: impl IntoIterator<Item = Outpoint>,
    ) -> Result<Vec<StateEntry<TypedState>>, Error> {
    }
}

impl ContractState {
    pub fn merge(&mut self) {}
    pub fn reorg(&mut self) {}
}
