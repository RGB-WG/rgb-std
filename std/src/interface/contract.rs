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

use amplify::confinement::{LargeOrdMap, LargeVec, SmallVec};
use bp::Outpoint;
use rgb::{attachment, AssignmentsType, ContractState, GlobalStateType};
use strict_types::StrictVal;

use crate::interface::IfaceImpl;
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum TypedState {
    Void,
    Amount(u64),
    Data(StrictVal),
    Attachment(attachment::Revealed),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OwnedState {
    pub owner: Outpoint,
    pub state: TypedState,
}

/// Contract state is an in-memory structure providing API to read structured
/// data from the [`ContractHistory`].
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractIface {
    pub state: ContractState,
    pub iface: IfaceImpl,
}

impl ContractIface {
    pub fn global(&self, state_type: GlobalStateType) -> SmallVec<StrictVal> { todo!() }
    pub fn rights(&self, assign_type: AssignmentsType) -> LargeVec<Outpoint> { todo!() }
    pub fn fungible(&self, assign_type: AssignmentsType) -> LargeVec<(Outpoint, u64)> { todo!() }
    // TODO: Add attachments and structured data APIs
    pub fn outpoint(
        &self,
        outpoint: Outpoint,
    ) -> LargeOrdMap<AssignmentsType, LargeVec<TypedState>> {
        todo!()
    }
}
