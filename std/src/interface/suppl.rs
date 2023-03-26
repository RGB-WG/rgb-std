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

use amplify::confinement::{TinyOrdMap, TinyString};
use amplify::Bytes32;
use rgb::{AssignmentType, ContractId, GlobalStateType};
use strict_types::value;

use crate::LIB_NAME_RGB_STD;

/// Contract supplement identifier.
///
/// Contract supplement identifier commits to all of the supplement data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SupplId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

/// Contract supplement, providing non-consensus information about standard
/// way of working with the contract data. Each contract can have only a single
/// valid supplement; the supplement is attached to the contract via trusted
/// provider signature (providers are ordered by the priority).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractSuppl {
    pub contract_id: ContractId,
    pub ticker: TickerSuppl,
    pub global_state: TinyOrdMap<AssignmentType, OwnedStateSuppl>,
    pub owned_state: TinyOrdMap<AssignmentType, OwnedStateSuppl>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum TickerSuppl {
    #[strict_type(tag = 0, dumb)]
    Absent,
    #[strict_type(tag = 1)]
    Global(GlobalStateType, value::Path),
    #[strict_type(tag = 2)]
    Owned(AssignmentType, value::Path),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct OwnedStateSuppl {
    pub meaning: TinyString,
    pub velocity_class: VelocityClass,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, try_from_u8, into_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum VelocityClass {
    #[strict_type(dumb)]
    HighFrequency = 10,
    Frequent = 20,
    Regular = 30,
    Episodic = 40,
    Seldom = 50,
}
