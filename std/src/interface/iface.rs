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

use amplify::confinement::TinyOrdMap;
use rgb::Occurrences;
use strict_encoding::{
    StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, StrictType,
    TypeName,
};
use strict_types::SemId;

use crate::LIB_NAME_RGB_STD;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Req<Info: StrictType + StrictEncode + StrictDecode + StrictDumb> {
    pub info: Info,
    pub required: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum GlobalIface {
    #[strict_type(dumb)]
    Any,
    Typed(SemId),
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum OwnedIface {
    #[strict_type(dumb)]
    Any,
    AnyData,
    AnyValue,
    AnyAttach,
    Rights,
    Data(SemId),
}

pub type TypeReqMap = TinyOrdMap<TypeName, Occurrences>;

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GenesisIface {
    pub metadata: Option<SemId>,
    pub global_state: TypeReqMap,
    pub owned_state: TypeReqMap,
    pub valencies: TypeReqMap,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ExtensionIface {
    pub metadata: Option<SemId>,
    pub global_state: TypeReqMap,
    pub redeems: TypeReqMap,
    pub owned_state: TypeReqMap,
    pub valencies: TypeReqMap,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionIface {
    pub metadata: Option<SemId>,
    pub global_state: TypeReqMap,
    pub closes: TypeReqMap,
    pub owned_state: TypeReqMap,
    pub valencies: TypeReqMap,
}

/// Interface definition.
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Iface {
    pub global_state: TinyOrdMap<TypeName, Req<GlobalIface>>,
    pub owned_state: TinyOrdMap<TypeName, Req<OwnedIface>>,
    pub valencies: TinyOrdMap<TypeName, Req<()>>,
    pub genesis: GenesisIface,
    pub transitions: TinyOrdMap<TypeName, Req<TransitionIface>>,
    pub extensions: TinyOrdMap<TypeName, Req<ExtensionIface>>,
}

impl StrictSerialize for Iface {}
impl StrictDeserialize for Iface {}
