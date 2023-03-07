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

use std::cmp::Ordering;
use std::str::FromStr;

use amplify::confinement::TinyOrdMap;
use amplify::{Bytes32, RawArray};
use baid58::{Baid58ParseError, FromBaid58, ToBaid58};
use commit_verify::{CommitStrategy, CommitmentId};
use rgb::Occurrences;
use strict_encoding::{
    StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, StrictType,
    TypeName,
};
use strict_types::SemId;

use crate::LIB_NAME_RGB_STD;

/// Interface identifier.
///
/// Interface identifier commits to all of the interface data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_baid58)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct IfaceId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl ToBaid58<32> for IfaceId {
    const HRI: &'static str = "rgb-iface";
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_raw_array() }
}
impl FromBaid58<32> for IfaceId {}

impl FromStr for IfaceId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid58_str(s) }
}

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

impl Req<GlobalIface> {
    pub fn some() -> Self {
        Req {
            info: GlobalIface::Any,
            required: false,
        }
    }
    pub fn require_any() -> Self {
        Req {
            info: GlobalIface::Any,
            required: true,
        }
    }
    pub fn optional(sem_id: SemId) -> Self {
        Req {
            info: GlobalIface::Typed(sem_id),
            required: false,
        }
    }
    pub fn require(sem_id: SemId) -> Self {
        Req {
            info: GlobalIface::Typed(sem_id),
            required: true,
        }
    }
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
    Rights,
    Amount,
    AnyData,
    AnyAttach,
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
    pub global: TypeReqMap,
    pub assignments: TypeReqMap,
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
    pub globals: TypeReqMap,
    pub redeems: TypeReqMap,
    pub assignments: TypeReqMap,
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
    pub globals: TypeReqMap,
    pub inputs: TypeReqMap,
    pub assignments: TypeReqMap,
    pub valencies: TypeReqMap,
}

/// Interface definition.
#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Iface {
    pub name: TypeName,
    pub global_state: TinyOrdMap<TypeName, Req<GlobalIface>>,
    pub owned_state: TinyOrdMap<TypeName, OwnedIface>,
    pub valencies: TinyOrdMap<TypeName, Req<()>>,
    pub genesis: GenesisIface,
    pub transitions: TinyOrdMap<TypeName, TransitionIface>,
    pub extensions: TinyOrdMap<TypeName, ExtensionIface>,
}

impl PartialEq for Iface {
    fn eq(&self, other: &Self) -> bool { self.iface_id() == other.iface_id() }
}

impl Ord for Iface {
    fn cmp(&self, other: &Self) -> Ordering { self.iface_id().cmp(&other.iface_id()) }
}

impl PartialOrd for Iface {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl CommitStrategy for Iface {
    type Strategy = commit_verify::strategies::Strict;
}

impl CommitmentId for Iface {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:interface:v01#2303";
    type Id = IfaceId;
}

impl StrictSerialize for Iface {}
impl StrictDeserialize for Iface {}

impl Iface {
    #[inline]
    pub fn iface_id(&self) -> IfaceId { self.commitment_id() }
}
