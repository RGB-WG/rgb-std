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

use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use amplify::{ByteArray, Bytes32};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use commit_verify::{CommitId, CommitmentId, DigestExt, Sha256};
use rgb::{Occurrences, Types};
use strict_encoding::{
    FieldName, StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize,
    StrictType, TypeName,
};
use strict_types::SemId;

use crate::interface::VerNo;
use crate::LIB_NAME_RGB_STD;

/// Interface identifier.
///
/// Interface identifier commits to all the interface data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
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

impl From<Sha256> for IfaceId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for IfaceId {
    const TAG: &'static str = "urn:lnp-bp:rgb:interface#2024-02-04";
}

impl ToBaid58<32> for IfaceId {
    const HRI: &'static str = "if";
    const CHUNKING: Option<Chunking> = CHUNKING_32;
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_byte_array() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for IfaceId {}
impl Display for IfaceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            f.write_str("urn:lnp-bp:if:")?;
        }
        if f.sign_minus() {
            write!(f, "{:.2}", self.to_baid58())
        } else {
            write!(f, "{:#.2}", self.to_baid58())
        }
    }
}
impl FromStr for IfaceId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_baid58_maybe_chunked_str(s.trim_start_matches("urn:lnp-bp:"), ':', '#')
    }
}
impl IfaceId {
    pub const fn from_array(id: [u8; 32]) -> Self { IfaceId(Bytes32::from_array(id)) }
    pub fn to_mnemonic(&self) -> String { self.to_baid58().mnemonic() }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum Req {
    Optional,
    Required,
    NoneOrMore,
    OneOrMore,
}

impl Req {
    pub fn is_required(self) -> bool { self == Req::Required || self == Req::OneOrMore }
    pub fn is_multiple(self) -> bool { self == Req::NoneOrMore || self == Req::OneOrMore }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ValencyIface {
    pub required: bool,
    pub multiple: bool,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalIface {
    pub sem_id: Option<SemId>,
    pub required: bool,
    pub multiple: bool,
}

impl GlobalIface {
    pub fn any(req: Req) -> Self {
        GlobalIface {
            sem_id: None,
            required: req.is_required(),
            multiple: req.is_multiple(),
        }
    }
    pub fn optional(sem_id: SemId) -> Self {
        GlobalIface {
            sem_id: Some(sem_id),
            required: false,
            multiple: false,
        }
    }
    pub fn required(sem_id: SemId) -> Self {
        GlobalIface {
            sem_id: Some(sem_id),
            required: true,
            multiple: false,
        }
    }
    pub fn none_or_many(sem_id: SemId) -> Self {
        GlobalIface {
            sem_id: Some(sem_id),
            required: false,
            multiple: true,
        }
    }
    pub fn one_or_many(sem_id: SemId) -> Self {
        GlobalIface {
            sem_id: Some(sem_id),
            required: true,
            multiple: true,
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
pub struct AssignIface {
    pub owned_state: OwnedIface,
    pub public: bool,
    pub required: bool,
    pub multiple: bool,
}

impl AssignIface {
    pub fn public(owned_state: OwnedIface, req: Req) -> Self {
        AssignIface {
            owned_state,
            public: true,
            required: req.is_required(),
            multiple: req.is_multiple(),
        }
    }

    pub fn private(owned_state: OwnedIface, req: Req) -> Self {
        AssignIface {
            owned_state,
            public: false,
            required: req.is_required(),
            multiple: req.is_multiple(),
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
pub enum OwnedIface {
    #[strict_type(dumb)]
    Any,
    Rights,
    Amount,
    AnyData,
    AnyAttach,
    Data(SemId),
}

pub type ArgMap = TinyOrdMap<FieldName, Occurrences>;

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
    pub global: ArgMap,
    pub assignments: ArgMap,
    pub valencies: ArgMap,
    pub errors: TinyOrdSet<u8>,
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
    pub globals: ArgMap,
    pub redeems: ArgMap,
    pub assignments: ArgMap,
    pub valencies: ArgMap,
    pub errors: TinyOrdSet<u8>,
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
    /// Defines whence schema may omit providing this operation.
    pub optional: bool,
    pub metadata: Option<SemId>,
    pub globals: ArgMap,
    pub inputs: ArgMap,
    pub assignments: ArgMap,
    pub valencies: ArgMap,
    pub errors: TinyOrdSet<u8>,
    pub default_assignment: Option<FieldName>,
}

/// Interface definition.
#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = IfaceId)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Iface {
    pub version: VerNo,
    pub name: TypeName,
    pub global_state: TinyOrdMap<FieldName, GlobalIface>,
    pub assignments: TinyOrdMap<FieldName, AssignIface>,
    pub valencies: TinyOrdMap<FieldName, ValencyIface>,
    pub genesis: GenesisIface,
    pub transitions: TinyOrdMap<TypeName, TransitionIface>,
    pub extensions: TinyOrdMap<TypeName, ExtensionIface>,
    pub error_type: SemId,
    pub default_operation: Option<TypeName>,
    pub types: Types,
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

impl StrictSerialize for Iface {}
impl StrictDeserialize for Iface {}

impl Iface {
    #[inline]
    pub fn iface_id(&self) -> IfaceId { self.commit_id() }
}
