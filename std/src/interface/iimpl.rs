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

use std::str::FromStr;

use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use amplify::{Bytes32, RawArray};
use baid58::{Baid58ParseError, FromBaid58, ToBaid58};
use commit_verify::{CommitStrategy, CommitmentId};
use rgb::{
    AssignmentsType, ExtensionType, GlobalStateType, SchemaId, SchemaTypeIndex, SubSchema,
    TransitionType, ValencyType,
};
use strict_types::encoding::{
    StrictDecode, StrictDeserialize, StrictEncode, StrictSerialize, StrictType, TypeName,
};

use crate::interface::iface::IfaceId;
use crate::interface::Iface;
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
pub struct ImplId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl ToBaid58<32> for ImplId {
    const HRI: &'static str = "rgb-impl";
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_raw_array() }
}
impl FromBaid58<32> for ImplId {}

impl FromStr for ImplId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid58_str(s) }
}

/// Maps certain form of type id (global or owned state or a specific operation
/// type) to a human-readable name.
///
/// Two distinct [`NamedType`] objects must always have both different state ids
/// and names.   
#[derive(Clone, Eq, PartialOrd, Ord, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct NamedType<T: SchemaTypeIndex> {
    pub id: T,
    pub name: TypeName,
}

impl<T> PartialEq for NamedType<T>
where T: SchemaTypeIndex
{
    fn eq(&self, other: &Self) -> bool { self.id == other.id || self.name == other.name }
}

impl<T: SchemaTypeIndex> NamedType<T> {
    pub fn with(id: T, name: TypeName) -> NamedType<T> { NamedType { id, name } }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct SchemaIfaces {
    pub schema: SubSchema,
    pub iimpls: TinyOrdMap<IfaceId, IfaceImpl>,
}

impl SchemaIfaces {
    pub fn new(schema: SubSchema) -> Self {
        SchemaIfaces {
            schema,
            iimpls: none!(),
        }
    }
}

/// Interface implementation for some specific schema.
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct IfaceImpl {
    pub schema_id: SchemaId,
    pub iface_id: IfaceId,
    pub global_state: TinyOrdSet<NamedType<GlobalStateType>>,
    pub owned_state: TinyOrdSet<NamedType<AssignmentsType>>,
    pub valencies: TinyOrdSet<NamedType<ValencyType>>,
    pub transitions: TinyOrdSet<NamedType<TransitionType>>,
    pub extensions: TinyOrdSet<NamedType<ExtensionType>>,
}

impl CommitStrategy for IfaceImpl {
    type Strategy = commit_verify::strategies::Strict;
}

impl CommitmentId for IfaceImpl {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:ifaceimpl:v01#2303";
    type Id = ImplId;
}

impl StrictSerialize for IfaceImpl {}
impl StrictDeserialize for IfaceImpl {}

impl IfaceImpl {
    #[inline]
    pub fn impl_id(&self) -> ImplId { self.commitment_id() }

    pub fn global_type(&self, name: &TypeName) -> Option<GlobalStateType> {
        self.global_state
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn assignments_type(&self, name: &TypeName) -> Option<AssignmentsType> {
        self.owned_state
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }
}

// TODO: Implement validation of implementation against interface requirements

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct IfacePair {
    pub iface: Iface,
    pub iimpl: IfaceImpl,
}

impl IfacePair {
    pub fn with(iface: Iface, iimpl: IfaceImpl) -> IfacePair { IfacePair { iface, iimpl } }

    pub fn iface_id(&self) -> IfaceId { self.iface.iface_id() }
}
