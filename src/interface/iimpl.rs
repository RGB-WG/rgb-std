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

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use amplify::{ByteArray, Bytes32};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use commit_verify::{CommitStrategy, CommitmentId};
use rgb::{
    AssignmentType, ExtensionType, GlobalStateType, SchemaId, Script, SubSchema, TransitionType,
    ValencyType,
};
use strict_encoding::{FieldName, StrictDumb, TypeName};
use strict_types::encoding::{
    StrictDecode, StrictDeserialize, StrictEncode, StrictSerialize, StrictType,
};

use crate::interface::iface::IfaceId;
use crate::interface::{Iface, VerNo};
use crate::{ReservedBytes, LIB_NAME_RGB_STD};

pub trait SchemaTypeIndex:
    Copy + Eq + Ord + StrictType + StrictDumb + StrictEncode + StrictDecode
{
}
impl SchemaTypeIndex for GlobalStateType {}
impl SchemaTypeIndex for AssignmentType {}
impl SchemaTypeIndex for ValencyType {}
impl SchemaTypeIndex for ExtensionType {}
impl SchemaTypeIndex for TransitionType {}

/// Interface identifier.
///
/// Interface identifier commits to all of the interface data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
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
    const HRI: &'static str = "im";
    const CHUNKING: Option<Chunking> = CHUNKING_32;
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_byte_array() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for ImplId {}
impl Display for ImplId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            f.write_str("urn:lnp-bp:im:")?;
        }
        if f.sign_minus() {
            write!(f, "{:.2}", self.to_baid58())
        } else {
            write!(f, "{:#.2}", self.to_baid58())
        }
    }
}
impl FromStr for ImplId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_baid58_maybe_chunked_str(s.trim_start_matches("urn:lnp-bp:"), ':', '#')
    }
}
impl ImplId {
    pub fn to_mnemonic(&self) -> String { self.to_baid58().mnemonic() }
}

/// Maps certain form of type id (global or owned state or a valency) to a
/// human-readable name.
///
/// Two distinct [`NamedField`] objects must always have both different state
/// ids and names.   
#[derive(Clone, Eq, PartialOrd, Ord, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct NamedField<T: SchemaTypeIndex> {
    pub id: T,
    pub name: FieldName,
    /// Reserved bytes for storing information about value transformation
    /// procedures
    pub reserved: ReservedBytes<0u8, 4usize>,
}

impl<T> PartialEq for NamedField<T>
where T: SchemaTypeIndex
{
    fn eq(&self, other: &Self) -> bool { self.id == other.id || self.name == other.name }
}

impl<T: SchemaTypeIndex> NamedField<T> {
    pub fn with(id: T, name: FieldName) -> NamedField<T> {
        NamedField {
            id,
            name,
            reserved: default!(),
        }
    }
}

/// Maps operation numeric type id to a human-readable name.
///
/// Two distinct [`NamedType`] objects must always have both different state
/// ids and names.   
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
    /// Reserved bytes for storing information about adaptor procedures
    pub reserved: ReservedBytes<0, 4>,
}

impl<T> PartialEq for NamedType<T>
where T: SchemaTypeIndex
{
    fn eq(&self, other: &Self) -> bool { self.id == other.id || self.name == other.name }
}

impl<T: SchemaTypeIndex> NamedType<T> {
    pub fn with(id: T, name: TypeName) -> NamedType<T> {
        NamedType {
            id,
            name,
            reserved: default!(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
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
    pub version: VerNo,
    pub schema_id: SchemaId,
    pub iface_id: IfaceId,
    pub global_state: TinyOrdSet<NamedField<GlobalStateType>>,
    pub assignments: TinyOrdSet<NamedField<AssignmentType>>,
    pub valencies: TinyOrdSet<NamedField<ValencyType>>,
    pub transitions: TinyOrdSet<NamedType<TransitionType>>,
    pub extensions: TinyOrdSet<NamedField<ExtensionType>>,
    pub script: Script,
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

    pub fn global_type(&self, name: &FieldName) -> Option<GlobalStateType> {
        self.global_state
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn assignments_type(&self, name: &FieldName) -> Option<AssignmentType> {
        self.assignments
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn transition_type(&self, name: &TypeName) -> Option<TransitionType> {
        self.transitions
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn global_name(&self, id: GlobalStateType) -> Option<&FieldName> {
        self.global_state
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
    }

    pub fn assignment_name(&self, id: AssignmentType) -> Option<&FieldName> {
        self.assignments
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
    }

    pub fn transition_name(&self, id: TransitionType) -> Option<&TypeName> {
        self.transitions
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
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
    pub fn impl_id(&self) -> ImplId { self.iimpl.impl_id() }
    pub fn global_type(&self, name: &FieldName) -> Option<GlobalStateType> {
        self.iimpl.global_type(name)
    }
    pub fn assignments_type(&self, name: &FieldName) -> Option<AssignmentType> {
        self.iimpl.assignments_type(name)
    }
    pub fn transition_type(&self, name: &TypeName) -> Option<TransitionType> {
        self.iimpl.transition_type(name)
    }
}

pub trait ContractClass {
    fn schema() -> SubSchema;
    fn main_iface_impl() -> IfaceImpl;
}
