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

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::confinement::TinyOrdSet;
use amplify::{ByteArray, Bytes32};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use commit_verify::{CommitId, CommitmentId, DigestExt, Sha256};
use rgb::{
    AssignmentType, ExtensionType, GlobalStateType, Identity, MetaType, SchemaId, TransitionType,
    ValencyType,
};
use strict_encoding::{FieldName, StrictDumb, VariantName};
use strict_types::encoding::{StrictDecode, StrictEncode, StrictType};

use crate::interface::iface::IfaceId;
use crate::interface::VerNo;
use crate::{ReservedBytes, LIB_NAME_RGB_STD};

pub trait SchemaTypeIndex:
    Copy + Eq + Ord + StrictType + StrictDumb + StrictEncode + StrictDecode
{
}
impl SchemaTypeIndex for u8 {} // Error types
impl SchemaTypeIndex for MetaType {}
impl SchemaTypeIndex for GlobalStateType {}
impl SchemaTypeIndex for AssignmentType {}
impl SchemaTypeIndex for ValencyType {}
impl SchemaTypeIndex for ExtensionType {}
impl SchemaTypeIndex for TransitionType {}

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
pub struct ImplId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for ImplId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for ImplId {
    const TAG: &'static str = "urn:lnp-bp:rgb:iface-impl#2024-02-04";
}

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
    pub reserved: ReservedBytes<4usize>,
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

/// Maps certain form of type id (global or owned state or a valency) to a
/// human-readable name.
///
/// Two distinct [`crate::interface::NamedField`] objects must always have both
/// different state ids and names.
#[derive(Clone, Eq, PartialOrd, Ord, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct NamedVariant<T: SchemaTypeIndex> {
    pub id: T,
    pub name: VariantName,
    /// Reserved bytes for storing information about value transformation
    /// procedures
    pub reserved: ReservedBytes<4usize>,
}

impl<T> PartialEq for NamedVariant<T>
where T: SchemaTypeIndex
{
    fn eq(&self, other: &Self) -> bool { self.id == other.id || self.name == other.name }
}

impl<T: SchemaTypeIndex> NamedVariant<T> {
    pub fn with(id: T, name: VariantName) -> NamedVariant<T> {
        NamedVariant {
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
    pub name: FieldName,
    /// Reserved bytes for storing information about adaptor procedures
    pub reserved: ReservedBytes<0, 4>,
}

impl<T> PartialEq for NamedType<T>
where T: SchemaTypeIndex
{
    fn eq(&self, other: &Self) -> bool { self.id == other.id || self.name == other.name }
}

impl<T: SchemaTypeIndex> NamedType<T> {
    pub fn with(id: T, name: impl Into<FieldName>) -> NamedType<T> {
        NamedType {
            id,
            name: name.into(),
            reserved: default!(),
        }
    }
}

/// Interface implementation for some specific schema.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = ImplId)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct IfaceImpl {
    pub version: VerNo,
    pub schema_id: SchemaId,
    pub iface_id: IfaceId,
    pub timestamp: i64,
    pub metadata: TinyOrdSet<NamedField<MetaType>>,
    pub global_state: TinyOrdSet<NamedField<GlobalStateType>>,
    pub assignments: TinyOrdSet<NamedField<AssignmentType>>,
    pub valencies: TinyOrdSet<NamedField<ValencyType>>,
    pub transitions: TinyOrdSet<NamedField<TransitionType>>,
    pub extensions: TinyOrdSet<NamedField<ExtensionType>>,
    pub errors: TinyOrdSet<NamedVariant<u8>>,
    pub developer: Identity,
}

impl IfaceImpl {
    #[inline]
    pub fn impl_id(&self) -> ImplId { self.commit_id() }

    pub fn meta_type(&self, name: &FieldName) -> Option<MetaType> {
        self.metadata
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

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

    pub fn transition_type(&self, name: &FieldName) -> Option<TransitionType> {
        self.transitions
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn extension_name(&self, id: ExtensionType) -> Option<&FieldName> {
        self.extensions
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
    }

    pub fn extension_type(&self, name: &FieldName) -> Option<ExtensionType> {
        self.extensions
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn valency_type(&self, name: &FieldName) -> Option<ValencyType> {
        self.valencies
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn valency_name(&self, id: ValencyType) -> Option<&FieldName> {
        self.valencies
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
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

    pub fn transition_name(&self, id: TransitionType) -> Option<&FieldName> {
        self.transitions
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
    }

    pub fn error_name(&self, errno: u8) -> Option<&VariantName> {
        self.errors
            .iter()
            .find(|nt| nt.id == errno)
            .map(|nt| &nt.name)
    }
}
