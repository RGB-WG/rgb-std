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
use std::marker::PhantomData;
use std::str::FromStr;

use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use amplify::{ByteArray, Bytes32};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use commit_verify::{CommitId, CommitmentId, DigestExt, Sha256};
use rgb::{
    AssignmentType, ExtensionType, GlobalStateType, SchemaId, Script, SubSchema, TransitionType,
    ValencyType,
};
use strict_encoding::{FieldName, StrictDumb};
use strict_types::encoding::{
    StrictDecode, StrictDeserialize, StrictEncode, StrictSerialize, StrictType,
};
use strict_types::TypeLib;

use crate::interface::iface::IfaceId;
use crate::interface::{Iface, IfaceWrapper, VerNo};
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
    pub global_state: TinyOrdSet<NamedField<GlobalStateType>>,
    pub assignments: TinyOrdSet<NamedField<AssignmentType>>,
    pub valencies: TinyOrdSet<NamedField<ValencyType>>,
    pub transitions: TinyOrdSet<NamedField<TransitionType>>,
    pub extensions: TinyOrdSet<NamedField<ExtensionType>>,
    pub script: Script,
}

impl StrictSerialize for IfaceImpl {}
impl StrictDeserialize for IfaceImpl {}

impl IfaceImpl {
    #[inline]
    pub fn impl_id(&self) -> ImplId { self.commit_id() }

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

    pub fn global_name(&self, global_type: GlobalStateType) -> Option<&FieldName> {
        self.iimpl.global_name(global_type)
    }

    pub fn assignments_type(&self, name: &FieldName) -> Option<AssignmentType> {
        self.iimpl.assignments_type(name)
    }

    pub fn assignment_name(&self, assignment_type: AssignmentType) -> Option<&FieldName> {
        self.iimpl.assignment_name(assignment_type)
    }

    pub fn transition_type(&self, name: &FieldName) -> Option<TransitionType> {
        self.iimpl.transition_type(name)
    }

    pub fn transition_name(&self, transition_type: TransitionType) -> Option<&FieldName> {
        self.iimpl.transition_name(transition_type)
    }
}

pub trait IssuerClass {
    type IssuingIface: IfaceClass;

    fn schema() -> SubSchema;
    fn issue_impl() -> IfaceImpl;

    fn issuer() -> SchemaIssuer<Self::IssuingIface> {
        SchemaIssuer::new(Self::schema(), Self::issue_impl())
            .expect("implementation schema mismatch")
    }
}

pub trait IfaceClass: IfaceWrapper {
    fn iface() -> Iface;
    fn stl() -> TypeLib;
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum WrongImplementation {
    /// the provided implementation {impl_id} implements interface {actual}
    /// instead of {expected} for the schema {schema_id}
    InterfaceMismatch {
        schema_id: SchemaId,
        impl_id: ImplId,
        expected: IfaceId,
        actual: IfaceId,
    },

    /// the provided implementation {impl_id} uses schema {actual} instead of
    /// {expected}
    SchemaMismatch {
        impl_id: ImplId,
        expected: SchemaId,
        actual: SchemaId,
    },
}

#[derive(Getters, Clone, Eq, PartialEq, Debug)]
pub struct IssuerTriplet {
    schema: SubSchema,
    iface: Iface,
    iimpl: IfaceImpl,
}

impl IssuerTriplet {
    #[allow(clippy::result_large_err)]
    pub fn new(
        iface: Iface,
        schema: SubSchema,
        iimpl: IfaceImpl,
    ) -> Result<Self, WrongImplementation> {
        let expected = iface.iface_id();
        let actual = iimpl.iface_id;

        if actual != expected {
            return Err(WrongImplementation::InterfaceMismatch {
                schema_id: schema.schema_id(),
                impl_id: iimpl.impl_id(),
                expected,
                actual,
            });
        }

        let expected = schema.schema_id();
        let actual = iimpl.schema_id;
        if actual != expected {
            return Err(WrongImplementation::SchemaMismatch {
                impl_id: iimpl.impl_id(),
                expected,
                actual,
            });
        }

        // TODO: check schema internal consistency
        // TODO: check interface internal consistency
        // TODO: check implementation internal consistency

        Ok(Self {
            iface,
            schema,
            iimpl,
        })
    }

    #[inline]
    pub fn into_split(self) -> (Iface, SubSchema, IfaceImpl) {
        (self.iface, self.schema, self.iimpl)
    }

    #[inline]
    pub fn into_issuer(self) -> (SubSchema, IfaceImpl) { (self.schema, self.iimpl) }
}

#[derive(Getters, Clone, Eq, PartialEq, Debug)]
pub struct SchemaIssuer<I: IfaceClass> {
    schema: SubSchema,
    iimpl: IfaceImpl,
    phantom: PhantomData<I>,
}

impl<I: IfaceClass> SchemaIssuer<I> {
    #[allow(clippy::result_large_err)]
    pub fn new(schema: SubSchema, iimpl: IfaceImpl) -> Result<Self, WrongImplementation> {
        let triplet = IssuerTriplet::new(I::iface(), schema, iimpl)?;
        let (_, schema, iimpl) = triplet.into_split();

        Ok(Self {
            schema,
            iimpl,
            phantom: default!(),
        })
    }

    #[inline]
    pub fn into_split(self) -> (SubSchema, IfaceImpl) { (self.schema, self.iimpl) }

    pub fn into_triplet(self) -> IssuerTriplet {
        let (schema, iimpl) = self.into_split();
        IssuerTriplet {
            schema,
            iface: I::iface(),
            iimpl,
        }
    }
}
