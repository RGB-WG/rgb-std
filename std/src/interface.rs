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

//! RGB contract interface provides a mapping between identifiers of RGB schema-
//! defined contract state and operation types to a human-readable and
//! standardized wallet APIs.

use amplify::confinement::TinyOrdSet;
use rgb::{ExtensionType, GlobalStateType, OwnedStateType, SchemaId, TransitionType, ValencyType};
use strict_encoding::{
    StrictDecode, StrictDeserialize, StrictEncode, StrictSerialize, StrictType, TypeName,
};

use crate::LIB_NAME_RGB_STD;

pub trait SchemaTypeId:
    Copy + Eq + Ord + Default + StrictType + StrictEncode + StrictDecode
{
}
impl SchemaTypeId for u16 {}

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
pub struct NamedType<T: SchemaTypeId> {
    pub id: T,
    pub name: TypeName,
}

impl<T> PartialEq for NamedType<T>
where T: SchemaTypeId
{
    fn eq(&self, other: &Self) -> bool { self.id == other.id || self.name == other.name }
}

impl<T: SchemaTypeId> NamedType<T> {
    pub fn with(id: T, name: TypeName) -> NamedType<T> { NamedType { id, name } }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum IfaceStd {
    #[strict_type(dumb)]
    #[display("RGB20")]
    Rgb20Fungible = 20,

    #[display("RGB21")]
    Rgb21Collectible = 21,

    #[display("RGB22")]
    Rgb22Identity = 22,

    #[display("RGB23")]
    Rgb23Audit = 23,

    #[display("RGB24")]
    Rgb24Naming = 24,
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
    pub standard: Option<IfaceStd>,
    pub global_state: TinyOrdSet<NamedType<GlobalStateType>>,
    pub owned_state: TinyOrdSet<NamedType<OwnedStateType>>,
    pub valencies: TinyOrdSet<NamedType<ValencyType>>,
    pub transitions: TinyOrdSet<NamedType<TransitionType>>,
    pub extensions: TinyOrdSet<NamedType<ExtensionType>>,
}

impl StrictSerialize for IfaceImpl {}
impl StrictDeserialize for IfaceImpl {}

impl core::fmt::Display for IfaceImpl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use base64::Engine;

        writeln!(f, "----- BEGIN RGB INTERFACE IMPLEMENTATION -----")?;
        if let Some(standard) = self.standard {
            writeln!(f, "Standard: {}", standard)?;
        }
        writeln!(f, "For-Schema: {:#}", self.schema_id)?;
        writeln!(f)?;

        let data = self.to_strict_serialized::<0xFFFFFF>().expect("in-memory");
        let engine = base64::engine::general_purpose::STANDARD;
        let data = engine.encode(data);
        let mut data = data.as_str();
        while data.len() >= 76 {
            let (line, rest) = data.split_at(76);
            writeln!(f, "{}", line)?;
            data = rest;
        }
        writeln!(f, "{}", data)?;

        writeln!(f, "\n----- END RGB INTERFACE IMPLEMENTATION -----")?;
        Ok(())
    }
}
