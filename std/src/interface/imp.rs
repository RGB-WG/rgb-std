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

use amplify::confinement::TinyOrdSet;
use rgb::{
    ExtensionType, GlobalStateType, OwnedStateType, SchemaId, SchemaTypeIndex, TransitionType,
    ValencyType,
};
use strict_types::encoding::{
    StrictDecode, StrictDeserialize, StrictEncode, StrictSerialize, StrictType, TypeName,
};

use super::IfaceStd;
use crate::LIB_NAME_RGB_STD;

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

// TODO: Implement validation of implementation against interface requirements

impl core::fmt::Display for IfaceImpl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use base64::Engine;

        writeln!(f, "----- BEGIN RGB INTERFACE IMPLEMENTATION -----")?;
        if let Some(standard) = self.standard {
            writeln!(f, "Standard: {}", standard)?;
        }
        writeln!(f, "Schema: {:#}", self.schema_id)?;
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
