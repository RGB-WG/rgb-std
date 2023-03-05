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
use strict_encoding::TypeName;

/// Maps certain form of type id (global or owned state or a specific operation
/// type) to a human-readable name.
///
/// Two distinct [`NamedType`] objects must always have both different state ids
/// and names.   
#[derive(Clone, Eq, PartialOrd, Ord, Debug)]
pub struct NamedType<T> {
    pub id: T,
    pub name: TypeName,
}

impl<T> PartialEq for NamedType<T>
where T: Eq
{
    fn eq(&self, other: &Self) -> bool { self.id == other.id || self.name == other.name }
}

impl<T> NamedType<T> {
    pub fn with(id: T, name: TypeName) -> NamedType<T> { NamedType { id, name } }
}

/// Interface implementation for some specific schema.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct IfaceImpl {
    pub schema_id: SchemaId,
    pub global_state: TinyOrdSet<NamedType<GlobalStateType>>,
    pub owned_state: TinyOrdSet<NamedType<OwnedStateType>>,
    pub valencies: TinyOrdSet<NamedType<ValencyType>>,
    pub transitions: TinyOrdSet<NamedType<TransitionType>>,
    pub extensions: TinyOrdSet<NamedType<ExtensionType>>,
}
