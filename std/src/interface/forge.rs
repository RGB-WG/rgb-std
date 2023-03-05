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

use bp::Chain;
use rgb::{Genesis, Schema};
use strict_types::StrictVal;

use crate::containers::Contract;
use crate::interface::{Iface, IfaceImpl, IfacePair};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ForgeError {
    /// interface implementation references different interface that the one
    /// provided to the forge.
    InterfaceMismatch,

    /// interface implementation references different schema that the one
    /// provided to the forge.
    SchemaMismatch,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IssueError {}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Forge {
    schema: Schema,
    iface: Iface,
    imp: IfaceImpl,
}

impl Forge {
    pub fn with(iface: Iface, schema: Schema, imp: IfaceImpl) -> Result<Self, ForgeError> {
        if imp.iface_id != iface.iface_id() {
            return Err(ForgeError::InterfaceMismatch);
        }
        if imp.schema_id != schema.schema_id() {
            return Err(ForgeError::SchemaMismatch);
        }

        // TODO: check schema internal consistency
        // TODO: check interface internal consistency
        // TODO: check implmenetation internal consistency

        Ok(Forge { schema, iface, imp })
    }

    pub fn issue(
        &self,
        chain: Chain,
        global: impl Into<StrictVal>,
        owned: impl Into<StrictVal>,
    ) -> Result<Contract, IssueError> {
        let genesis = Genesis {
            ffv: none!(),
            schema_id: self.schema.schema_id(),
            chain,
            metadata: None,
            global_state: Default::default(),
            owned_state: Default::default(),
            valencies: none!(),
        };
        Ok(Contract::new(
            self.schema.clone(),
            IfacePair::with(self.iface.clone(), self.imp.clone()),
            genesis,
        ))
    }
}
