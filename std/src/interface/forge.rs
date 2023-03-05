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

use rgb::Schema;
use strict_types::StrictVal;

use crate::containers::Contract;
use crate::interface::{Iface, IfaceImpl};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ForgeError {}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IssueError {}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Forge {
    pub iface: Iface,
    pub schema: Schema,
    pub imp: IfaceImpl,
}

impl Forge {
    pub fn with(iface: Iface, schema: Schema, imp: IfaceImpl) -> Result<Self, ForgeError> {
        todo!()
    }

    pub fn issue(
        &self,
        global: impl Into<StrictVal>,
        owned: impl Into<StrictVal>,
    ) -> Result<Contract, IssueError> {
        todo!()
    }
}
