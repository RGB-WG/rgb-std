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

use amplify::confinement::Confined;
use strict_types::TypeSystem;

use crate::containers::{ContainerVer, Kit, ValidKit};
use crate::contract::ContractData;
use crate::persistence::ContractStateRead;
use crate::validation::Scripts;
use crate::Schema;

/// The instances implementing this trait are used as wrappers around [`ContractData`] object,
/// allowing a simple API matching the schema requirements.
pub trait SchemaWrapper<S: ContractStateRead> {
    fn with(data: ContractData<S>) -> Self;
}

pub trait IssuerWrapper {
    type Wrapper<S: ContractStateRead>: SchemaWrapper<S>;

    fn schema() -> Schema;
    fn types() -> TypeSystem;
    fn scripts() -> Scripts;

    fn kit() -> ValidKit {
        let kit = Kit {
            version: ContainerVer::V0,
            schemata: tiny_bset![Self::schema()],
            types: Self::types(),
            scripts: Confined::from_iter_checked(Self::scripts().release().into_values()),
        };
        kit.validate().expect("invalid construction")
    }
}
