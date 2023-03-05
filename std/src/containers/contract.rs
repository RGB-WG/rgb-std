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

use rgb::{Genesis, Schema};

use crate::containers::{ContainerVer, Contract};
use crate::interface::IfacePair;

impl Contract {
    pub fn new(schema: Schema, iface: IfacePair, genesis: Genesis) -> Self {
        Contract {
            version: ContainerVer::V1,
            transfer: false,
            schema,
            ifaces: tiny_bmap! { iface.iface_id() => iface },
            genesis,
            terminals: none!(),
            bundles: none!(),
            extensions: none!(),
            attachments: none!(),
            signatures: none!(),
        }
    }
}
