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

use armor::{ArmorHeader, StrictArmor};
use commit_verify::CommitId;

use crate::containers::{Consignment, ConsignmentId};
use crate::interface::{ContractSuppl, Iface, IfaceId, IfaceImpl, ImplId, SupplId};

pub const ASCII_ARMOR_NAME: &str = "Name";
pub const ASCII_ARMOR_IFACE_ID: &str = "Interface-Id";
pub const ASCII_ARMOR_SCHEMA_ID: &str = "Schema-Id";
pub const ASCII_ARMOR_CONTRACT_ID: &str = "Contract-Id";
pub const ASCII_ARMOR_VERSION: &str = "Version";
pub const ASCII_ARMOR_TERMINAL: &str = "Terminal";
pub const ASCII_ARMOR_TYPE: &str = "Type";

impl<const TYPE: bool> StrictArmor for Consignment<TYPE> {
    type Id = ConsignmentId;
    const PLATE_TITLE: &'static str = "RGB CONSIGNMENT";

    fn armor_id(&self) -> Self::Id { self.commit_id() }
    fn armor_headers(&self) -> Vec<ArmorHeader> {
        let mut headers = vec![
            ArmorHeader::new(ASCII_ARMOR_VERSION, self.header.version.to_string()),
            ArmorHeader::new(
                ASCII_ARMOR_TYPE,
                if self.transfer {
                    s!("transfer")
                } else {
                    s!("contract")
                },
            ),
            ArmorHeader::new(ASCII_ARMOR_CONTRACT_ID, self.contract_id().to_string()),
        ];
        for bundle_id in self.terminals.keys() {
            headers.push(ArmorHeader::new(ASCII_ARMOR_TERMINAL, bundle_id.to_string()));
        }
        headers
    }
}

impl StrictArmor for Iface {
    type Id = IfaceId;
    const PLATE_TITLE: &'static str = "RGB INTERFACE";

    fn armor_id(&self) -> Self::Id { self.iface_id() }
    fn armor_headers(&self) -> Vec<ArmorHeader> {
        vec![ArmorHeader::new(ASCII_ARMOR_NAME, self.name.to_string())]
    }
}

impl StrictArmor for IfaceImpl {
    type Id = ImplId;
    const PLATE_TITLE: &'static str = "RGB IMPLEMENTATION";

    fn armor_id(&self) -> Self::Id { self.impl_id() }
    fn armor_headers(&self) -> Vec<ArmorHeader> {
        vec![
            ArmorHeader::new(ASCII_ARMOR_SCHEMA_ID, self.schema_id.to_string()),
            ArmorHeader::new(ASCII_ARMOR_IFACE_ID, self.iface_id.to_string()),
        ]
    }
}

impl StrictArmor for ContractSuppl {
    type Id = SupplId;
    const PLATE_TITLE: &'static str = "RGB SUPPLEMENT";

    fn armor_id(&self) -> Self::Id { self.suppl_id() }
    fn armor_headers(&self) -> Vec<ArmorHeader> {
        vec![ArmorHeader::new(ASCII_ARMOR_CONTRACT_ID, self.contract_id.to_string())]
    }
}
