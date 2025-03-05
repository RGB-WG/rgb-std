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

use std::fmt::{self, Debug, Display, Formatter};

use chrono::{DateTime, TimeZone, Utc};
use rgb::{ChainNet, ContractId, Genesis, Identity, Operation, Schema, SchemaId};
use strict_encoding::TypeName;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SchemaInfo {
    pub id: SchemaId,
    pub name: TypeName,
    pub developer: Identity,
    pub created_at: DateTime<Utc>,
}

impl SchemaInfo {
    pub fn with(schema: &Schema) -> Self {
        SchemaInfo {
            id: schema.schema_id(),
            name: schema.name.clone(),
            developer: schema.developer.clone(),
            created_at: Utc
                .timestamp_opt(schema.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
        }
    }
}

impl Display for SchemaInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{: <24}", self.name.to_string())?;
        write!(f, "\t{: <80}", self.id.to_string())?;
        write!(f, "\t{}", self.created_at.format("%Y-%m-%d"))?;
        writeln!(f, "\t{}", self.developer)?;
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractInfo {
    pub id: ContractId,
    pub schema_id: SchemaId,
    pub issuer: Identity,
    pub issued_at: DateTime<Utc>,
    pub chain_net: ChainNet,
}

impl ContractInfo {
    pub fn with(genesis: &Genesis) -> Self {
        ContractInfo {
            id: genesis.contract_id(),
            schema_id: genesis.schema_id,
            issuer: genesis.issuer.clone(),
            issued_at: Utc
                .timestamp_opt(genesis.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
            chain_net: genesis.chain_net,
        }
    }
}

impl Display for ContractInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)?;
        write!(f, "\t{}", self.chain_net)?;
        write!(f, "\t{}", self.issued_at.format("%Y-%m-%d"))?;
        writeln!(f, "\t{: <80}", self.schema_id.to_string())?;
        writeln!(f, "  Developer: {}", self.issuer)
    }
}
