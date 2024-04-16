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

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use rgb::{Identity, SchemaId};
use strict_encoding::{FieldName, TypeName};

use crate::interface::{Iface, IfaceId, IfaceImpl, ImplId, VerNo};
use crate::persistence::SchemaIfaces;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct IfaceInfo {
    pub id: IfaceId,
    pub version: VerNo,
    pub name: TypeName,
    pub developer: Identity,
    pub created_at: DateTime<Utc>,
    pub inherits: Vec<IfaceId>,
    pub default_op: Option<FieldName>,
}

impl IfaceInfo {
    pub fn with(iface: &Iface) -> Self {
        IfaceInfo {
            id: iface.iface_id(),
            version: iface.version,
            name: iface.name.clone(),
            developer: iface.developer.clone(),
            created_at: Utc
                .timestamp_opt(iface.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
            inherits: iface.inherits.iter().cloned().collect(),
            default_op: iface.default_operation.clone(),
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct SchemaInfo {
    pub id: SchemaId,
    pub name: TypeName,
    pub developer: Identity,
    pub created_at: DateTime<Utc>,
    pub implements: BTreeMap<IfaceId, ImplInfo>,
}

impl SchemaInfo {
    pub fn with(schema_ifaces: &SchemaIfaces) -> Self {
        let schema = &schema_ifaces.schema;
        SchemaInfo {
            id: schema.schema_id(),
            name: schema.name.clone(),
            developer: schema.developer.clone(),
            created_at: Utc
                .timestamp_opt(schema.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
            implements: schema_ifaces
                .iimpls
                .iter()
                .map(|(id, iimpl)| (*id, ImplInfo::with(iimpl)))
                .collect(),
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct ImplInfo {
    pub id: ImplId,
    pub iface_id: IfaceId,
    pub developer: Identity,
    pub created_at: DateTime<Utc>,
}

impl ImplInfo {
    pub fn with(iimpl: &IfaceImpl) -> Self {
        ImplInfo {
            id: iimpl.impl_id(),
            iface_id: iimpl.iface_id,
            developer: iimpl.developer.clone(),
            created_at: Utc
                .timestamp_opt(iimpl.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
        }
    }
}
