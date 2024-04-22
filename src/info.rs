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

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter, Write};

use chrono::{DateTime, TimeZone, Utc};
use rgb::{Identity, SchemaId};
use strict_encoding::{FieldName, TypeName};

use crate::interface::{Iface, IfaceId, IfaceImpl, IfaceRef, ImplId, VerNo};
use crate::persistence::SchemaIfaces;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct IfaceInfo {
    pub id: IfaceId,
    pub version: VerNo,
    pub name: TypeName,
    pub developer: Identity,
    pub created_at: DateTime<Utc>,
    pub inherits: Vec<IfaceRef>,
    pub default_op: Option<FieldName>,
}

impl IfaceInfo {
    pub fn with(iface: &Iface, names: &HashMap<IfaceId, TypeName>) -> Self {
        eprintln!("{:#?}", names);
        IfaceInfo {
            id: iface.iface_id(),
            version: iface.version,
            name: iface.name.clone(),
            developer: iface.developer.clone(),
            created_at: Utc
                .timestamp_opt(iface.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
            inherits: iface
                .inherits
                .iter()
                .map(|id| {
                    names
                        .get(id)
                        .cloned()
                        .map(IfaceRef::Name)
                        .unwrap_or(IfaceRef::Id(*id))
                })
                .collect(),
            default_op: iface.default_operation.clone(),
        }
    }
}

impl Display for IfaceInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{: <18}", self.developer.to_string())?;
        f.write_char(f.fill())?;
        write!(f, "{}", self.version)?;
        f.write_char(f.fill())?;
        write!(f, "{}", self.created_at.format("%Y-%m-%d"))?;
        f.write_char(f.fill())?;
        write!(f, "{:24}", self.default_op.clone().unwrap_or_else(|| fname!("~")))?;
        f.write_char(f.fill())?;
        write!(
            f,
            "{:32}",
            self.inherits
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(f, "{}", self.name)?;
        f.write_char(f.fill())?;
        writeln!(f, "\t{}", self.id)
    }
}

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
    pub implements: Vec<ImplInfo>,
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
                .map(|(name, iimpl)| ImplInfo::with(name.clone(), iimpl))
                .collect(),
        }
    }
}

impl Display for SchemaInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{: <18}", self.developer.to_string())?;
        f.write_char(f.fill())?;
        write!(f, "{}", self.created_at.format("%Y-%m-%d"))?;
        f.write_char(f.fill())?;
        write!(f, "{: <80}", self.id.to_string())?;
        f.write_char(f.fill())?;
        writeln!(f, "{: <24}", self.name)?;
        f.write_char(f.fill())?;
        for info in &self.implements {
            writeln!(f, "\t{info}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ImplInfo {
    pub id: ImplId,
    pub iface_id: IfaceId,
    pub iface_name: TypeName,
    pub developer: Identity,
    pub created_at: DateTime<Utc>,
}

impl ImplInfo {
    pub fn with(iface_name: TypeName, iimpl: &IfaceImpl) -> Self {
        ImplInfo {
            id: iimpl.impl_id(),
            iface_id: iimpl.iface_id,
            iface_name,
            developer: iimpl.developer.clone(),
            created_at: Utc
                .timestamp_opt(iimpl.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
        }
    }
}

impl Display for ImplInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{: <24}", self.iface_name)?;
        f.write_char(f.fill())?;
        write!(f, "{: <18}", self.developer.to_string())?;
        f.write_char(f.fill())?;
        write!(f, "{}", self.created_at.format("%Y-%m-%d"))?;
        f.write_char(f.fill())?;
        write!(f, "{: <80}", self.id.to_string())
    }
}