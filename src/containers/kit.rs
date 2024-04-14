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

use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;

use aluvm::library::Lib;
use amplify::confinement::{SmallOrdSet, TinyOrdMap, TinyOrdSet};
use amplify::Bytes32;
use armor::{ArmorHeader, AsciiArmor, StrictArmor};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use commit_verify::{CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256};
use rgb::{validation, Schema};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::TypeSystem;

use super::{
    ASCII_ARMOR_IFACE, ASCII_ARMOR_IIMPL, ASCII_ARMOR_SCHEMA, ASCII_ARMOR_SCRIPT,
    ASCII_ARMOR_SUPPL, ASCII_ARMOR_TYPE_SYSTEM, ASCII_ARMOR_VERSION,
};
use crate::containers::{ContainerVer, ContentId, ContentSigs};
use crate::interface::{ContractSuppl, Iface, IfaceImpl};
use crate::LIB_NAME_RGB_STD;

/// Kit identifier.
///
/// Kit identifier commits to all data provided within the kit.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct KitId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for KitId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for KitId {
    const TAG: &'static str = "urn:lnp-bp:rgb:kit#2024-04-09";
}

impl ToBaid58<32> for KitId {
    const HRI: &'static str = "kit";
    const CHUNKING: Option<Chunking> = CHUNKING_32;
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_byte_array() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for KitId {}
impl Display for KitId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            f.write_str("urn:lnp-bp:kit:")?;
        }
        if f.sign_minus() {
            write!(f, "{:.2}", self.to_baid58())
        } else {
            write!(f, "{:#.2}", self.to_baid58())
        }
    }
}
impl FromStr for KitId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_baid58_maybe_chunked_str(s.trim_start_matches("urn:lnp-bp:"), ':', '#')
    }
}
impl KitId {
    pub const fn from_array(id: [u8; 32]) -> Self { KitId(Bytes32::from_array(id)) }
    pub fn to_mnemonic(&self) -> String { self.to_baid58().mnemonic() }
}

#[derive(Clone, Debug, Display)]
#[display("{kit}")]
pub struct ValidKit {
    /// Status of the latest validation.
    validation_status: validation::Status,
    kit: Kit,
}

impl ValidKit {
    pub fn validation_status(&self) -> &validation::Status { &self.validation_status }

    pub fn into_kit(self) -> Kit { self.kit }

    pub fn into_validation_status(self) -> validation::Status { self.validation_status }

    pub fn split(self) -> (Kit, validation::Status) { (self.kit, self.validation_status) }
}

impl Deref for ValidKit {
    type Target = Kit;

    fn deref(&self) -> &Self::Target { &self.kit }
}

#[derive(Clone, Default, Debug, Display)]
#[display(AsciiArmor::to_ascii_armored_string)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Kit {
    /// Version.
    pub version: ContainerVer,

    pub ifaces: TinyOrdSet<Iface>,

    pub schemata: TinyOrdSet<Schema>,

    pub iimpls: TinyOrdSet<IfaceImpl>,

    pub supplements: TinyOrdSet<ContractSuppl>,

    /// Type system covering all types used in schema, interfaces and
    /// implementations.
    pub types: TypeSystem,

    /// Collection of scripts used across kit data.
    pub scripts: SmallOrdSet<Lib>,

    /// Signatures on the pieces of content which are the part of the kit.
    pub signatures: TinyOrdMap<ContentId, ContentSigs>,
}

impl StrictSerialize for Kit {}
impl StrictDeserialize for Kit {}

impl CommitEncode for Kit {
    type CommitmentId = KitId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.version);

        e.commit_to_set(&TinyOrdSet::from_iter_unsafe(
            self.ifaces.iter().map(|iface| iface.iface_id()),
        ));
        e.commit_to_set(&TinyOrdSet::from_iter_unsafe(
            self.schemata.iter().map(|schema| schema.schema_id()),
        ));
        e.commit_to_set(&TinyOrdSet::from_iter_unsafe(
            self.iimpls.iter().map(|iimpl| iimpl.impl_id()),
        ));
        e.commit_to_set(&TinyOrdSet::from_iter_unsafe(
            self.supplements.iter().map(|suppl| suppl.suppl_id()),
        ));

        e.commit_to_serialized(&self.types.id());
        e.commit_to_set(&SmallOrdSet::from_iter_unsafe(self.scripts.iter().map(|lib| lib.id())));

        e.commit_to_map(&self.signatures);
    }
}

impl Kit {
    #[inline]
    pub fn kit_id(&self) -> KitId { self.commit_id() }

    pub fn validate(self) -> Result<ValidKit, (validation::Status, Kit)> {
        let status = validation::Status::new();
        // TODO:
        //  - Verify integrity for each interface
        //  - Verify implementations against interfaces
        //  - Check schema integrity
        Ok(ValidKit {
            validation_status: status,
            kit: self,
        })
    }
}

impl StrictArmor for Kit {
    type Id = KitId;
    const PLATE_TITLE: &'static str = "RGB KIT";

    fn armor_id(&self) -> Self::Id { self.kit_id() }
    fn armor_headers(&self) -> Vec<ArmorHeader> {
        let mut headers = vec![ArmorHeader::new(ASCII_ARMOR_VERSION, self.version.to_string())];
        for iface in &self.ifaces {
            let mut header = ArmorHeader::new(ASCII_ARMOR_IFACE, iface.name.to_string());
            header.params.push((s!("id"), iface.iface_id().to_string()));
            headers.push(header);
        }
        for iimpl in &self.iimpls {
            let mut header = ArmorHeader::new(ASCII_ARMOR_IIMPL, iimpl.impl_id().to_string());
            header.params.push((s!("of"), iimpl.iface_id.to_string()));
            header.params.push((s!("for"), iimpl.schema_id.to_string()));
            headers.push(header);
        }
        for schema in &self.schemata {
            headers.push(ArmorHeader::new(ASCII_ARMOR_SCHEMA, schema.schema_id().to_string()));
        }
        headers.push(ArmorHeader::new(ASCII_ARMOR_TYPE_SYSTEM, self.types.id().to_string()));
        for lib in &self.scripts {
            headers.push(ArmorHeader::new(ASCII_ARMOR_SCRIPT, lib.id().to_string()));
        }
        for suppl in &self.supplements {
            headers.push(ArmorHeader::new(ASCII_ARMOR_SUPPL, suppl.suppl_id().to_string()));
        }
        headers
    }
}
