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
use amplify::{ByteArray, Bytes32};
use armor::{ArmorHeader, AsciiArmor, StrictArmor};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use commit_verify::{CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256};
use rgb::{validation, Schema};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::TypeSystem;

use super::{ASCII_ARMOR_SCHEMA, ASCII_ARMOR_SCRIPT, ASCII_ARMOR_TYPE_SYSTEM, ASCII_ARMOR_VERSION};
use crate::containers::{ContainerVer, ContentId, ContentSigs};
use crate::LIB_NAME_RGB_STD;

/// Kit identifier.
///
/// Kit identifier commits to all data provided within the kit.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
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

impl DisplayBaid64 for KitId {
    const HRI: &'static str = "rgb:kit";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = false;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for KitId {}
impl FromStr for KitId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for KitId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl_serde_baid64!(KitId);

impl KitId {
    pub const fn from_array(id: [u8; 32]) -> Self { KitId(Bytes32::from_array(id)) }
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

#[derive(Clone, Default, Debug, Display, PartialEq)]
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

    pub schemata: TinyOrdSet<Schema>,

    /// Type system covering all types used in schema.
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

        e.commit_to_set(&TinyOrdSet::from_iter_checked(
            self.schemata.iter().map(|schema| schema.schema_id()),
        ));

        e.commit_to_serialized(&self.types.id());
        e.commit_to_set(&SmallOrdSet::from_iter_checked(self.scripts.iter().map(|lib| lib.id())));

        e.commit_to_map(&self.signatures);
    }
}

impl Kit {
    #[inline]
    pub fn kit_id(&self) -> KitId { self.commit_id() }

    pub fn validate(
        self,
        // TODO: Add sig validator
        //_: &impl SigValidator,
    ) -> Result<ValidKit, (validation::Status, Kit)> {
        let status = validation::Status::new();
        // TODO:
        //  - Check schema integrity
        //  - Validate content sigs and remove untrusted ones
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
        let mut headers =
            vec![ArmorHeader::new(ASCII_ARMOR_VERSION, format!("{:#}", self.version))];
        for schema in &self.schemata {
            let mut header = ArmorHeader::new(ASCII_ARMOR_SCHEMA, schema.name.to_string());
            let id = schema.schema_id();
            header.params.push((s!("id"), format!("{id:-}")));
            headers.push(header);
        }
        headers.push(ArmorHeader::new(ASCII_ARMOR_TYPE_SYSTEM, self.types.id().to_string()));
        for lib in &self.scripts {
            headers.push(ArmorHeader::new(ASCII_ARMOR_SCRIPT, lib.id().to_string()));
        }
        headers
    }
}

impl FromStr for Kit {
    type Err = armor::StrictArmorError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_ascii_armored_str(s) }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn kit_str_round_trip() {
        let kit = Kit::from_str(include_str!("../../asset/armored_kit.default"))
            .expect("kit from str should work");

        let hardcoded = include_str!("../../asset/armored_kit.default").replace('\r', "");
        assert_eq!(kit.to_string(), hardcoded, "kit string round trip fails");

        assert_eq!(
            kit.validate().unwrap().to_string(),
            hardcoded,
            "validated kit string round trip fails"
        );
    }

    #[test]
    fn error_kit_strs() {
        assert!(Kit::from_str(
            r#"-----BEGIN RGB KIT-----
Id: rgb:kit:ij7UAXOl-MCrXzKt-L8fC6Vu-e$xPh5k-GEurStO-4RNfzsI
Version: 2
Type-System: sts:8Vb$sM1F-5MsQc20-HEixf55-gJR37FM-0zRKfpY-SwIp35w#design-farmer-camel
Check-SHA256: d86e8112f3c4c4442126f8e9f44f16867da487f29052bf91b810457db34209a4

0ssI200000

-----END RGB KIT-----"#
        )
        .is_ok());

        // Wrong Id
        assert!(Kit::from_str(
            r#"-----BEGIN RGB KIT-----
Id: rgb:kit:11111111-2222222-XmR8XRJ-v!q$Dzf-yImkPjD-t8EjfvI
Version: 2
Type-System: sts:8Vb$sM1F-5MsQc20-HEixf55-gJR37FM-0zRKfpY-SwIp35w#design-farmer-camel
Check-SHA256: d86e8112f3c4c4442126f8e9f44f16867da487f29052bf91b810457db34209a4

0ssI200000

-----END RGB KIT-----"#
        )
        .is_err());

        // wrong checksum
        assert!(Kit::from_str(
            r#"-----BEGIN RGB KIT-----
Id: rgb:kit:ij7UAXOl-MCrXzKt-L8fC6Vu-e$xPh5k-GEurStO-4RNfzsI
Version: 2
Type-System: sts:8Vb$sM1F-5MsQc20-HEixf55-gJR37FM-0zRKfpY-SwIp35w#design-farmer-camel
Check-SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

0ssI200000

-----END RGB KIT-----"#
        )
        .is_err());
    }
}
