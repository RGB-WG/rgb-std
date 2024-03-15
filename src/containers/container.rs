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

use std::collections::{btree_set, BTreeSet};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::{fmt, io};

use aluvm::data::encoding::{Decode, Encode};
use aluvm::library::{Lib, LibId};
use amplify::confinement::{
    Confined, SmallBlob, SmallOrdMap, SmallOrdSet, TinyAscii, TinyBlob, TinyOrdMap, TinyOrdSet,
    TinyString,
};
use amplify::{ByteArray, Bytes32};
use armor::{ArmorHeader, StrictArmor};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use commit_verify::{CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256};
use rgb::{ContractId, SchemaId};
use strict_encoding::{
    DecodeError, ReadTuple, StrictDecode, StrictDeserialize, StrictEncode, StrictProduct,
    StrictSerialize, StrictTuple, StrictType, TypedRead, TypedWrite, WriteTuple,
};
use strict_types::{TypeLib, TypeLibId, TypeSysId, TypeSystem};

use super::Kit;
use crate::containers::armor::ASCII_ARMOR_VERSION;
use crate::interface::{Iface, IfaceId, ImplId, SupplId};
use crate::LIB_NAME_RGB_STD;

pub type IfaceContainer = Container<Iface>;
pub type KitContainer = Container<Kit>;

/// Container identifier.
///
/// Container identifier commits the container data and container headers,
/// except container signatures. Container signatures sign container identifier
/// as a message.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ContainerId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for ContainerId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for ContainerId {
    const TAG: &'static str = "urn:lnp-bp:rgb:container#2024-03-13";
}

impl ToBaid58<32> for ContainerId {
    const HRI: &'static str = "pkg";
    const CHUNKING: Option<Chunking> = CHUNKING_32;
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_byte_array() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for ContainerId {}
impl Display for ContainerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            f.write_str("urn:lnp-bp:")?;
        }
        if f.sign_minus() {
            write!(f, "{:.2}", self.to_baid58())
        } else {
            write!(f, "{:#.2}", self.to_baid58())
        }
    }
}
impl FromStr for ContainerId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_baid58_maybe_chunked_str(s.trim_start_matches("urn:lnp-bp:"), ':', '#')
    }
}
impl ContainerId {
    pub const fn from_array(id: [u8; 32]) -> Self { Self(Bytes32::from_array(id)) }
    pub fn to_mnemonic(&self) -> String { self.to_baid58().mnemonic() }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(lowercase)]
#[non_exhaustive]
#[repr(u8)]
pub enum ContainerVer {
    // V0 and V1 was a previous version before v0.11, currently not supported.
    #[default]
    V2 = 2,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContainerHeader {
    /// Version.
    pub version: ContainerVer,
    /// Signatures over the container id.
    pub container_sigs: TinyOrdSet<SigSet>,
    /// Signatures on the pieces of content which are the part of the
    /// consignment.
    pub content_sigs: TinyOrdMap<ContentId, SigSet>,
    /// Type libraries used by schema and interfaces.
    pub types: Types,
    /// Validation scripts used by schema and interfaces.
    pub scripts: SmallOrdMap<LibId, AluLib>,
}

impl ContainerHeader {
    pub(crate) fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.version);
        e.commit_to_map(&self.content_sigs);
        self.types.commit_encode(e);
        e.commit_to_serialized(&self.scripts.len_u16());
        for id in self.scripts.keys() {
            e.commit_to_serialized(id);
        }
    }
}

pub trait ContainerContent: StrictEncode + StrictDecode {
    const ARMOR_PLATE_TITLE: &'static str;
    fn armor_headers(&self) -> Vec<ArmorHeader>;
}

/// Container represents an information distributed between RGB users.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = ContainerId)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Container<C: ContainerContent> {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub header: ContainerHeader,

    /// Content hosted by the container.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub content: C,
}

impl<C: ContainerContent> StrictSerialize for Container<C> {}
impl<C: ContainerContent> StrictDeserialize for Container<C> {}

impl<C: ContainerContent> StrictArmor for Container<C> {
    type Id = ContainerId;
    const PLATE_TITLE: &'static str = C::ARMOR_PLATE_TITLE;

    fn armor_id(&self) -> Self::Id { self.commit_id() }

    fn armor_headers(&self) -> Vec<ArmorHeader> {
        let mut headers =
            vec![ArmorHeader::new(ASCII_ARMOR_VERSION, self.header.version.to_string())];
        // TODO: Add signatures
        headers.extend(self.content.armor_headers());
        headers
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Types {
    pub index: SmallOrdMap<TypeSysId, SmallOrdSet<TypeLibId>>,
    pub libs: SmallOrdMap<TypeLibId, TypeLib>,
    #[strict_type(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub systems: SmallOrdMap<TypeSysId, TypeSystem>,
}

impl Types {
    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_map(&self.index);
        e.commit_to_serialized(&self.libs.len_u16());
        e.commit_to_serialized(&self.systems.len_u16());
        // We skip the rest since commitment to ids suffice
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom, dumb = ContentId::Schema(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum ContentId {
    #[strict_type(tag = 0x01)]
    TypeLib(TypeLibId),
    #[strict_type(tag = 0x02)]
    ScriptLib(LibId),
    #[strict_type(tag = 0x10)]
    Schema(SchemaId),
    #[strict_type(tag = 0x11)]
    Genesis(ContractId),
    #[strict_type(tag = 0x20)]
    Iface(IfaceId),
    #[strict_type(tag = 0x21)]
    IfaceImpl(ImplId),
    #[strict_type(tag = 0x80)]
    Suppl(SupplId),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display("{name} <{email}>; using={suite}")]
#[non_exhaustive]
pub struct Identity {
    pub name: TinyString,
    pub email: TinyAscii,
    pub suite: IdSuite,
    pub pk: TinyBlob,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[non_exhaustive]
#[repr(u8)]
pub enum IdSuite {
    #[strict_type(dumb)]
    #[display("OpenPGP")]
    Pgp,
    #[display("OpenSSH")]
    Ssh,
    #[display("SSI")]
    Ssi,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Sig {
    pub signer: Identity,
    pub signature: TinyBlob,
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, dumb = Self(confined_bset!(strict_dumb!())))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct SigSet(Confined<BTreeSet<Sig>, 1, 10>);

impl IntoIterator for SigSet {
    type Item = Sig;
    type IntoIter = btree_set::IntoIter<Sig>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

#[derive(Wrapper, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, From)]
#[wrapper(Deref, Display)]
pub struct AluLib(pub Lib);

// TODO: Remove this once aluvm::Lib will support strict encoding
impl StrictType for AluLib {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_RGB_STD;
}
impl StrictProduct for AluLib {}
impl StrictTuple for AluLib {
    const FIELD_COUNT: u8 = 1;
}
impl StrictEncode for AluLib {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        let blob = SmallBlob::try_from(self.0.serialize()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Alu library has size exceeding RGB requirement of 64kiB",
            )
        })?;
        writer.write_tuple::<Self>(|w| Ok(w.write_field(&blob)?.complete()))
    }
}
impl StrictDecode for AluLib {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let blob = r.read_field::<SmallBlob>()?;
            let lib = Lib::deserialize(&blob)
                .map_err(|e| DecodeError::DataIntegrityError(e.to_string()))?;
            Ok(AluLib(lib))
        })
    }
}

#[cfg(feature = "serde")]
mod _serde {
    use aluvm::library::Lib;
    use armor::AsciiArmor;
    use serde_crate::de::Error;
    use serde_crate::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for AluLib {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.0.to_ascii_armored_string())
            } else {
                Serialize::serialize(&self.0, serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for AluLib {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s: String = Deserialize::deserialize(deserializer)?;
                let lib = Lib::from_ascii_armored_str(&s).map_err(D::Error::custom)?;
                Ok(lib.into())
            } else {
                let lib: Lib = Deserialize::deserialize(deserializer)?;
                Ok(lib.into())
            }
        }
    }
}
