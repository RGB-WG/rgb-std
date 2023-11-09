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

//! Bindle is a wrapper for different RGB containers, which can be serialized
//! and optionally signed by the creator with certain id and send over to a
//! remote party.

use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::io::{self, Read};
use std::ops::Deref;
use std::str::FromStr;

use amplify::confinement::{self, Confined, TinyVec, U24};
use baid58::Baid58ParseError;
use rgb::{BundleId, ContractId, Schema, SchemaId, SchemaRoot, SubSchema};
use strict_encoding::{
    StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictReader, StrictSerialize,
    StrictType,
};

use crate::containers::transfer::TransferId;
use crate::containers::{Cert, Contract, Transfer};
use crate::interface::{Iface, IfaceId, IfaceImpl, ImplId};
use crate::LIB_NAME_RGB_STD;

// TODO: Move to UBIDECO crate
pub trait BindleContent: StrictSerialize + StrictDeserialize + StrictDumb {
    /// Magic bytes used in saving/restoring container from a file.
    const MAGIC: [u8; 4];
    /// String used in ASCII armored blocks
    const PLATE_TITLE: &'static str;

    type Id: Copy
        + Eq
        + Debug
        + Display
        + FromStr<Err = Baid58ParseError>
        + StrictType
        + StrictDumb
        + StrictEncode
        + StrictDecode;

    fn bindle_id(&self) -> Self::Id;
    fn bindle_headers(&self) -> BTreeMap<&'static str, String> { none!() }
    fn bindle(self) -> Bindle<Self> { Bindle::new(self) }
    fn bindle_mnemonic(&self) -> Option<String> { None }
}

impl<Root: SchemaRoot> BindleContent for Schema<Root> {
    const MAGIC: [u8; 4] = *b"SCHM";
    const PLATE_TITLE: &'static str = "RGB SCHEMA";
    type Id = SchemaId;
    fn bindle_id(&self) -> Self::Id { self.schema_id() }
    fn bindle_mnemonic(&self) -> Option<String> { Some(self.schema_id().to_mnemonic()) }
}

impl BindleContent for Contract {
    const MAGIC: [u8; 4] = *b"CNRC";
    const PLATE_TITLE: &'static str = "RGB CONTRACT";
    type Id = ContractId;
    fn bindle_id(&self) -> Self::Id { self.contract_id() }
    fn bindle_headers(&self) -> BTreeMap<&'static str, String> {
        bmap! {
            "Version" => self.version.to_string(),
            "Terminals" => self.terminals
                .keys()
                .map(BundleId::to_string)
                .collect::<Vec<_>>()
                .join(",\n  "),
        }
    }
}

impl BindleContent for Transfer {
    const MAGIC: [u8; 4] = *b"TRNS";
    const PLATE_TITLE: &'static str = "RGB STATE TRANSFER";
    type Id = TransferId;
    fn bindle_id(&self) -> Self::Id { self.transfer_id() }
    fn bindle_mnemonic(&self) -> Option<String> { Some(self.transfer_id().to_mnemonic()) }
    fn bindle_headers(&self) -> BTreeMap<&'static str, String> {
        bmap! {
            "Version" => self.version.to_string(),
            "ContractId" => self.contract_id().to_string(),
            "Terminals" => self.terminals
                .keys()
                .map(BundleId::to_string)
                .collect::<Vec<_>>()
                .join(",\n  "),
        }
    }
}

impl BindleContent for Iface {
    const MAGIC: [u8; 4] = *b"IFCE";
    const PLATE_TITLE: &'static str = "RGB INTERFACE";
    type Id = IfaceId;
    fn bindle_id(&self) -> Self::Id { self.iface_id() }
    fn bindle_mnemonic(&self) -> Option<String> { Some(self.iface_id().to_mnemonic()) }
    fn bindle_headers(&self) -> BTreeMap<&'static str, String> {
        bmap! {
            "Name" => self.name.to_string()
        }
    }
}

impl BindleContent for IfaceImpl {
    const MAGIC: [u8; 4] = *b"IMPL";
    const PLATE_TITLE: &'static str = "RGB INTERFACE IMPLEMENTATION";
    type Id = ImplId;
    fn bindle_id(&self) -> Self::Id { self.impl_id() }
    fn bindle_mnemonic(&self) -> Option<String> { Some(self.impl_id().to_mnemonic()) }
    fn bindle_headers(&self) -> BTreeMap<&'static str, String> {
        bmap! {
            "IfaceId" => format!("{:-#}", self.iface_id),
            "SchemaId" => format!("{:-#}", self.schema_id),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Bindle<C: BindleContent> {
    id: C::Id,
    data: C,
    sigs: TinyVec<Cert>,
}

impl<C: BindleContent> Deref for Bindle<C> {
    type Target = C;
    fn deref(&self) -> &Self::Target { &self.data }
}

impl<C: BindleContent> From<C> for Bindle<C> {
    fn from(data: C) -> Self { Bindle::new(data) }
}

impl<C: BindleContent> Bindle<C> {
    pub fn new(data: C) -> Self {
        Bindle {
            id: data.bindle_id(),
            data,
            sigs: empty!(),
        }
    }

    pub fn id(&self) -> C::Id { self.id }

    pub fn into_split(self) -> (C, TinyVec<Cert>) { (self.data, self.sigs) }
    pub fn unbindle(self) -> C { self.data }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BindleParseError<Id: Copy + Eq + Debug + Display> {
    /// the provided text doesn't represent a recognizable ASCII-armored RGB
    /// bindle encoding.
    WrongStructure,

    /// Id header of the bindle contains unparsable information. Details: {0}
    InvalidId(Baid58ParseError),

    /// the actual data doesn't match the provided id.
    ///
    /// Actual id: {actual}.
    ///
    /// Expected id: {expected}.
    MismatchedId { actual: Id, expected: Id },

    /// bindle data has invalid Base85 encoding (ASCII armoring).
    #[from(base85::Error)]
    Base85,

    /// unable to decode the provided bindle data. Details: {0}
    #[from]
    Deserialize(strict_encoding::DeserializeError),

    /// bindle contains more than 16MB of data.
    #[from(confinement::Error)]
    TooLarge,
}

impl<C: BindleContent> FromStr for Bindle<C> {
    type Err = BindleParseError<C::Id>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.lines();
        let first = format!("-----BEGIN {}-----", C::PLATE_TITLE);
        let last = format!("-----END {}-----", C::PLATE_TITLE);
        if (lines.next(), lines.next_back()) != (Some(&first), Some(&last)) {
            return Err(BindleParseError::WrongStructure);
        }
        let mut header_id = None;
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            if let Some(id_str) = line.strip_prefix("Id: ") {
                header_id = Some(C::Id::from_str(id_str).map_err(BindleParseError::InvalidId)?);
            }
        }
        let armor = lines.filter(|l| !l.is_empty()).collect::<String>();
        let data = base85::decode(&armor)?;
        let data = C::from_strict_serialized::<U24>(Confined::try_from(data)?)?;
        let id = data.bindle_id();
        if let Some(header_id) = header_id {
            if header_id != id {
                return Err(BindleParseError::MismatchedId {
                    actual: id,
                    expected: header_id,
                });
            }
        }
        // TODO: check mnemonic
        // TODO: parse and validate sigs
        Ok(Self {
            id,
            data,
            sigs: none!(),
        })
    }
}

impl<C: BindleContent> Display for Bindle<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "-----BEGIN {}-----", C::PLATE_TITLE)?;
        writeln!(f, "Id: {:-#}", self.id)?;
        if let Some(mnemonic) = self.bindle_mnemonic() {
            writeln!(f, "Mnemonic: {}", mnemonic)?;
        }
        for (header, value) in self.bindle_headers() {
            writeln!(f, "{header}: {value}")?;
        }
        for cert in &self.sigs {
            writeln!(f, "Signed-By: {}", cert.signer)?;
        }
        writeln!(f)?;

        // TODO: Replace with streamed writer
        let data = self.data.to_strict_serialized::<U24>().expect("in-memory");
        let data = base85::encode(&data);
        let mut data = data.as_str();
        while data.len() >= 64 {
            let (line, rest) = data.split_at(64);
            writeln!(f, "{}", line)?;
            data = rest;
        }
        writeln!(f, "{}", data)?;

        writeln!(f, "\n-----END {}-----", C::PLATE_TITLE)?;
        Ok(())
    }
}

impl<C: BindleContent> Bindle<C> {
    pub fn load(mut data: impl Read) -> Result<Self, LoadError> {
        let mut rgb = [0u8; 3];
        let mut magic = [0u8; 4];
        data.read_exact(&mut rgb)?;
        data.read_exact(&mut magic)?;
        if rgb != *b"RGB" || magic != C::MAGIC {
            return Err(LoadError::InvalidMagic);
        }
        let mut reader = StrictReader::with(usize::MAX, data);
        let me = Self::strict_decode(&mut reader)?;
        Ok(me)
    }
}

#[derive(Clone, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
pub enum UniversalBindle {
    #[from]
    #[cfg_attr(feature = "serde", serde(rename = "interface"))]
    Iface(Bindle<Iface>),

    #[from]
    Schema(Bindle<SubSchema>),

    #[from]
    #[cfg_attr(feature = "serde", serde(rename = "implementation"))]
    Impl(Bindle<IfaceImpl>),

    #[from]
    Contract(Bindle<Contract>),

    #[from]
    Transfer(Bindle<Transfer>),
}

impl UniversalBindle {
    pub fn load(mut data: impl Read) -> Result<Self, LoadError> {
        let mut rgb = [0u8; 3];
        let mut magic = [0u8; 4];
        data.read_exact(&mut rgb)?;
        data.read_exact(&mut magic)?;
        if rgb != *b"RGB" {
            return Err(LoadError::InvalidMagic);
        }
        let mut reader = StrictReader::with(usize::MAX, data);
        Ok(match magic {
            x if x == Iface::MAGIC => Bindle::<Iface>::strict_decode(&mut reader)?.into(),
            x if x == SubSchema::MAGIC => Bindle::<SubSchema>::strict_decode(&mut reader)?.into(),
            x if x == IfaceImpl::MAGIC => Bindle::<IfaceImpl>::strict_decode(&mut reader)?.into(),
            x if x == Contract::MAGIC => Bindle::<Contract>::strict_decode(&mut reader)?.into(),
            x if x == Transfer::MAGIC => Bindle::<Transfer>::strict_decode(&mut reader)?.into(),
            _ => return Err(LoadError::InvalidMagic),
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum LoadError {
    /// invalid file data.
    InvalidMagic,

    #[display(inner)]
    #[from]
    #[from(io::Error)]
    Decode(strict_encoding::DecodeError),
}

#[cfg(feature = "fs")]
mod _fs {
    use std::io::Write;
    use std::path::Path;
    use std::{fs, io};

    use strict_encoding::{StrictEncode, StrictWriter};

    use super::*;

    impl<C: BindleContent> Bindle<C> {
        pub fn load_file(path: impl AsRef<Path>) -> Result<Self, LoadError> {
            let file = fs::File::open(path)?;
            Self::load(file)
        }

        pub fn save(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
            let mut file = fs::File::create(path)?;
            file.write_all(b"RGB")?;
            file.write_all(&C::MAGIC)?;
            let writer = StrictWriter::with(usize::MAX, file);
            self.strict_encode(writer)?;
            Ok(())
        }
    }

    impl UniversalBindle {
        pub fn load_file(path: impl AsRef<Path>) -> Result<Self, LoadError> {
            let file = fs::File::open(path)?;
            Self::load(file)
        }
    }
}
