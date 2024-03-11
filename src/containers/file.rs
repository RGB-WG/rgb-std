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

use std::fmt::Debug;
use std::io::{self, Read, Write};

use amplify::confinement::U32 as FILE_MAX_LEN;
use armor::StrictArmor;
use rgb::{Schema, SchemaRoot, SubSchema};
use strict_encoding::{StreamReader, StreamWriter, StrictDecode, StrictEncode};

use crate::containers::{Contract, Transfer};
use crate::interface::{ContractSuppl, Iface, IfaceImpl};

const RGB_PREFIX: [u8; 4] = *b"RGB\x00";

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

pub trait FileContent: StrictArmor {
    /// Magic bytes used in saving/restoring container from a file.
    const MAGIC: [u8; 4];

    fn load(mut data: impl Read) -> Result<Self, LoadError> {
        let mut rgb = [0u8; 4];
        let mut magic = [0u8; 4];
        data.read_exact(&mut rgb)?;
        data.read_exact(&mut magic)?;
        if rgb != RGB_PREFIX || magic != Self::MAGIC {
            return Err(LoadError::InvalidMagic);
        }

        let reader = StreamReader::new::<FILE_MAX_LEN>(data);
        let me = Self::strict_read(reader)?;

        Ok(me)
    }

    fn save(&self, mut writer: impl Write) -> Result<(), io::Error> {
        writer.write_all(&RGB_PREFIX)?;
        writer.write_all(&Self::MAGIC)?;

        let writer = StreamWriter::new::<FILE_MAX_LEN>(writer);
        self.strict_write(writer)?;

        Ok(())
    }

    #[cfg(feature = "fs")]
    fn load_file(path: impl AsRef<std::path::Path>) -> Result<Self, LoadError> {
        let file = std::fs::File::open(path)?;
        Self::load(file)
    }

    #[cfg(feature = "fs")]
    fn save_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), io::Error> {
        let file = std::fs::File::create(path)?;
        self.save(file)
    }
}

impl<Root: SchemaRoot> FileContent for Schema<Root> {
    const MAGIC: [u8; 4] = *b"SEMA";
}

impl FileContent for Contract {
    const MAGIC: [u8; 4] = *b"CONT";
}

impl FileContent for Transfer {
    const MAGIC: [u8; 4] = *b"TRFR";
}

impl FileContent for Iface {
    const MAGIC: [u8; 4] = *b"IFCE";
}

impl FileContent for IfaceImpl {
    const MAGIC: [u8; 4] = *b"IMPL";
}

impl FileContent for ContractSuppl {
    const MAGIC: [u8; 4] = *b"SUPL";
}

#[derive(Clone, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
pub enum UniversalFile {
    #[from]
    #[cfg_attr(feature = "serde", serde(rename = "interface"))]
    Iface(Iface),

    #[from]
    Schema(SubSchema),

    #[from]
    #[cfg_attr(feature = "serde", serde(rename = "implementation"))]
    Impl(IfaceImpl),

    #[from]
    Contract(Contract),

    #[from]
    Transfer(Transfer),

    #[from]
    #[cfg_attr(feature = "serde", serde(rename = "supplement"))]
    Suppl(ContractSuppl),
}

impl UniversalFile {
    pub fn load(mut data: impl Read) -> Result<Self, LoadError> {
        let mut rgb = [0u8; 4];
        let mut magic = [0u8; 4];
        data.read_exact(&mut rgb)?;
        data.read_exact(&mut magic)?;
        if rgb != RGB_PREFIX {
            return Err(LoadError::InvalidMagic);
        }
        let mut reader = StreamReader::new::<FILE_MAX_LEN>(data);
        Ok(match magic {
            x if x == Iface::MAGIC => Iface::strict_read(&mut reader)?.into(),
            x if x == SubSchema::MAGIC => SubSchema::strict_read(&mut reader)?.into(),
            x if x == IfaceImpl::MAGIC => IfaceImpl::strict_read(&mut reader)?.into(),
            x if x == Contract::MAGIC => Contract::strict_read(&mut reader)?.into(),
            x if x == Transfer::MAGIC => Transfer::strict_read(&mut reader)?.into(),
            x if x == ContractSuppl::MAGIC => ContractSuppl::strict_read(&mut reader)?.into(),
            _ => return Err(LoadError::InvalidMagic),
        })
    }

    pub fn save(&self, mut writer: impl Write) -> Result<(), io::Error> {
        writer.write_all(&RGB_PREFIX)?;
        let magic = match self {
            UniversalFile::Iface(_) => Iface::MAGIC,
            UniversalFile::Schema(_) => SubSchema::MAGIC,
            UniversalFile::Impl(_) => IfaceImpl::MAGIC,
            UniversalFile::Contract(_) => Contract::MAGIC,
            UniversalFile::Transfer(_) => Transfer::MAGIC,
            UniversalFile::Suppl(_) => ContractSuppl::MAGIC,
        };
        writer.write_all(&magic)?;

        let writer = StreamWriter::new::<FILE_MAX_LEN>(writer);

        match self {
            UniversalFile::Iface(content) => content.strict_write(writer),
            UniversalFile::Schema(content) => content.strict_write(writer),
            UniversalFile::Impl(content) => content.strict_write(writer),
            UniversalFile::Contract(content) => content.strict_write(writer),
            UniversalFile::Transfer(content) => content.strict_write(writer),
            UniversalFile::Suppl(content) => content.strict_write(writer),
        }
    }

    #[cfg(feature = "fs")]
    pub fn load_file(path: impl AsRef<std::path::Path>) -> Result<Self, LoadError> {
        let file = std::fs::File::open(path)?;
        Self::load(file)
    }

    #[cfg(feature = "fs")]
    pub fn save_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), io::Error> {
        let file = std::fs::File::create(path)?;
        self.save(file)
    }
}
