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
use std::io::{self, Read, Write};

use amplify::confinement::U32 as FILE_MAX_LEN;
use armor::{AsciiArmor, StrictArmor};
use strict_encoding::{StreamReader, StreamWriter, StrictDecode, StrictEncode};

use crate::containers::{Contract, Kit, Transfer};

const RGB_PREFIX: [u8; 4] = *b"RGB\x00";
const MAGIC_LEN: usize = 3;

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
    const MAGIC: [u8; MAGIC_LEN];

    fn load(mut data: impl Read) -> Result<Self, LoadError> {
        let mut rgb = [0u8; 4];
        let mut magic = [0u8; MAGIC_LEN];
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

impl FileContent for Kit {
    const MAGIC: [u8; MAGIC_LEN] = *b"KIT";
}

impl FileContent for Contract {
    const MAGIC: [u8; MAGIC_LEN] = *b"CON";
}

impl FileContent for Transfer {
    const MAGIC: [u8; MAGIC_LEN] = *b"TFR";
}

// TODO: Add disclosure
// TODO: Add batch and fascia

#[derive(Clone, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
pub enum UniversalFile {
    #[from]
    Kit(Kit),

    #[from]
    Contract(Contract),

    #[from]
    Transfer(Transfer),
    // TODO: Add disclosure
    // TODO: Add batch and fascia
}

impl UniversalFile {
    pub fn load(mut data: impl Read) -> Result<Self, LoadError> {
        let mut rgb = [0u8; 4];
        let mut magic = [0u8; MAGIC_LEN];
        data.read_exact(&mut rgb)?;
        data.read_exact(&mut magic)?;
        if rgb != RGB_PREFIX {
            return Err(LoadError::InvalidMagic);
        }
        let mut reader = StreamReader::new::<FILE_MAX_LEN>(data);
        Ok(match magic {
            x if x == Kit::MAGIC => Kit::strict_read(&mut reader)?.into(),
            x if x == Contract::MAGIC => Contract::strict_read(&mut reader)?.into(),
            x if x == Transfer::MAGIC => Transfer::strict_read(&mut reader)?.into(),
            _ => return Err(LoadError::InvalidMagic),
        })
    }

    pub fn save(&self, mut writer: impl Write) -> Result<(), io::Error> {
        writer.write_all(&RGB_PREFIX)?;
        let magic = match self {
            UniversalFile::Kit(_) => Kit::MAGIC,
            UniversalFile::Contract(_) => Contract::MAGIC,
            UniversalFile::Transfer(_) => Transfer::MAGIC,
        };
        writer.write_all(&magic)?;

        let writer = StreamWriter::new::<FILE_MAX_LEN>(writer);

        match self {
            UniversalFile::Kit(content) => content.strict_write(writer),
            UniversalFile::Contract(content) => content.strict_write(writer),
            UniversalFile::Transfer(content) => content.strict_write(writer),
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

impl Display for UniversalFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            UniversalFile::Kit(content) => Display::fmt(&content.display_ascii_armored(), f),
            UniversalFile::Contract(content) => Display::fmt(&content.display_ascii_armored(), f),
            UniversalFile::Transfer(content) => Display::fmt(&content.display_ascii_armored(), f),
        }
    }
}
