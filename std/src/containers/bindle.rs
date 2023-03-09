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

use std::fmt::Display;

#[cfg(feature = "fs")]
pub use _fs::*;
use amplify::confinement::TinyVec;
use baid58::ToBaid58;
use rgb::{ContractId, Schema, SchemaId, SchemaRoot};
use strict_encoding::{
    StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, StrictType,
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

    type Id: ToBaid58<32> + Display + StrictType + StrictDumb + StrictEncode + StrictDecode;

    fn bindle_id(&self) -> Self::Id;
    fn bindle(self) -> Bindle<Self> { Bindle::new(self) }
}

impl<Root: SchemaRoot> BindleContent for Schema<Root> {
    const MAGIC: [u8; 4] = *b"SCHM";
    const PLATE_TITLE: &'static str = "RGB SCHEMA";
    type Id = SchemaId;
    fn bindle_id(&self) -> Self::Id { self.schema_id() }
}

impl BindleContent for Contract {
    const MAGIC: [u8; 4] = *b"CNRC";
    const PLATE_TITLE: &'static str = "RGB CONTRACT";
    type Id = ContractId;
    fn bindle_id(&self) -> Self::Id { self.contract_id() }
}

impl BindleContent for Transfer {
    const MAGIC: [u8; 4] = *b"TRNS";
    const PLATE_TITLE: &'static str = "RGB STATE TRANSFER";
    type Id = TransferId;
    fn bindle_id(&self) -> Self::Id { self.transfer_id() }
}

impl BindleContent for Iface {
    const MAGIC: [u8; 4] = *b"IFCE";
    const PLATE_TITLE: &'static str = "RGB INTERFACE";
    type Id = IfaceId;
    fn bindle_id(&self) -> Self::Id { self.iface_id() }
}

impl BindleContent for IfaceImpl {
    const MAGIC: [u8; 4] = *b"IMPL";
    const PLATE_TITLE: &'static str = "RGB INTERFACE IMPLEMENTATION";
    type Id = ImplId;
    fn bindle_id(&self) -> Self::Id { self.impl_id() }
}

#[derive(Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct Bindle<C: BindleContent> {
    id: C::Id,
    data: C,
    sigs: TinyVec<Cert>,
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

    pub fn into_split(self) -> (C, TinyVec<Cert>) { (self.data, self.sigs) }
    pub fn unbindle(self) -> C { self.data }
}

impl<C: BindleContent> Display for Bindle<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use base64::Engine;

        writeln!(f, "----- BEGIN {} -----", C::PLATE_TITLE)?;
        writeln!(f, "Id: {}", self.id)?;
        writeln!(f, "Checksum: {}", self.id.to_baid58().mnemonic())?;
        for cert in &self.sigs {
            writeln!(f, "Signed-By: {}", cert.signer)?;
        }
        writeln!(f)?;

        // TODO: Replace with streamed writer
        let data = self
            .data
            .to_strict_serialized::<0xFFFFFF>()
            .expect("in-memory");
        let engine = base64::engine::general_purpose::STANDARD;
        let data = engine.encode(data);
        let mut data = data.as_str();
        while data.len() >= 76 {
            let (line, rest) = data.split_at(76);
            writeln!(f, "{}", line)?;
            data = rest;
        }
        writeln!(f, "{}", data)?;

        writeln!(f, "\n----- END {} -----", C::PLATE_TITLE)?;
        Ok(())
    }
}

#[cfg(feature = "fs")]
mod _fs {
    use std::io::{Read, Write};
    use std::path::Path;
    use std::{fs, io};

    use rgb::SubSchema;
    use strict_encoding::{DecodeError, StrictEncode, StrictReader, StrictWriter};

    use super::*;

    #[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
    #[display(doc_comments)]
    pub enum LoadError {
        /// invalid file data.
        InvalidMagic,

        #[display(inner)]
        #[from]
        #[from(io::Error)]
        Decode(DecodeError),
    }

    #[derive(Debug, From)]
    pub enum UniversalBindle {
        #[from]
        Iface(Bindle<Iface>),

        #[from]
        Schema(Bindle<SubSchema>),

        #[from]
        Impl(Bindle<IfaceImpl>),

        #[from]
        Contract(Bindle<Contract>),

        #[from]
        Transfer(Bindle<Transfer>),
    }

    impl<C: BindleContent> Bindle<C> {
        pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadError> {
            let mut rgb = [0u8; 3];
            let mut magic = [0u8; 4];
            let mut file = fs::File::open(path)?;
            file.read_exact(&mut rgb)?;
            file.read_exact(&mut magic)?;
            if rgb != *b"RGB" || magic != C::MAGIC {
                return Err(LoadError::InvalidMagic);
            }
            let mut reader = StrictReader::with(usize::MAX, file);
            let me = Self::strict_decode(&mut reader)?;
            Ok(me)
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
        pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadError> {
            let mut rgb = [0u8; 3];
            let mut magic = [0u8; 4];
            let mut file = fs::File::open(path)?;
            file.read_exact(&mut rgb)?;
            file.read_exact(&mut magic)?;
            if rgb != *b"RGB" {
                return Err(LoadError::InvalidMagic);
            }
            let mut reader = StrictReader::with(usize::MAX, file);
            Ok(match magic {
                x if x == Iface::MAGIC => Bindle::<Iface>::strict_decode(&mut reader)?.into(),
                x if x == SubSchema::MAGIC => {
                    Bindle::<SubSchema>::strict_decode(&mut reader)?.into()
                }
                x if x == IfaceImpl::MAGIC => {
                    Bindle::<IfaceImpl>::strict_decode(&mut reader)?.into()
                }
                x if x == Contract::MAGIC => Bindle::<Contract>::strict_decode(&mut reader)?.into(),
                x if x == Transfer::MAGIC => Bindle::<Transfer>::strict_decode(&mut reader)?.into(),
                _ => return Err(LoadError::InvalidMagic),
            })
        }
    }
}
