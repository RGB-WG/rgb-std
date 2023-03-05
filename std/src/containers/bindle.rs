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

use amplify::confinement::TinyVec;
use baid58::{Baid58, ToBaid58};
use rgb::{Schema, SchemaRoot};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::containers::{Cert, Contract, Transfer};
use crate::interface::{Iface, IfaceImpl};

// TODO: Move to UBIDECO crate
pub trait Bindle: StrictSerialize + StrictDeserialize {
    /// Magic bytes used in saving/restoring container from a file.
    const MAGIC: [u8; 4];
    /// String used in ASCII armored blocks
    const PLATE_TITLE: &'static str;
    fn baid58(&self) -> Baid58<32>;
}

impl<Root: SchemaRoot> Bindle for Schema<Root> {
    const MAGIC: [u8; 4] = *b"SCHM";
    const PLATE_TITLE: &'static str = "RGB SCHEMA";
    fn baid58(&self) -> Baid58<32> { self.schema_id().to_baid58() }
}

impl Bindle for Contract {
    const MAGIC: [u8; 4] = *b"CNRC";
    const PLATE_TITLE: &'static str = "RGB CONTRACT";
    fn baid58(&self) -> Baid58<32> { self.contract_id().to_baid58() }
}

impl Bindle for Transfer {
    const MAGIC: [u8; 4] = *b"TRNS";
    const PLATE_TITLE: &'static str = "RGB STATE TRANSFER";
    fn baid58(&self) -> Baid58<32> { self.transfer_id().to_baid58() }
}

impl Bindle for Iface {
    const MAGIC: [u8; 4] = *b"IFCE";
    const PLATE_TITLE: &'static str = "RGB INTERFACE";
    fn baid58(&self) -> Baid58<32> { self.iface_id().to_baid58() }
}

impl Bindle for IfaceImpl {
    const MAGIC: [u8; 4] = *b"IMPL";
    const PLATE_TITLE: &'static str = "RGB INTERFACE IMPLEMENTATION";
    fn baid58(&self) -> Baid58<32> { self.impl_id().to_baid58() }
}

#[derive(Debug)]
pub struct BindleWrap<C: Bindle> {
    id: Baid58<32>,
    data: C,
    sigs: TinyVec<Cert>,
}

impl<C: Bindle> BindleWrap<C> {
    pub fn new(data: C) -> Self {
        BindleWrap {
            id: data.baid58(),
            data,
            sigs: empty!(),
        }
    }
}

impl<C: Bindle> core::fmt::Display for BindleWrap<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use base64::Engine;

        writeln!(f, "----- BEGIN {} -----", C::PLATE_TITLE)?;
        writeln!(f, "Id: {}", self.id)?;
        writeln!(f, "Checksum: {}", self.id)?;
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

mod _fs {
    use std::path::Path;

    use super::*;

    impl<C: Bindle> BindleWrap<C> {
        pub fn save(&self, _path: impl AsRef<Path>) { todo!() }
    }
}
