// Standard Library for RGB smart contracts
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use core::borrow::Borrow;
// TODO: Used in strict encoding; once solved there, remove here
use std::io;

use hypersonic::aora::Aora;
use hypersonic::{
    AcceptError, Articles, AuthToken, CellAddr, ContractId, IssueParams, Schema, Stock, Supply,
};
use single_use_seals::{PublishedWitness, SingleUseSeal};
use strict_encoding::{
    ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter, WriteRaw,
};

use crate::pile::Protocol;
use crate::Pile;

#[derive(Getters)]
pub struct Stockpile<S: Supply<CAPS>, P: Pile, const CAPS: u32> {
    #[getter(as_mut)]
    stock: Stock<S, CAPS>,
    #[getter(as_mut)]
    pile: P,
}

impl<S: Supply<CAPS>, P: Pile, const CAPS: u32> Stockpile<S, P, CAPS> {
    pub fn issue(schema: Schema, params: IssueParams, supply: S, pile: P) -> Self {
        let articles = schema.issue::<CAPS>(params);
        let stock = Stock::create(articles, supply);
        Self { stock, pile }
    }

    pub fn open(articles: Articles<CAPS>, supply: S, pile: P) -> Self {
        let stock = Stock::open(articles, supply);
        Self { stock, pile }
    }

    pub fn contract_id(&self) -> ContractId { self.stock.contract_id() }

    pub fn seal(&self, seal: &P::Seal) -> Option<CellAddr> {
        let auth = seal.auth_token();
        self.stock.state().raw.auth.get(&auth).copied()
    }

    pub fn append_witness(
        &mut self,
        published: &<P::Seal as SingleUseSeal>::PubWitness,
        client: &<P::Seal as SingleUseSeal>::CliWitness,
    ) where
        <<P::Seal as SingleUseSeal>::PubWitness as PublishedWitness<P::Seal>>::PubId:
            Into<[u8; 32]>,
    {
        let id = published.pub_id();
        self.pile.hoard_mut().append(id, client);
        self.pile.cache_mut().append(id, published);
    }

    pub fn consign(
        &mut self,
        terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        writer: StrictWriter<impl WriteRaw>,
    ) -> io::Result<()>
    where
        <P::Seal as SingleUseSeal>::CliWitness: StrictDumb + StrictEncode,
        <P::Seal as SingleUseSeal>::PubWitness: StrictDumb + StrictEncode,
        <<P::Seal as SingleUseSeal>::PubWitness as PublishedWitness<P::Seal>>::PubId: StrictEncode,
    {
        self.stock
            .export_aux(terminals, writer, |opid, mut writer| {
                let iter = self.pile.retrieve(opid);
                let len = iter.len();
                writer = (len as u64).strict_encode(writer)?;
                for (client, published) in iter {
                    writer = client.strict_encode(writer)?;
                    writer = published.strict_encode(writer)?;
                }
                Ok(writer)
            })
    }

    pub fn accept(&mut self, reader: &mut StrictReader<impl ReadRaw>) -> Result<(), AcceptError>
    where
        <P::Seal as SingleUseSeal>::CliWitness: StrictDecode,
        <P::Seal as SingleUseSeal>::PubWitness: StrictDecode,
        <<P::Seal as SingleUseSeal>::PubWitness as PublishedWitness<P::Seal>>::PubId: StrictDecode,
    {
        self.stock.accept_aux(reader, |opid, reader| {
            let len = u64::strict_decode(reader)?;
            for _ in 0..len {
                let client = <P::Seal as SingleUseSeal>::CliWitness::strict_decode(reader)?;
                let published = <P::Seal as SingleUseSeal>::PubWitness::strict_decode(reader)?;
                self.pile.append(opid, client, published);
            }
            Ok(())
        })
    }
}

#[cfg(feature = "fs")]
mod fs {
    use std::fs::File;
    use std::path::Path;

    use hypersonic::FileSupply;
    use strict_encoding::{StreamReader, StreamWriter, StrictDecode, StrictDumb, StrictEncode};

    use super::*;
    use crate::FilePile;

    impl<Seal: Protocol, const CAPS: u32> Stockpile<FileSupply, FilePile<Seal>, CAPS>
    where
        Seal::CliWitness: StrictEncode + StrictDecode,
        Seal::PubWitness: StrictEncode + StrictDecode,
        <Seal::PubWitness as PublishedWitness<Seal>>::PubId: Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        pub fn load(path: impl AsRef<Path>) -> Self {
            let path = path.as_ref();
            let pile = FilePile::open(path);
            let supply = FileSupply::open(path);
            Self::open(supply.load_articles(), supply, pile)
        }

        pub fn issue_file(schema: Schema, params: IssueParams, path: impl AsRef<Path>) -> Self {
            let path = path.as_ref();
            let pile = FilePile::new(params.name.as_str(), path);
            let supply = FileSupply::new(params.name.as_str(), path);
            Self::issue(schema, params, supply, pile)
        }

        pub fn consign_to_file(
            &mut self,
            terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
            path: impl AsRef<Path>,
        ) -> io::Result<()>
        where
            Seal::CliWitness: StrictDumb,
            Seal::PubWitness: StrictDumb,
            <Seal::PubWitness as PublishedWitness<Seal>>::PubId: StrictEncode,
        {
            let file = File::create_new(path)?;
            let writer = StrictWriter::with(StreamWriter::new::<{ usize::MAX }>(file));
            self.consign(terminals, writer)
        }

        pub fn accept_from_file(&mut self, path: impl AsRef<Path>) -> Result<(), AcceptError>
        where
            Seal::CliWitness: StrictDumb,
            Seal::PubWitness: StrictDumb,
            <Seal::PubWitness as PublishedWitness<Seal>>::PubId: StrictDecode,
        {
            let file = File::open(path)?;
            let mut reader = StrictReader::with(StreamReader::new::<{ usize::MAX }>(file));
            self.accept(&mut reader)
        }
    }
}
