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

// TODO: Used in strict encoding; once solved there, remove here
use std::io;

use hypersonic::{Articles, AuthToken, CellAddr, ContractId, IssueParams, Schema, Stock, Supply};
use single_use_seals::SingleUseSeal;
use strict_encoding::{StrictWriter, WriteRaw};

use crate::pile::Protocol;
use crate::Pile;

pub struct Stockpile<S: Supply<CAPS>, P: Pile, const CAPS: u32> {
    stock: Stock<S, CAPS>,
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
        published: <P::Seal as SingleUseSeal>::PubWitness,
        client: <P::Seal as SingleUseSeal>::CliWitness,
    ) {
        todo!()
    }

    pub fn consign<'a>(
        &mut self,
        terminals: impl IntoIterator<Item = &'a AuthToken>,
        mut writer: StrictWriter<impl WriteRaw>,
    ) -> io::Result<()> {
        todo!()
    }
}

#[cfg(feature = "fs")]
mod fs {
    use std::path::Path;

    use hypersonic::FileSupply;
    use strict_encoding::{StrictDecode, StrictEncode};

    use super::*;
    use crate::FilePile;

    impl<Seal: Protocol, const CAPS: u32> Stockpile<FileSupply, FilePile<Seal>, CAPS>
    where
        Seal::CliWitness: StrictEncode + StrictDecode,
        Seal::PubWitness: StrictEncode + StrictDecode,
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
    }
}
