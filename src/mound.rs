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

use alloc::collections::BTreeMap;

use hypersonic::{CellAddr, CodexId, ContractId, IssueParams, Schema, Supply};

use crate::{Pile, Stockpile};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[repr(u32)]
pub enum SealType {
    #[cfg(feature = "bitcoin")]
    #[display("bitcoin.opret")]
    BitcoinOpret = crate::bitcoin::BITCOIN_OPRET,

    #[cfg(feature = "bitcoin")]
    #[display("bitcoin.tapret")]
    BitcoinTapret = crate::bitcoin::BITCOIN_TAPRET,

    #[cfg(feature = "liquid")]
    #[display("liquid.tapret")]
    LiquidTapret = crate::liquid::LIQUID_TAPRET,

    #[cfg(feature = "prime")]
    #[display("prime")]
    Prime = crate::prime::PRIME,
}

impl From<u32> for SealType {
    fn from(caps: u32) -> Self {
        match caps {
            #[cfg(feature = "bitcoin")]
            crate::bitcoin::BITCOIN_OPRET => Self::BitcoinOpret,
            #[cfg(feature = "bitcoin")]
            crate::bitcoin::BITCOIN_TAPRET => Self::BitcoinTapret,
            #[cfg(feature = "liquid")]
            crate::liquid::LIQUID_TAPRET => Self::LiquidTapret,
            #[cfg(feature = "prime")]
            crate::prime::PRIME => Self::Prime,
            unknown => panic!("unknown seal type {unknown:#10x}"),
        }
    }
}

pub struct Mound<S: Supply<CAPS>, P: Pile, X, const CAPS: u32> {
    schemata: BTreeMap<CodexId, Schema>,
    contracts: BTreeMap<ContractId, Stockpile<S, P, CAPS>>,
    persistence: X,
}

impl<S: Supply<CAPS>, P: Pile, X: Default, const CAPS: u32> Default for Mound<S, P, X, CAPS> {
    fn default() -> Self {
        Self {
            schemata: BTreeMap::new(),
            contracts: BTreeMap::new(),
            persistence: default!(),
        }
    }
}

impl<S: Supply<CAPS>, P: Pile, const CAPS: u32> Mound<S, P, (), CAPS> {
    pub fn new() -> Self {
        Self {
            schemata: BTreeMap::new(),
            contracts: BTreeMap::new(),
            persistence: (),
        }
    }
}

impl<S: Supply<CAPS>, P: Pile, X, const CAPS: u32> Mound<S, P, X, CAPS> {
    pub fn with(persistence: X) -> Self {
        Self {
            schemata: BTreeMap::new(),
            contracts: BTreeMap::new(),
            persistence,
        }
    }

    pub fn open(mut loader: impl Excavate<S, P, CAPS, Persistence = X>) -> Self {
        Self {
            schemata: loader.schemata().collect(),
            contracts: loader.contracts().collect(),
            persistence: loader.persistence(),
        }
    }

    pub fn issue(&mut self, schema: Schema, params: IssueParams, supply: S, pile: P) -> ContractId {
        let stockpile = Stockpile::issue(schema, params, supply, pile);
        let id = stockpile.contract_id();
        self.contracts.insert(id, stockpile);
        id
    }

    pub fn codex_ids(&self) -> impl Iterator<Item = CodexId> + use<'_, S, P, X, CAPS> {
        self.schemata.keys().copied()
    }

    pub fn schemata(&self) -> impl Iterator<Item = (CodexId, &Schema)> {
        self.schemata.iter().map(|(id, schema)| (*id, schema))
    }

    pub fn schema(&self, codex_id: CodexId) -> Option<&Schema> { self.schemata.get(&codex_id) }

    pub fn contract_ids(&self) -> impl Iterator<Item = ContractId> + use<'_, S, P, X, CAPS> {
        self.contracts.keys().copied()
    }

    pub fn contracts(&self) -> impl Iterator<Item = (ContractId, &Stockpile<S, P, CAPS>)> {
        self.contracts.iter().map(|(id, stock)| (*id, stock))
    }

    pub fn contracts_mut(
        &mut self,
    ) -> impl Iterator<Item = (ContractId, &mut Stockpile<S, P, CAPS>)> {
        self.contracts.iter_mut().map(|(id, stock)| (*id, stock))
    }

    pub fn contract(&self, id: ContractId) -> &Stockpile<S, P, CAPS> {
        self.contracts
            .get(&id)
            .unwrap_or_else(|| panic!("unknown contract {id}"))
    }

    pub fn contract_mut(&mut self, id: ContractId) -> &mut Stockpile<S, P, CAPS> {
        self.contracts
            .get_mut(&id)
            .unwrap_or_else(|| panic!("unknown contract {id}"))
    }

    pub fn select<'seal>(
        &self,
        seal: &'seal P::Seal,
    ) -> impl Iterator<Item = (ContractId, CellAddr)> + use<'_, 'seal, S, P, X, CAPS> {
        self.contracts
            .iter()
            .filter_map(|(id, stockpile)| stockpile.seal(seal).map(|addr| (*id, addr)))
    }
}

pub trait Excavate<S: Supply<CAPS>, P: Pile, const CAPS: u32> {
    type Persistence;
    fn persistence(&self) -> Self::Persistence;
    fn schemata(&mut self) -> impl Iterator<Item = (CodexId, Schema)>;
    fn contracts(&mut self) -> impl Iterator<Item = (ContractId, Stockpile<S, P, CAPS>)>;
}

pub mod file {
    use std::fs;
    use std::fs::FileType;
    use std::marker::PhantomData;
    use std::path::{Path, PathBuf};

    use hypersonic::FileSupply;
    use strict_encoding::{StrictDecode, StrictEncode};

    use super::*;
    use crate::pile::Protocol;
    use crate::FilePile;

    struct DirExcavator<Seal: Protocol, const CAPS: u32> {
        dir: PathBuf,
        _phantom: PhantomData<Seal>,
    }

    impl<Seal: Protocol, const CAPS: u32> DirExcavator<Seal, CAPS> {
        pub fn new(dir: PathBuf) -> Self {
            Self {
                dir,
                _phantom: PhantomData,
            }
        }

        fn contents(&mut self) -> impl Iterator<Item = (FileType, PathBuf)> {
            let seal = SealType::from(CAPS);
            let root = self.dir.join(seal.to_string());
            fs::read_dir(root)
                .expect("unable to read directory")
                .map(|entry| {
                    let entry = entry.expect("unable to read directory");
                    let ty = entry.file_type().expect("unable to read file type");
                    (ty, entry.path())
                })
        }
    }

    impl<Seal: Protocol, const CAPS: u32> Excavate<FileSupply, FilePile<Seal>, CAPS>
        for DirExcavator<Seal, CAPS>
    where
        Seal::CliWitness: StrictEncode + StrictDecode,
        Seal::PubWitness: StrictEncode + StrictDecode,
    {
        type Persistence = PathBuf;

        fn persistence(&self) -> Self::Persistence { self.dir.clone() }

        fn schemata(&mut self) -> impl Iterator<Item = (CodexId, Schema)> {
            self.contents().filter_map(|(ty, path)| {
                if ty.is_file() && path.ends_with(".schema") {
                    Schema::load(path)
                        .ok()
                        .map(|schema| (schema.codex.codex_id(), schema))
                } else {
                    None
                }
            })
        }

        fn contracts(
            &mut self,
        ) -> impl Iterator<Item = (ContractId, Stockpile<FileSupply, FilePile<Seal>, CAPS>)>
        {
            self.contents().filter_map(|(ty, path)| {
                if ty.is_file() && path.ends_with(".contract") {
                    let contract = Stockpile::load(path);
                    Some((contract.contract_id(), contract))
                } else {
                    None
                }
            })
        }
    }

    pub type FileMound<Seal: Protocol, const CAPS: u32> =
        Mound<FileSupply, FilePile<Seal>, PathBuf, CAPS>;

    impl<Seal: Protocol, const CAPS: u32> FileMound<Seal, CAPS>
    where
        Seal::CliWitness: StrictEncode + StrictDecode,
        Seal::PubWitness: StrictEncode + StrictDecode,
    {
        pub fn load(path: impl AsRef<Path>) -> Self {
            let path = path.as_ref();
            let excavator = DirExcavator::new(path.to_owned());
            Self::open(excavator)
        }

        pub fn issue_file(&mut self, schema: Schema, params: IssueParams) -> ContractId {
            let pile = FilePile::<Seal>::new(params.name.as_str(), &self.persistence);
            let supply = FileSupply::new(params.name.as_str(), &self.persistence);
            self.issue(schema, params, supply, pile)
        }

        pub fn path(&self) -> &Path { &self.persistence }
    }
}
