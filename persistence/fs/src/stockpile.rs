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

use std::collections::HashMap;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, io};

use amplify::MultiError;
use rgb::{
    Articles, CodexId, Consensus, Consignment, ConsumeError, Contract, ContractId, CreateParams,
    Issuer, IssuerError, Pile, RgbSeal, Stock, Stockpile,
};
use sonic_persist_fs::{FsError, StockFs};
use strict_encoding::{StrictDecode, StrictEncode};

use crate::PileFs;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StockpileDir<Seal: RgbSeal> {
    consensus: Consensus,
    testnet: bool,
    dir: PathBuf,
    issuers: HashMap<CodexId, String>,
    contracts: HashMap<ContractId, String>,
    _phantom: PhantomData<Seal>,
}

impl<Seal: RgbSeal> StockpileDir<Seal> {
    pub fn load(dir: PathBuf, consensus: Consensus, testnet: bool) -> Result<Self, io::Error> {
        let mut issuers = HashMap::new();
        let mut contracts = HashMap::new();

        let readdir = fs::read_dir(&dir)?;
        for entry in readdir {
            let entry = entry?;
            let path = entry.path();
            let ty = entry.file_type()?;
            let Some(extension) = path.extension().and_then(OsStr::to_str) else {
                continue;
            };
            let Some(name) = path.file_stem().and_then(OsStr::to_str) else {
                continue;
            };
            let Some((name, id_str)) = name.split_once('.') else {
                continue;
            };
            if ty.is_file() && extension == "issuer" {
                let Ok(id) = CodexId::from_str(id_str) else {
                    continue;
                };
                issuers.insert(id, name.to_string());
            } else if ty.is_dir() && extension == "contract" {
                let Ok(id) = ContractId::from_str(id_str) else {
                    continue;
                };
                contracts.insert(id, name.to_string());
            }
        }

        Ok(Self {
            consensus,
            testnet,
            dir,
            issuers,
            contracts,
            _phantom: PhantomData,
        })
    }

    pub fn dir(&self) -> &Path { self.dir.as_path() }

    fn get_contract_dir(&self, contract_id: ContractId) -> Option<PathBuf> {
        let subdir = self.contracts.get(&contract_id)?;
        let path = self.dir.join(format!("{subdir}.{contract_id:-}.contract"));
        Some(path)
    }

    fn create_contract_dir(&self, articles: &Articles) -> io::Result<PathBuf> {
        let dir = self.dir.join(format!(
            "{}.{:-}.contract",
            articles.issue().meta.name,
            articles.contract_id()
        ));

        if fs::exists(&dir)? {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Contract already exists"));
        }
        fs::create_dir_all(&dir)?;

        Ok(dir)
    }
}

impl<Seal: RgbSeal> Stockpile for StockpileDir<Seal>
where
    Seal::Client: StrictEncode + StrictDecode,
    Seal::Published: Eq + StrictEncode + StrictDecode,
    Seal::WitnessId: From<[u8; 32]> + Into<[u8; 32]>,
{
    type Stock = StockFs;
    type Pile = PileFs<Seal>;
    type Error = io::Error;

    fn consensus(&self) -> Consensus { self.consensus }

    fn is_testnet(&self) -> bool { self.testnet }

    fn issuers_count(&self) -> usize { self.issuers.len() }

    fn contracts_count(&self) -> usize { self.contracts.len() }

    fn has_issuer(&self, codex_id: CodexId) -> bool { self.issuers.contains_key(&codex_id) }

    fn has_contract(&self, contract_id: ContractId) -> bool {
        self.contracts.contains_key(&contract_id)
    }

    fn codex_ids(&self) -> impl Iterator<Item = CodexId> { self.issuers.keys().copied() }

    fn contract_ids(&self) -> impl Iterator<Item = ContractId> { self.contracts.keys().copied() }

    fn issuer(&self, codex_id: CodexId) -> Option<Issuer> {
        let name = self.issuers.get(&codex_id)?;
        let path = self.dir.join(format!("{name}.{codex_id:#}.issuer"));
        // We trust the storage
        Issuer::load(path, |_, _, _| -> Result<_, Infallible> { Ok(()) }).ok()
    }

    fn contract(&self, contract_id: ContractId) -> Option<Contract<Self::Stock, Self::Pile>> {
        let path = self.get_contract_dir(contract_id)?;
        let contract = Contract::load(path.clone(), path).ok()?;
        let meta = &contract.articles().issue().meta;
        if meta.consensus != self.consensus || meta.testnet != self.testnet {
            return None;
        }
        Some(contract)
    }

    fn import_issuer(&mut self, issuer: Issuer) -> Result<Issuer, Self::Error> {
        let codex_id = issuer.codex_id();
        let name = issuer.codex().name.to_string();
        let path = self.dir.join(format!("{name}.{codex_id:#}.issuer"));
        issuer.save(path)?;
        self.issuers.insert(codex_id, name);
        Ok(issuer)
    }

    fn import_contract(
        &mut self,
        articles: Articles,
        consignment: Consignment<Seal>,
    ) -> Result<
        Contract<Self::Stock, Self::Pile>,
        MultiError<
            ConsumeError<Seal::Definition>,
            <Self::Stock as Stock>::Error,
            <Self::Pile as Pile>::Error,
        >,
    >
    where
        Seal::Client: StrictDecode,
        Seal::Published: StrictDecode,
        Seal::WitnessId: StrictDecode,
    {
        let dir = self.create_contract_dir(&articles).map_err(MultiError::C)?;
        let contract = Contract::with(articles, consignment, dir)?;
        self.contracts
            .insert(contract.contract_id(), contract.articles().issue().meta.name.to_string());
        Ok(contract)
    }

    fn issue(
        &mut self,
        params: CreateParams<<<Self::Pile as Pile>::Seal as RgbSeal>::Definition>,
    ) -> Result<Contract<Self::Stock, Self::Pile>, MultiError<IssuerError, FsError, io::Error>>
    {
        let schema = self
            .issuer(params.issuer.codex_id())
            .ok_or(MultiError::A(IssuerError::UnknownCodex(params.issuer.codex_id())))?;
        let contract =
            Contract::issue(schema, params, |articles| Ok(self.create_contract_dir(articles)?))
                .map_err(MultiError::from_other_a)?;
        self.contracts
            .insert(contract.contract_id(), contract.articles().issue().meta.name.to_string());
        Ok(contract)
    }

    fn purge(&mut self, contract_id: ContractId) -> Result<(), Self::Error> {
        let path = self
            .get_contract_dir(contract_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Contract not found"))?;
        fs::remove_dir_all(&path)
    }
}
