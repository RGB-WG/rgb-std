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
use std::collections::{BTreeMap, HashMap};
use std::io;

use amplify::confinement::SmallOrdMap;
use hypersonic::{
    AcceptError, AuthToken, CallParams, CodexId, ContractId, ContractName, Opid, Schema, Stock,
};
use rgb::{ContractApi, RgbSeal};
use strict_encoding::{
    ReadRaw, SerializeError, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter,
    WriteRaw,
};

use crate::{
    Articles, Consensus, ConsumeError, Contract, ContractInfo, ContractRef, ContractState,
    ContractsApi, CreateParams, IssueError, Operation, Pile, Witness, WitnessStatus,
};

/// In-memory collection of RGB smart contracts and contract issuers.
#[derive(Getters)]
pub struct ContractsInmem<S: Stock, P: Pile> {
    #[getter(as_copy)]
    consensus: Consensus,
    #[getter(as_copy)]
    testnet: bool,
    schemata: HashMap<CodexId, Schema>,
    contracts: HashMap<ContractId, Contract<S, P>>,
}

impl<S: Stock, P: Pile> ContractsInmem<S, P> {
    pub fn new_bitcoin_testnet() -> Self {
        Self {
            testnet: true,
            consensus: Consensus::Bitcoin,
            schemata: HashMap::new(),
            contracts: HashMap::new(),
        }
    }

    pub fn new_testnet(consensus: Consensus) -> Self {
        Self {
            testnet: true,
            consensus,
            schemata: HashMap::new(),
            contracts: HashMap::new(),
        }
    }

    /// Adds contracts and corresponding schemata from an iterator, ignoring known ones.
    ///
    /// # Panics
    ///
    /// If any of the added contracts network or consensus doesn't match the ones set for the
    /// structure.
    pub fn add_contracts(&mut self, contracts: impl IntoIterator<Item = Contract<S, P>>) {
        for contract in contracts {
            let articles = contract.articles();
            if articles.issue.meta.testnet != self.testnet
                || articles.issue.meta.consensus != self.consensus
            {
                panic!("contract {} network doesn't match", contract.contract_id());
            }
            let codex_id = contract.codex().codex_id();
            if !self.schemata.contains_key(&codex_id) {
                self.schemata.insert(codex_id, articles.schema.clone());
            }
            let contract_id = contract.contract_id();
            if !self.contracts.contains_key(&contract_id) {
                self.contracts.insert(contract_id, contract);
            }
        }
    }

    pub fn add_schemata(&mut self, schemata: impl IntoIterator<Item = Schema>) {
        self.schemata.extend(
            schemata
                .into_iter()
                .map(|schema| (schema.codex.codex_id(), schema)),
        );
    }

    fn contract_mut(&mut self, id: ContractId) -> &mut Contract<S, P> {
        self.contracts.get_mut(&id).expect("contract not found")
    }
}

impl<S: Stock, P: Pile> ContractsApi<S, P> for ContractsInmem<S, P> {
    fn codex_ids(&self) -> impl Iterator<Item = CodexId> { self.schemata.keys().copied() }

    fn schemata(&self) -> impl Iterator<Item = (CodexId, &Schema)> {
        self.schemata.iter().map(|(id, schema)| (*id, schema))
    }

    fn schema(&self, codex_id: CodexId) -> Option<&Schema> { self.schemata.get(&codex_id) }

    fn contract_ids(&self) -> impl Iterator<Item = ContractId> { self.contracts.keys().copied() }

    fn contracts_info(&self) -> impl Iterator<Item = ContractInfo> {
        self.contracts
            .iter()
            .map(|(id, contract)| ContractInfo::new(*id, contract.articles()))
    }

    fn contract_state(&self, id: ContractId) -> ContractState<P::Seal> {
        self.contracts[&id].state()
    }

    fn contract_articles(&self, id: ContractId) -> &Articles { self.contracts[&id].articles() }

    fn has_contract(&self, id: ContractId) -> bool { self.contracts.contains_key(&id) }

    fn find_contract_id(&self, r: impl Into<ContractRef>) -> Option<ContractId> {
        match r.into() {
            ContractRef::Id(id) if self.has_contract(id) => Some(id),
            ContractRef::Id(_) => None,
            ContractRef::Name(name) => {
                let name = ContractName::Named(name);
                self.contracts
                    .iter()
                    .find(|(_, contract)| contract.articles().issue.meta.name == name)
                    .map(|(id, _)| *id)
            }
        }
    }

    fn witnesses(&self, id: ContractId) -> impl Iterator<Item = Witness<P::Seal>> {
        self.contracts[&id].witnesses()
    }

    fn issue(
        &mut self,
        params: CreateParams<<P::Seal as RgbSeal>::Definiton>,
        stock_conf: S::Conf,
        pile_conf: P::Conf,
    ) -> Result<ContractId, IssueError<S::Error>>
    where
        S::Error: From<P::Error>,
    {
        if params.consensus != self.consensus {
            return Err(IssueError::ConsensusMismatch);
        }
        if params.testnet != self.testnet {
            return Err(if params.testnet {
                IssueError::TestnetMismatch
            } else {
                IssueError::MainnetMismatch
            });
        }
        let schema = self
            .schema(params.codex_id)
            .ok_or(IssueError::UnknownCodex(params.codex_id))?;
        let contract = Contract::issue(schema.clone(), params, stock_conf, pile_conf)?;
        let id = contract.contract_id();
        self.contracts.insert(id, contract);
        Ok(id)
    }

    fn contract_call(
        &mut self,
        contract_id: ContractId,
        call: CallParams,
        seals: SmallOrdMap<u16, <P::Seal as RgbSeal>::Definiton>,
    ) -> Result<Operation, AcceptError> {
        let contract = self.contract_mut(contract_id);
        contract.call(call, seals)
    }

    fn update_witness_status(
        &mut self,
        contract_id: ContractId,
        wid: <P::Seal as RgbSeal>::WitnessId,
        status: WitnessStatus,
    ) -> Result<(), AcceptError> {
        self.contract_mut(contract_id)
            .update_witness_status(wid, status)
    }

    fn rollback(
        &mut self,
        contract_id: ContractId,
        opids: impl IntoIterator<Item = Opid>,
    ) -> Result<(), SerializeError> {
        self.contract_mut(contract_id).rollback(opids)
    }

    fn forward(
        &mut self,
        contract_id: ContractId,
        opids: impl IntoIterator<Item = Opid>,
    ) -> Result<(), AcceptError> {
        self.contract_mut(contract_id).forward(opids)
    }

    fn include(
        &mut self,
        contract_id: ContractId,
        opid: Opid,
        pub_witness: &<P::Seal as RgbSeal>::Published,
        anchor: <P::Seal as RgbSeal>::Client,
    ) {
        self.contract_mut(contract_id)
            .include(opid, anchor, pub_witness)
    }

    fn consign(
        &mut self,
        contract_id: ContractId,
        terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        writer: StrictWriter<impl WriteRaw>,
    ) -> io::Result<()>
    where
        <P::Seal as RgbSeal>::Client: StrictDumb + StrictEncode,
        <P::Seal as RgbSeal>::Published: StrictDumb + StrictEncode,
        <P::Seal as RgbSeal>::WitnessId: StrictEncode,
    {
        self.contract_mut(contract_id).consign(terminals, writer)
    }

    fn consume(
        &mut self,
        contract_id: ContractId,
        reader: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(&Operation) -> BTreeMap<u16, <P::Seal as RgbSeal>::Definiton>,
    ) -> Result<(), ConsumeError<<P::Seal as RgbSeal>::Definiton>>
    where
        <P::Seal as RgbSeal>::Client: StrictDecode,
        <P::Seal as RgbSeal>::Published: StrictDecode,
        <P::Seal as RgbSeal>::WitnessId: StrictDecode,
    {
        self.contract_mut(contract_id)
            .consume(reader, seal_resolver)
    }
}

#[cfg(feature = "fs")]
pub mod file {
    use std::ffi::OsStr;
    use std::fs;
    use std::fs::{File, FileType};
    use std::marker::PhantomData;
    use std::path::{Path, PathBuf};

    use hypersonic::persistance::StockFs;
    use strict_encoding::{StreamWriter, StrictDecode, StrictEncode};

    use super::*;
    use crate::PileFs;

    struct DirExcavator<Seal: RgbSeal> {
        dir: PathBuf,
        consensus: Consensus,
        testnet: bool,
        no_prefix: bool,
        _phantom: PhantomData<Seal>,
    }

    impl<Seal: RgbSeal> DirExcavator<Seal> {
        pub fn new(consensus: Consensus, testnet: bool, dir: PathBuf, no_prefix: bool) -> Self {
            Self { dir, consensus, testnet, no_prefix, _phantom: PhantomData }
        }

        fn consensus_dir(&self) -> PathBuf {
            if self.no_prefix {
                return self.dir.to_owned();
            }
            let mut dir = self.dir.join(self.consensus.to_string());
            if self.testnet {
                dir.set_extension("testnet");
            }
            dir
        }

        fn contents(&self, top: bool) -> impl Iterator<Item = (FileType, PathBuf)> {
            let dir =
                if top { fs::read_dir(&self.dir) } else { fs::read_dir(self.consensus_dir()) };
            dir.unwrap_or_else(|_| panic!("unable to read directory `{}`", self.dir.display()))
                .map(|entry| {
                    let entry = entry.expect("unable to read directory");
                    let ty = entry.file_type().expect("unable to read file type");
                    (ty, entry.path())
                })
        }
    }

    impl<Seal: RgbSeal> DirExcavator<Seal>
    where
        Seal::Client: StrictEncode + StrictDecode,
        Seal::Published: Eq + StrictEncode + StrictDecode,
        Seal::WitnessId: Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        pub fn schemata(&self) -> impl Iterator<Item = Schema> {
            self.contents(true).filter_map(|(ty, path)| {
                if ty.is_file() && path.extension().and_then(OsStr::to_str) == Some("issuer") {
                    Schema::load(path).ok()
                } else {
                    None
                }
            })
        }

        pub fn contracts(
            &self,
        ) -> impl Iterator<Item = Contract<StockFs, PileFs<Seal>>> + use<'_, Seal> {
            self.contents(false).filter_map(|(ty, path)| {
                if ty.is_dir() && path.extension().and_then(OsStr::to_str) == Some("contract") {
                    let contract = Contract::load(path.clone(), path.clone())
                        .inspect_err(|err| {
                            eprintln!("Unable to read contract in '{}': {err}", path.display());
                        })
                        .ok()?;
                    let meta = &contract.articles().issue.meta;
                    if meta.consensus == self.consensus && meta.testnet == self.testnet {
                        return Some(contract);
                    }
                }
                None
            })
        }
    }

    impl<Seal: RgbSeal> ContractsInmem<StockFs, PileFs<Seal>>
    where
        Seal::Client: StrictEncode + StrictDecode,
        Seal::Published: Eq + StrictEncode + StrictDecode,
        Seal::WitnessId: Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        fn excavator(&self, path: PathBuf, no_prefix: bool) -> DirExcavator<Seal> {
            DirExcavator::new(self.consensus, self.testnet, path, no_prefix)
        }

        pub fn with_testnet_dir(consensus: Consensus, path: PathBuf, no_prefix: bool) -> Self {
            let mut me = Self::new_testnet(consensus);
            let excavator = me.excavator(path, no_prefix);
            me.add_contracts(excavator.contracts());
            me.add_schemata(excavator.schemata());
            me
        }

        pub fn issue_to_dir(
            &mut self,
            mut path: PathBuf,
            params: CreateParams<Seal::Definiton>,
        ) -> Result<ContractId, IssueError<io::Error>> {
            path.push(params.name.as_str());
            path.set_extension("contract");
            self.issue(params, path.clone(), path)
        }

        pub fn consign_to_file(
            &mut self,
            contract_id: ContractId,
            terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
            path: impl AsRef<Path>,
        ) -> io::Result<()>
        where
            Seal::Client: StrictDumb,
            Seal::Published: StrictDumb,
            Seal::WitnessId: StrictEncode,
        {
            let file = File::create_new(path)?;
            let writer = StrictWriter::with(StreamWriter::new::<{ usize::MAX }>(file));
            self.consign(contract_id, terminals, writer)
        }
    }
}
