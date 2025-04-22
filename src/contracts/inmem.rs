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
use core::borrow::Borrow;
use core::error::Error as StdError;
use std::collections::HashMap;
use std::io;

use amplify::confinement::SmallOrdMap;
use hypersonic::{
    AcceptError, AuthToken, CallParams, CodexId, ContractId, ContractName, Opid, Schema,
};
use rgb::RgbSeal;
use strict_encoding::{
    ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter, WriteRaw,
};

use crate::{
    Articles, ConsumeError, Contract, ContractInfo, ContractRef, ContractState, ContractsApi,
    CreateParams, IssueError, Operation, Pile, Stockpile, WitnessStatus,
};

/// Collection of RGB smart contracts and contract issuers, which keeps all of them in memory.
pub struct ContractsInmem<Sp: Stockpile> {
    schemata: HashMap<CodexId, Schema>,
    contracts: HashMap<ContractId, Contract<Sp::Stock, Sp::Pile>>,
    persistence: Sp,
}

impl<Sp: Stockpile> ContractsInmem<Sp> {
    pub fn load(persistence: Sp) -> Self {
        // TODO: Do not pre-load everything but append lazily

        let schemata = persistence
            .issuer_ids()
            .filter_map(|id| persistence.issuer(id).map(|schema| (id, schema)))
            .collect();
        let contracts = persistence
            .contract_ids()
            .filter_map(|id| persistence.contract(id).map(|contract| (id, contract)))
            .collect();

        Self { schemata, contracts, persistence }
    }

    fn contract_mut(&mut self, id: ContractId) -> &mut Contract<Sp::Stock, Sp::Pile> {
        self.contracts.get_mut(&id).expect("contract not found")
    }
}

impl<Sp: Stockpile> ContractsApi<Sp::Stock, Sp::Pile> for ContractsInmem<Sp> {
    fn codex_ids(&self) -> impl Iterator<Item = CodexId> { self.schemata.keys().copied() }

    fn schemata_count(&self) -> usize { self.schemata.len() }

    fn schemata(&self) -> impl Iterator<Item = (CodexId, &Schema)> {
        self.schemata.iter().map(|(id, schema)| (*id, schema))
    }

    fn schema(&self, codex_id: CodexId) -> Option<&Schema> { self.schemata.get(&codex_id) }

    fn contracts_count(&self) -> usize { self.contracts.len() }

    fn contract_ids(&self) -> impl Iterator<Item = ContractId> { self.contracts.keys().copied() }

    fn contracts_info(&self) -> impl Iterator<Item = ContractInfo> {
        self.contracts
            .iter()
            .map(|(id, contract)| ContractInfo::new(*id, contract.articles()))
    }

    fn contract_state(&self, id: ContractId) -> ContractState<<Sp::Pile as Pile>::Seal> {
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

    fn witness_ids(
        &self,
    ) -> impl Iterator<Item = <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId> {
        self.contracts
            .values()
            .flat_map(|contract| contract.witness_ids())
    }

    fn import(&mut self, schema: Schema) -> Result<CodexId, impl StdError> {
        let codex_id = schema.codex.codex_id();
        let schema = match self.persistence.import(schema) {
            Ok(schema) => schema,
            Err(err) => return Err(err),
        };
        self.schemata.insert(codex_id, schema);
        Ok(codex_id)
    }

    fn issue(
        &mut self,
        params: CreateParams<<<Sp::Pile as Pile>::Seal as RgbSeal>::Definiton>,
    ) -> Result<ContractId, IssueError<impl StdError>> {
        let contract = self.persistence.issue(params)?;
        let id = contract.contract_id();
        self.contracts.insert(id, contract);
        Ok(id)
    }

    fn contract_call(
        &mut self,
        contract_id: ContractId,
        call: CallParams,
        seals: SmallOrdMap<u16, <<Sp::Pile as Pile>::Seal as RgbSeal>::Definiton>,
    ) -> Result<Operation, AcceptError> {
        let contract = self.contract_mut(contract_id);
        contract.call(call, seals)
    }

    fn sync(
        &mut self,
        changed: impl IntoIterator<
            Item = (<<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId, WitnessStatus),
        >,
    ) -> Result<(), AcceptError> {
        for (id, status) in changed {
            for contract in self.contracts.values_mut() {
                contract.sync(id, status)?;
            }
        }
        Ok(())
    }

    fn include(
        &mut self,
        contract_id: ContractId,
        opid: Opid,
        pub_witness: &<<Sp::Pile as Pile>::Seal as RgbSeal>::Published,
        anchor: <<Sp::Pile as Pile>::Seal as RgbSeal>::Client,
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
        <<Sp::Pile as Pile>::Seal as RgbSeal>::Client: StrictDumb + StrictEncode,
        <<Sp::Pile as Pile>::Seal as RgbSeal>::Published: StrictDumb + StrictEncode,
        <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId: StrictEncode,
    {
        self.contract_mut(contract_id).consign(terminals, writer)
    }

    fn consume(
        &mut self,
        contract_id: ContractId,
        reader: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(
            &Operation,
        )
            -> BTreeMap<u16, <<Sp::Pile as Pile>::Seal as RgbSeal>::Definiton>,
    ) -> Result<(), ConsumeError<<<Sp::Pile as Pile>::Seal as RgbSeal>::Definiton>>
    where
        <<Sp::Pile as Pile>::Seal as RgbSeal>::Client: StrictDecode,
        <<Sp::Pile as Pile>::Seal as RgbSeal>::Published: StrictDecode,
        <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId: StrictDecode,
    {
        self.contract_mut(contract_id)
            .consume(reader, seal_resolver)
    }
}
