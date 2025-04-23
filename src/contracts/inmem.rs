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
use core::cell::RefCell;
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
    schemata: RefCell<HashMap<CodexId, Schema>>,
    contracts: RefCell<HashMap<ContractId, Contract<Sp::Stock, Sp::Pile>>>,
    persistence: Sp,
}

impl<Sp: Stockpile> ContractsInmem<Sp> {
    pub fn load(persistence: Sp) -> Self {
        Self { schemata: none!(), contracts: none!(), persistence }
    }

    fn with_contract<R>(
        &self,
        id: ContractId,
        f: impl FnOnce(&Contract<Sp::Stock, Sp::Pile>) -> R,
        or: Option<R>,
    ) -> R {
        if let Some(contract) = self.contracts.borrow().get(&id) {
            f(contract)
        } else if let Some(contract) = self.persistence.contract(id) {
            let res = f(&contract);
            self.contracts.borrow_mut().insert(id, contract);
            res
        } else if let Some(or) = or {
            or
        } else {
            panic!("Contract {} not found", id)
        }
    }

    fn with_contract_mut<R>(
        &mut self,
        id: ContractId,
        f: impl FnOnce(&mut Contract<Sp::Stock, Sp::Pile>) -> R,
    ) -> R {
        if let Some(contract) = self.contracts.borrow_mut().get_mut(&id) {
            f(contract)
        } else if let Some(mut contract) = self.persistence.contract(id) {
            let res = f(&mut contract);
            self.contracts.borrow_mut().insert(id, contract);
            res
        } else {
            panic!("Contract {} not found", id)
        }
    }
}

impl<Sp: Stockpile> ContractsApi<Sp::Stock, Sp::Pile> for ContractsInmem<Sp> {
    fn codex_ids(&self) -> impl Iterator<Item = CodexId> { self.persistence.codex_ids() }

    fn issuers_count(&self) -> usize { self.persistence.issuers_count() }

    fn issuers(&self) -> impl Iterator<Item = (CodexId, Schema)> {
        self.persistence
            .codex_ids()
            .filter_map(|codex_id| self.issuer(codex_id).map(|schema| (codex_id, schema)))
    }

    fn issuer(&self, codex_id: CodexId) -> Option<Schema> {
        if let Some(issuer) = self.schemata.borrow().get(&codex_id) {
            return Some(issuer.clone());
        };
        let issuer = self.persistence.issuer(codex_id)?;
        self.schemata.borrow_mut().insert(codex_id, issuer);
        self.schemata.borrow().get(&codex_id).cloned()
    }

    fn contracts_count(&self) -> usize { self.persistence.contracts_count() }

    fn contract_ids(&self) -> impl Iterator<Item = ContractId> { self.persistence.contract_ids() }

    fn contracts_info(&self) -> impl Iterator<Item = ContractInfo> {
        self.contract_ids().filter_map(|id| {
            self.with_contract(
                id,
                |contract| Some(ContractInfo::new(id, contract.articles())),
                Some(None),
            )
        })
    }

    fn contract_state(&self, contract_id: ContractId) -> ContractState<<Sp::Pile as Pile>::Seal> {
        self.with_contract(contract_id, |contract| contract.state(), None)
    }

    fn contract_articles(&self, contract_id: ContractId) -> Articles {
        self.with_contract(contract_id, |contract| contract.articles().clone(), None)
    }

    fn has_contract(&self, contract_id: ContractId) -> bool {
        self.persistence.has_contract(contract_id)
    }

    fn find_contract_id(&self, r: impl Into<ContractRef>) -> Option<ContractId> {
        match r.into() {
            ContractRef::Id(id) if self.has_contract(id) => Some(id),
            ContractRef::Id(_) => None,
            ContractRef::Name(name) => {
                let name = ContractName::Named(name);
                if let Some(id) = self
                    .contracts
                    .borrow()
                    .iter()
                    .find(|(_, contract)| contract.articles().issue.meta.name == name)
                    .map(|(id, _)| *id)
                {
                    return Some(id);
                }
                self.persistence
                    .contract_ids()
                    .filter_map(|id| self.persistence.contract(id))
                    .find(|contract| contract.articles().issue.meta.name == name)
                    .map(|contract| contract.contract_id())
            }
        }
    }

    fn witness_ids(
        &self,
    ) -> impl Iterator<Item = <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId> {
        self.persistence.contract_ids().flat_map(move |id| {
            self.with_contract(
                id,
                |contract| contract.witness_ids().collect::<Vec<_>>(),
                Some(none!()),
            )
        })
    }

    fn import(&mut self, schema: Schema) -> Result<CodexId, impl StdError> {
        let codex_id = schema.codex.codex_id();
        let schema = match self.persistence.import(schema) {
            Ok(schema) => schema,
            Err(err) => return Err(err),
        };
        self.schemata.borrow_mut().insert(codex_id, schema);
        Ok(codex_id)
    }

    fn issue(
        &mut self,
        params: CreateParams<<<Sp::Pile as Pile>::Seal as RgbSeal>::Definiton>,
    ) -> Result<ContractId, IssueError<impl StdError>> {
        let contract = self.persistence.issue(params)?;
        let id = contract.contract_id();
        self.contracts.borrow_mut().insert(id, contract);
        Ok(id)
    }

    fn contract_call(
        &mut self,
        contract_id: ContractId,
        call: CallParams,
        seals: SmallOrdMap<u16, <<Sp::Pile as Pile>::Seal as RgbSeal>::Definiton>,
    ) -> Result<Operation, AcceptError> {
        self.with_contract_mut(contract_id, |contract| contract.call(call, seals))
    }

    fn sync(
        &mut self,
        changed: impl IntoIterator<
            Item = (<<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId, WitnessStatus),
        >,
    ) -> Result<(), AcceptError> {
        let contract_ids = self.persistence.contract_ids().collect::<Vec<_>>();
        for (id, status) in changed {
            for contract_id in &contract_ids {
                self.with_contract_mut(*contract_id, |contract| contract.sync(id, status))?;
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
        self.with_contract_mut(contract_id, |contract| contract.include(opid, anchor, pub_witness))
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
        self.with_contract_mut(contract_id, |contract| contract.consign(terminals, writer))
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
        self.with_contract_mut(contract_id, |contract| contract.consume(reader, seal_resolver))
    }
}
