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

use amplify::confinement::{KeyedCollection, SmallOrdMap};
use hypersonic::{
    AcceptError, AuthToken, CallParams, CodexId, ContractId, ContractName, Opid, Schema,
};
use rgb::RgbSeal;
use strict_encoding::{
    ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter, WriteRaw,
};

use crate::{
    Articles, CallError, ConsumeError, Contract, ContractInfo, ContractRef, ContractState,
    CreateParams, Operation, Pile, Stockpile, WitnessStatus,
};

/// Collection of RGB smart contracts and contract issuers, which can be cached in memory.
///
/// # Generics
///
/// - `S` provides a specific cache implementation for an in-mem copy of issuers,
/// - `C` provides a specific cache implementation for an in-mem copy of contracts.
pub struct Contracts<
    Sp,
    S = HashMap<CodexId, Schema>,
    C = HashMap<ContractId, Contract<<Sp as Stockpile>::Stock, <Sp as Stockpile>::Pile>>,
> where
    Sp: Stockpile,
    S: KeyedCollection<Key = CodexId, Value = Schema>,
    C: KeyedCollection<Key = ContractId, Value = Contract<Sp::Stock, Sp::Pile>>,
{
    schemata: RefCell<S>,
    contracts: RefCell<C>,
    persistence: Sp,
}

impl<Sp, S, C> Contracts<Sp, S, C>
where
    Sp: Stockpile,
    S: KeyedCollection<Key = CodexId, Value = Schema>,
    C: KeyedCollection<Key = ContractId, Value = Contract<Sp::Stock, Sp::Pile>>,
{
    pub fn load(persistence: Sp) -> Self
    where
        S: Default,
        C: Default,
    {
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

impl<Sp, S, C> Contracts<Sp, S, C>
where
    Sp: Stockpile,
    S: KeyedCollection<Key = CodexId, Value = Schema>,
    C: KeyedCollection<Key = ContractId, Value = Contract<Sp::Stock, Sp::Pile>>,
{
    pub fn codex_ids(&self) -> impl Iterator<Item = CodexId> + use<'_, Sp, S, C> {
        self.persistence.codex_ids()
    }

    pub fn issuers_count(&self) -> usize { self.persistence.issuers_count() }

    pub fn has_issuer(&self, codex_id: CodexId) -> bool { self.persistence.has_issuer(codex_id) }

    pub fn issuers(&self) -> impl Iterator<Item = (CodexId, Schema)> + use<'_, Sp, S, C> {
        self.persistence
            .codex_ids()
            .filter_map(|codex_id| self.issuer(codex_id).map(|schema| (codex_id, schema)))
    }

    pub fn issuer(&self, codex_id: CodexId) -> Option<Schema> {
        if let Some(issuer) = self.schemata.borrow().get(&codex_id) {
            return Some(issuer.clone());
        };
        let issuer = self.persistence.issuer(codex_id)?;
        self.schemata.borrow_mut().insert(codex_id, issuer);
        self.schemata.borrow().get(&codex_id).cloned()
    }

    pub fn contracts_count(&self) -> usize { self.persistence.contracts_count() }

    pub fn has_contract(&self, contract_id: ContractId) -> bool {
        self.persistence.has_contract(contract_id)
    }

    pub fn contract_ids(&self) -> impl Iterator<Item = ContractId> + use<'_, Sp, S, C> {
        self.persistence.contract_ids()
    }

    pub fn contracts_info(&self) -> impl Iterator<Item = ContractInfo> + use<'_, Sp, S, C> {
        self.contract_ids().filter_map(|id| {
            self.with_contract(
                id,
                |contract| Some(ContractInfo::new(id, contract.articles())),
                Some(None),
            )
        })
    }

    pub fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> ContractState<<Sp::Pile as Pile>::Seal> {
        self.with_contract(contract_id, |contract| contract.state(), None)
    }

    pub fn contract_articles(&self, contract_id: ContractId) -> Articles {
        self.with_contract(contract_id, |contract| contract.articles().clone(), None)
    }

    pub fn find_contract_id(&self, r: impl Into<ContractRef>) -> Option<ContractId> {
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

    /// Iterates over all witness ids known to the set of contracts.
    ///
    /// # Nota bene
    ///
    /// Iterator may repeat the same id multiple times.
    pub fn witness_ids(
        &self,
    ) -> impl Iterator<Item = <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId> + use<'_, Sp, S, C>
    {
        self.persistence.contract_ids().flat_map(move |id| {
            self.with_contract(
                id,
                |contract| contract.witness_ids().collect::<Vec<_>>(),
                Some(none!()),
            )
        })
    }

    pub fn import(&mut self, schema: Schema) -> Result<CodexId, impl StdError + use<'_, Sp, S, C>> {
        let codex_id = schema.codex.codex_id();
        // This can't be replaced with a question mark due to `impl StdError` return type
        #[allow(clippy::question_mark)]
        let schema = match self.persistence.import(schema) {
            Ok(schema) => schema,
            Err(err) => return Err(err),
        };
        self.schemata.borrow_mut().insert(codex_id, schema);
        Ok(codex_id)
    }

    pub fn issue(
        &mut self,
        params: CreateParams<<<Sp::Pile as Pile>::Seal as RgbSeal>::Definiton>,
    ) -> Result<ContractId, IssueError<impl StdError>> {
        let contract = self.persistence.issue(params)?;
        let id = contract.contract_id();
        self.contracts.borrow_mut().insert(id, contract);
        Ok(id)
    }

    pub fn contract_call(
        &mut self,
        contract_id: ContractId,
        call: CallParams,
        seals: SmallOrdMap<u16, <<Sp::Pile as Pile>::Seal as RgbSeal>::Definiton>,
    ) -> Result<Operation, AcceptError> {
        self.with_contract_mut(contract_id, |contract| contract.call(call, seals))
    }

    pub fn sync(
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

    pub fn include(
        &mut self,
        contract_id: ContractId,
        opid: Opid,
        pub_witness: &<<Sp::Pile as Pile>::Seal as RgbSeal>::Published,
        anchor: <<Sp::Pile as Pile>::Seal as RgbSeal>::Client,
    ) {
        self.with_contract_mut(contract_id, |contract| contract.include(opid, anchor, pub_witness))
    }

    pub fn consign(
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

    pub fn consume(
        &mut self,
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
        let contract_id = Contract::<Sp::Stock, Sp::Pile>::parse_consignment(reader)?;
        if !self.has_contract(contract_id) {
            return Err(ConsumeError::UnknownContract(contract_id));
        };

        self.with_contract_mut(contract_id, |contract| contract.consume(reader, seal_resolver))
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IssueError<E: StdError> {
    /// proof of publication layer mismatch.
    ConsensusMismatch,
    /// unable to consume a testnet contract for mainnet.
    TestnetMismatch,
    /// unable to consume a mainnet contract for testnet.
    MainnetMismatch,
    /// unknown codex for contract issue {0}.
    UnknownCodex(CodexId),

    /// invalid schema; {0}
    #[from]
    InvalidSchema(CallError),

    #[from]
    #[display(inner)]
    Inner(hypersonic::IssueError<E>),
}

#[cfg(feature = "fs")]
mod fs {
    use std::fs::File;
    use std::path::Path;

    use strict_encoding::{StreamReader, StreamWriter};

    use super::*;

    impl<Sp, S, C> Contracts<Sp, S, C>
    where
        Sp: Stockpile,
        S: KeyedCollection<Key = CodexId, Value = Schema>,
        C: KeyedCollection<Key = ContractId, Value = Contract<Sp::Stock, Sp::Pile>>,
    {
        pub fn consign_to_file(
            &mut self,
            path: impl AsRef<Path>,
            contract_id: ContractId,
            terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        ) -> io::Result<()>
        where
            <<Sp::Pile as Pile>::Seal as RgbSeal>::Client: StrictDumb + StrictEncode,
            <<Sp::Pile as Pile>::Seal as RgbSeal>::Published: StrictDumb + StrictEncode,
            <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId: StrictEncode,
        {
            let file = File::create_new(path)?;
            let writer = StrictWriter::with(StreamWriter::new::<{ usize::MAX }>(file));
            self.consign(contract_id, terminals, writer)
        }

        pub fn consume_from_file(
            &mut self,
            path: impl AsRef<Path>,
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
            let file = File::open(path)?;
            let mut reader = StrictReader::with(StreamReader::new::<{ usize::MAX }>(file));
            self.consume(&mut reader, seal_resolver)
        }
    }
}
