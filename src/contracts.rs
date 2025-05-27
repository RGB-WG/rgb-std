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
use std::collections::HashMap;
use std::io;

use amplify::confinement::{KeyedCollection, SmallOrdMap};
use amplify::MultiError;
use commit_verify::StrictHash;
use hypersonic::{
    AcceptError, AuthToken, CallParams, CodexId, ContractId, ContractName, Opid, Stock,
};
use rgb::RgbSeal;
use strict_encoding::{
    ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter, WriteRaw,
};

use crate::{
    parse_consignment, Articles, CallError, Consensus, Consignment, ConsumeError, Contract,
    ContractRef, ContractState, CreateParams, Identity, Issuer, Operation, Pile, SigBlob,
    Stockpile, WitnessStatus,
};

pub const CONSIGN_VERSION: u16 = 0;
#[cfg(feature = "fs")]
pub use _fs::CONSIGN_MAGIC_NUMBER;

/// Collection of RGB smart contracts and contract issuers, which can be cached in memory.
///
/// # Generics
///
/// - `S` provides a specific cache implementation for an in-mem copy of issuers,
/// - `C` provides a specific cache implementation for an in-mem copy of contracts.
#[derive(Clone, Debug)]
pub struct Contracts<
    Sp,
    S = HashMap<CodexId, Issuer>,
    C = HashMap<ContractId, Contract<<Sp as Stockpile>::Stock, <Sp as Stockpile>::Pile>>,
> where
    Sp: Stockpile,
    S: KeyedCollection<Key = CodexId, Value = Issuer>,
    C: KeyedCollection<Key = ContractId, Value = Contract<Sp::Stock, Sp::Pile>>,
{
    issuers: RefCell<S>,
    contracts: RefCell<C>,
    persistence: Sp,
}

impl<Sp, S, C> Contracts<Sp, S, C>
where
    Sp: Stockpile,
    S: KeyedCollection<Key = CodexId, Value = Issuer>,
    C: KeyedCollection<Key = ContractId, Value = Contract<Sp::Stock, Sp::Pile>>,
{
    pub fn load(persistence: Sp) -> Self
    where
        S: Default,
        C: Default,
    {
        Self { issuers: none!(), contracts: none!(), persistence }
    }

    fn with_contract<R>(
        &self,
        id: ContractId,
        f: impl FnOnce(&Contract<Sp::Stock, Sp::Pile>) -> R,
        or: Option<R>,
    ) -> R {
        // We need this bullshit due to a failed rust `RefCell` implementation which panics if we do
        // this block any other way.
        if self.contracts.borrow().contains_key(&id) {
            return f(self.contracts.borrow().get(&id).unwrap());
        }
        if let Some(contract) = self.persistence.contract(id) {
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
        // We need this bullshit due to a failed rust `RefCell` implementation which panics if we do
        // this block any other way.
        if self.contracts.borrow().contains_key(&id) {
            return f(self.contracts.borrow_mut().get_mut(&id).unwrap());
        }
        if let Some(mut contract) = self.persistence.contract(id) {
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
    S: KeyedCollection<Key = CodexId, Value = Issuer>,
    C: KeyedCollection<Key = ContractId, Value = Contract<Sp::Stock, Sp::Pile>>,
{
    pub fn codex_ids(&self) -> impl Iterator<Item = CodexId> + use<'_, Sp, S, C> {
        self.persistence.codex_ids()
    }

    pub fn issuers_count(&self) -> usize { self.persistence.issuers_count() }

    pub fn has_issuer(&self, codex_id: CodexId) -> bool { self.persistence.has_issuer(codex_id) }

    pub fn issuers(&self) -> impl Iterator<Item = (CodexId, Issuer)> + use<'_, Sp, S, C> {
        self.persistence
            .codex_ids()
            .filter_map(|codex_id| self.issuer(codex_id).map(|schema| (codex_id, schema)))
    }

    pub fn issuer(&self, codex_id: CodexId) -> Option<Issuer> {
        if let Some(issuer) = self.issuers.borrow().get(&codex_id) {
            return Some(issuer.clone());
        };
        let issuer = self.persistence.issuer(codex_id)?;
        self.issuers.borrow_mut().insert(codex_id, issuer);
        self.issuers.borrow().get(&codex_id).cloned()
    }

    pub fn contracts_count(&self) -> usize { self.persistence.contracts_count() }

    pub fn has_contract(&self, contract_id: ContractId) -> bool {
        self.persistence.has_contract(contract_id)
    }

    pub fn contract_ids(&self) -> impl Iterator<Item = ContractId> + use<'_, Sp, S, C> {
        self.persistence.contract_ids()
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
                    .find(|(_, contract)| contract.articles().issue().meta.name == name)
                    .map(|(id, _)| *id)
                {
                    return Some(id);
                }
                self.persistence
                    .contract_ids()
                    .filter_map(|id| self.persistence.contract(id))
                    .find(|contract| contract.articles().issue().meta.name == name)
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

    pub fn import_issuer(&mut self, issuer: Issuer) -> Result<CodexId, Sp::Error> {
        let codex_id = issuer.codex_id();
        let schema = self.persistence.import_issuer(issuer)?;
        self.issuers.borrow_mut().insert(codex_id, schema);
        Ok(codex_id)
    }

    fn check_layer1(
        &self,
        consensus: Consensus,
        testnet: bool,
    ) -> Result<(), MultiError<IssuerError, <Sp::Stock as Stock>::Error, <Sp::Pile as Pile>::Error>>
    {
        if consensus != self.persistence.consensus() {
            return Err(MultiError::A(IssuerError::ConsensusMismatch));
        }
        if testnet != self.persistence.is_testnet() {
            Err(if testnet {
                MultiError::A(IssuerError::TestnetMismatch)
            } else {
                MultiError::A(IssuerError::MainnetMismatch)
            })
        } else {
            Ok(())
        }
    }

    pub fn issue(
        &mut self,
        params: CreateParams<<<Sp::Pile as Pile>::Seal as RgbSeal>::Definition>,
    ) -> Result<
        ContractId,
        MultiError<IssuerError, <Sp::Stock as Stock>::Error, <Sp::Pile as Pile>::Error>,
    > {
        self.check_layer1(params.consensus, params.testnet)?;
        let contract = self.persistence.issue(params)?;
        let id = contract.contract_id();
        self.contracts.borrow_mut().insert(id, contract);
        Ok(id)
    }

    pub fn contract_call(
        &mut self,
        contract_id: ContractId,
        call: CallParams,
        seals: SmallOrdMap<u16, <<Sp::Pile as Pile>::Seal as RgbSeal>::Definition>,
    ) -> Result<Operation, MultiError<AcceptError, <Sp::Stock as Stock>::Error>> {
        self.with_contract_mut(contract_id, |contract| contract.call(call, seals))
    }

    pub fn sync<'a, I>(
        &mut self,
        changed: I,
    ) -> Result<(), MultiError<AcceptError, <Sp::Stock as Stock>::Error>>
    where
        I: IntoIterator<
                Item = (&'a <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId, &'a WitnessStatus),
            > + Copy,
        <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId: 'a,
    {
        let contract_ids = self.persistence.contract_ids().collect::<Vec<_>>();
        for contract_id in &contract_ids {
            self.with_contract_mut(*contract_id, |contract| {
                contract.sync(changed.into_iter().map(|(id, status)| (*id, *status)))
            })?;
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

    pub fn export(
        &self,
        contract_id: ContractId,
        writer: StrictWriter<impl WriteRaw>,
    ) -> io::Result<()>
    where
        <<Sp::Pile as Pile>::Seal as RgbSeal>::Client: StrictDumb + StrictEncode,
        <<Sp::Pile as Pile>::Seal as RgbSeal>::Published: StrictDumb + StrictEncode,
        <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId: StrictEncode,
    {
        self.with_contract(contract_id, |contract| contract.export(writer), None)
    }

    pub fn purge(&mut self, contract_id: ContractId) -> Result<(), Sp::Error> {
        self.contracts.borrow_mut().remove(&contract_id);
        self.persistence.purge(contract_id)?;
        Ok(())
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

    /// Consume a consignment stream.
    ///
    /// The method:
    /// - validates the consignment;
    /// - resolves auth tokens into seal definitions known to the current wallet (i.e., coming from
    ///   the invoices produced by the wallet);
    /// - checks the signature of the issuer over the contract articles;
    ///
    /// # Arguments
    ///
    /// - `allow_unknown`: allows importing a contract which was not known to the system;
    /// - `reader`: the input stream;
    /// - `seal_resolver`: lambda which knows about the seal definitions from the wallet-generated
    ///   invoices;
    /// - `sig_validator`: a validator for the signature of the issuer over the contract articles.
    pub fn consume<E>(
        &mut self,
        allow_unknown: bool,
        reader: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(
            &Operation,
        )
            -> BTreeMap<u16, <<Sp::Pile as Pile>::Seal as RgbSeal>::Definition>,
        sig_validator: impl FnOnce(StrictHash, &Identity, &SigBlob) -> Result<(), E>,
    ) -> Result<
        (),
        MultiError<
            ConsumeError<<<Sp::Pile as Pile>::Seal as RgbSeal>::Definition>,
            <Sp::Stock as Stock>::Error,
            <Sp::Pile as Pile>::Error,
        >,
    >
    where
        <Sp::Pile as Pile>::Conf: From<<Sp::Stock as Stock>::Conf>,
        <<Sp::Pile as Pile>::Seal as RgbSeal>::Client: StrictDecode,
        <<Sp::Pile as Pile>::Seal as RgbSeal>::Published: StrictDecode,
        <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId: StrictDecode,
    {
        // Checking version
        let contract_id = parse_consignment(reader).map_err(MultiError::from_a)?;
        if !self.has_contract(contract_id) {
            if allow_unknown {
                let consignment = Consignment::strict_decode(reader).map_err(MultiError::from_a)?;
                // Here we do not check for the end of the stream,
                // so in the future we can have arbitrary extensions
                // put here with no backward compatibility issues.

                let articles = consignment
                    .articles(sig_validator)
                    .map_err(MultiError::from_a)?;
                self.check_layer1(
                    articles.contract_meta().consensus,
                    articles.contract_meta().testnet,
                )
                .map_err(MultiError::from_other_a)?;

                let contract = self.persistence.import_contract(articles, consignment)?;
                self.contracts.borrow_mut().insert(contract_id, contract);
                Ok(())
            } else {
                Err(MultiError::A(ConsumeError::UnknownContract(contract_id)))
            }
        } else {
            self.with_contract_mut(contract_id, |contract| {
                contract.consume_internal(reader, seal_resolver, sig_validator)
            })
            .map_err(|err| match err {
                MultiError::A(a) => MultiError::A(a),
                MultiError::B(b) => MultiError::B(b),
                MultiError::C(_) => unreachable!(),
            })
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IssuerError {
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
    // TODO: Rename
    InvalidSchema(CallError),

    #[from]
    #[display(inner)]
    Inner(hypersonic::IssueError),
}

#[cfg(feature = "fs")]
mod _fs {
    use std::path::Path;

    use binfile::BinFile;
    use strict_encoding::StreamReader;

    use super::*;

    pub const CONSIGN_MAGIC_NUMBER: u64 = u64::from_be_bytes(*b"RGBCNSGN");

    impl<Sp, S, C> Contracts<Sp, S, C>
    where
        Sp: Stockpile,
        S: KeyedCollection<Key = CodexId, Value = Issuer>,
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
            self.with_contract_mut(contract_id, |contract| {
                contract.consign_to_file(path, terminals)
            })
        }

        pub fn consume_from_file<E>(
            &mut self,
            allow_unknown: bool,
            path: impl AsRef<Path>,
            seal_resolver: impl FnMut(
                &Operation,
            ) -> BTreeMap<
                u16,
                <<Sp::Pile as Pile>::Seal as RgbSeal>::Definition,
            >,
            sig_validator: impl FnOnce(StrictHash, &Identity, &SigBlob) -> Result<(), E>,
        ) -> Result<
            (),
            MultiError<
                ConsumeError<<<Sp::Pile as Pile>::Seal as RgbSeal>::Definition>,
                <Sp::Stock as Stock>::Error,
                <Sp::Pile as Pile>::Error,
            >,
        >
        where
            <Sp::Pile as Pile>::Conf: From<<Sp::Stock as Stock>::Conf>,
            <<Sp::Pile as Pile>::Seal as RgbSeal>::Client: StrictDecode,
            <<Sp::Pile as Pile>::Seal as RgbSeal>::Published: StrictDecode,
            <<Sp::Pile as Pile>::Seal as RgbSeal>::WitnessId: StrictDecode,
        {
            let file = BinFile::<CONSIGN_MAGIC_NUMBER, CONSIGN_VERSION>::open(path)
                .map_err(MultiError::from_a)?;
            let mut reader = StrictReader::with(StreamReader::new::<{ usize::MAX }>(file));
            self.consume(allow_unknown, &mut reader, seal_resolver, sig_validator)
        }
    }
}
