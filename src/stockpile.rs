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
use core::marker::PhantomData;
// TODO: Used in strict encoding; once solved there, remove here
use std::io;

use amplify::confinement::SmallVec;
use amplify::IoError;
use chrono::{DateTime, Utc};
use commit_verify::ReservedBytes;
use hypersonic::aora::Aora;
use hypersonic::sigs::ContentSigs;
use hypersonic::{
    Articles, AuthToken, CallParams, CellAddr, Codex, CodexId, Contract, ContractId, CoreParams,
    DataCell, IssueParams, LibRepo, Memory, MergeError, MethodName, NamedState, Operation, Opid,
    Schema, StateAtom, StateName, Stock, Supply,
};
use rgb::{
    ContractApi, ContractVerify, OperationSeals, ReadOperation, ReadWitness, RgbSeal,
    SealAuthToken, SealType, Step, VerificationError,
};
use single_use_seals::{PublishedWitness, SealWitness, SingleUseSeal};
use strict_encoding::{
    DecodeError, ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter,
    TypeName, WriteRaw,
};
use strict_types::StrictVal;

use crate::{ContractMeta, Pile, StateCell};

#[derive(Copy, Clone, PartialEq, Eq, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(untagged, bound = "Seal: serde::Serialize + for<'d> serde::Deserialize<'d>")
)]
pub enum EitherSeal<Seal> {
    Alt(Seal),
    #[from]
    Token(AuthToken),
}

impl<Seal> EitherSeal<Seal> {
    pub fn auth_token(&self) -> AuthToken
    where Seal: RgbSeal {
        match self {
            EitherSeal::Alt(seal) => seal.auth_token(),
            EitherSeal::Token(auth) => *auth,
        }
    }

    pub fn to_explicit(&self) -> Option<Seal>
    where Seal: Clone {
        match self {
            EitherSeal::Alt(seal) => Some(seal.clone()),
            EitherSeal::Token(_) => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound = "Seal: serde::Serialize + for<'d> serde::Deserialize<'d>"
    )
)]
pub struct Assignment<Seal> {
    pub seal: Seal,
    pub data: StrictVal,
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound = "Seal: serde::Serialize + for<'d> serde::Deserialize<'d>"
    )
)]
pub struct ContractState<Seal> {
    pub immutable: BTreeMap<StateName, BTreeMap<CellAddr, StateAtom>>,
    pub owned: BTreeMap<StateName, BTreeMap<CellAddr, Assignment<Seal>>>,
    pub computed: BTreeMap<StateName, StrictVal>,
}

impl<Seal> ContractState<Seal> {
    pub fn map<To>(self, f: impl Fn(Seal) -> To) -> ContractState<To> {
        ContractState {
            immutable: self.immutable,
            owned: self
                .owned
                .into_iter()
                .map(|(name, map)| {
                    let map = map
                        .into_iter()
                        .map(|(addr, data)| {
                            (addr, Assignment { seal: f(data.seal), data: data.data })
                        })
                        .collect();
                    (name, map)
                })
                .collect(),
            computed: self.computed,
        }
    }

    pub fn filter_map<To>(self, f: impl Fn(Seal) -> Option<To>) -> ContractState<To> {
        ContractState {
            immutable: self.immutable,
            owned: self
                .owned
                .into_iter()
                .map(|(name, map)| {
                    let map = map
                        .into_iter()
                        .filter_map(|(addr, data)| {
                            Some((addr, Assignment { seal: f(data.seal)?, data: data.data }))
                        })
                        .collect();
                    (name, map)
                })
                .collect(),
            computed: self.computed,
        }
    }
}

/// Parameters used by RGB for contract creation operations.
///
/// Differs from [`IssueParams`] in the fact that it uses full seal data instead of
/// [`hypersonic::AuthTokens`] for output definitions.
#[derive(Clone, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound = "Seal: serde::Serialize + for<'d> serde::Deserialize<'d>"
    )
)]
pub struct CreateParams<Seal: Clone> {
    pub codex_id: CodexId,
    pub seal_type: SealType,
    pub testnet: bool,
    pub method: MethodName,
    pub name: TypeName,
    pub timestamp: Option<DateTime<Utc>>,
    pub global: Vec<NamedState<StateAtom>>,
    pub owned: Vec<NamedState<Assignment<EitherSeal<Seal>>>>,
}

pub trait StockpileApi {
    type Seal: RgbSeal;
    type Pile: Pile<Seal = Self::Seal>;

    fn contract_id(&self) -> ContractId;

    fn pile(&self) -> &Self::Pile;
    fn pile_mut(&mut self) -> &mut Self::Pile;

    fn schema(&self) -> &Schema;
    fn state(&mut self) -> ContractState<Self::Seal>;
    fn call(&mut self, params: CallParams) -> Opid;
    fn operation(&mut self, opid: Opid) -> Operation;
    fn seal(&self, seal: &Self::Seal) -> Option<CellAddr>;

    fn attest(
        &mut self,
        opid: Opid,
        anchor: <Self::Seal as SingleUseSeal>::CliWitness,
        published: &<Self::Seal as SingleUseSeal>::PubWitness,
    );

    fn consign(
        &mut self,
        terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        writer: StrictWriter<impl WriteRaw>,
    ) -> io::Result<()>
    where
        <Self::Seal as SingleUseSeal>::CliWitness: StrictDumb + StrictEncode,
        <Self::Seal as SingleUseSeal>::PubWitness: StrictDumb + StrictEncode,
        <<Self::Seal as SingleUseSeal>::PubWitness as PublishedWitness<Self::Seal>>::PubId:
            StrictEncode;

    fn consume(
        &mut self,
        stream: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(&[StateCell]) -> Vec<Self::Seal>,
    ) -> Result<(), ConsumeError<Self::Seal>>
    where
        <Self::Seal as SingleUseSeal>::CliWitness: StrictDecode,
        <Self::Seal as SingleUseSeal>::PubWitness: StrictDecode,
        <<Self::Seal as SingleUseSeal>::PubWitness as PublishedWitness<Self::Seal>>::PubId:
            StrictDecode;
}

#[derive(Getters)]
pub struct Stockpile<S: Supply<CAPS>, P: Pile, const CAPS: u32> {
    stock: Stock<S, CAPS>,
    #[getter(skip)]
    pile: P,
}

impl<S: Supply<CAPS>, P: Pile, const CAPS: u32> Stockpile<S, P, CAPS> {
    pub fn issue(schema: Schema, params: CreateParams<P::Seal>, supply: S, mut pile: P) -> Self {
        assert_eq!(params.codex_id, schema.codex.codex_id());
        assert_eq!(params.seal_type as u32, CAPS, "invalid seal type for the issue");

        let seals = SmallVec::try_from_iter(
            params
                .owned
                .iter()
                .filter_map(|assignment| assignment.state.seal.to_explicit()),
        )
        .expect("too many outputs");
        let params = IssueParams {
            name: params.name,
            testnet: params.testnet,
            timestamp: params.timestamp,
            core: CoreParams {
                method: params.method,
                global: params.global,
                owned: params
                    .owned
                    .into_iter()
                    .map(|assignment| NamedState {
                        name: assignment.name,
                        state: DataCell {
                            auth: assignment.state.seal.auth_token(),
                            data: assignment.state.data,
                            lock: None,
                        },
                    })
                    .collect(),
            },
        };

        let articles = schema.issue::<CAPS>(params);
        let stock = Stock::create(articles, supply);

        // Init seals
        pile.keep_mut()
            .append(stock.articles().contract.genesis_opid(), &seals);

        Self { stock, pile }
    }

    pub fn open(articles: Articles<CAPS>, supply: S, pile: P) -> Self {
        let stock = Stock::open(articles, supply);
        Self { stock, pile }
    }
}

impl<S: Supply<CAPS>, P: Pile, const CAPS: u32> StockpileApi for Stockpile<S, P, CAPS> {
    type Seal = P::Seal;
    type Pile = P;

    fn contract_id(&self) -> ContractId { self.stock.contract_id() }

    fn pile(&self) -> &Self::Pile { &self.pile }

    fn pile_mut(&mut self) -> &mut Self::Pile { &mut self.pile }

    fn schema(&self) -> &Schema { &self.stock.articles().schema }

    fn call(&mut self, params: CallParams) -> Opid { self.stock.call(params) }

    fn operation(&mut self, opid: Opid) -> Operation { self.stock.operation(opid) }

    fn seal(&self, seal: &P::Seal) -> Option<CellAddr> {
        let auth = seal.auth_token();
        self.stock.state().raw.auth.get(&auth).copied()
    }

    fn state(&mut self) -> ContractState<P::Seal> {
        let state = self.stock().state().main.clone();
        ContractState {
            immutable: state.immutable,
            owned: state
                .owned
                .into_iter()
                .map(|(name, map)| {
                    let map = map
                        .into_iter()
                        .map(|(addr, data)| {
                            let seal = self.pile_mut().keep_mut().read(addr.opid)
                                [addr.pos as usize]
                                .clone();
                            (addr, Assignment { seal, data })
                        })
                        .collect();
                    (name, map)
                })
                .collect(),
            computed: state.computed,
        }
    }

    fn attest(
        &mut self,
        opid: Opid,
        anchor: <P::Seal as SingleUseSeal>::CliWitness,
        published: &<P::Seal as SingleUseSeal>::PubWitness,
    ) {
        self.pile.append(opid, anchor, published);
    }

    fn consign(
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
                // Write seal definitions
                let seals = self.pile.keep_mut().read(opid);
                writer = seals.strict_encode(writer)?;

                // Write witnesses
                let iter = self.pile.retrieve(opid);
                let len = iter.len();
                writer = (len as u64).strict_encode(writer)?;
                for witness in iter {
                    writer = witness.strict_encode(writer)?;
                }

                Ok(writer)
            })
    }

    fn consume(
        &mut self,
        stream: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(&[StateCell]) -> Vec<P::Seal>,
    ) -> Result<(), ConsumeError<P::Seal>>
    where
        <P::Seal as SingleUseSeal>::CliWitness: StrictDecode,
        <P::Seal as SingleUseSeal>::PubWitness: StrictDecode,
        <<P::Seal as SingleUseSeal>::PubWitness as PublishedWitness<P::Seal>>::PubId: StrictDecode,
    {
        // TODO: Add version

        // We need to read articles field by field since we have to evaluate genesis separately
        let schema = Schema::strict_decode(stream)?;
        let contract_sigs = ContentSigs::strict_decode(stream)?;
        let codex_version = ReservedBytes::<2>::strict_decode(stream)?;
        let meta = ContractMeta::<CAPS>::strict_decode(stream)?;
        let codex = Codex::strict_decode(stream)?;

        // We need to clone due to a borrow checker.
        let op_reader = OpReader { stream, seal_resolver, _phantom: PhantomData };
        self.evaluate(op_reader)?;

        let genesis = self.stock.articles().contract.genesis.clone();
        let articles = Articles::<CAPS> {
            contract: Contract { version: codex_version, meta, codex, genesis },
            contract_sigs,
            schema,
        };
        self.stock.merge_articles(articles)?;
        self.stock.complete_update();
        Ok(())
    }
}

pub struct OpReader<'r, Seal: RgbSeal, R: ReadRaw, F: FnMut(&[StateCell]) -> Vec<Seal>> {
    stream: &'r mut StrictReader<R>,
    seal_resolver: F,
    _phantom: PhantomData<Seal>,
}

impl<'r, Seal: RgbSeal, R: ReadRaw, F: FnMut(&[StateCell]) -> Vec<Seal>> ReadOperation
    for OpReader<'r, Seal, R, F>
{
    type Seal = Seal;
    type WitnessReader = WitnessReader<'r, Seal, R, F>;

    fn read_operation(mut self) -> Option<(OperationSeals<Self::Seal>, Self::WitnessReader)> {
        match Operation::strict_decode(self.stream) {
            Ok(operation) => {
                let mut defined_seals = SmallVec::strict_decode(self.stream)
                    .expect("Failed to read consignment stream");
                defined_seals
                    .extend((self.seal_resolver)(operation.destructible.as_ref()))
                    .expect("Too many seals defined in the operation");
                let op_seals = OperationSeals { operation, defined_seals };
                let count =
                    u64::strict_decode(self.stream).expect("Failed to read consignment stream");
                Some((op_seals, WitnessReader { parent: self, left: count }))
            }
            Err(DecodeError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => None,
            Err(e) => {
                // TODO: Report error via a side-channel
                panic!("Failed to read consignment stream: {}", e);
            }
        }
    }
}

pub struct WitnessReader<'r, Seal: RgbSeal, R: ReadRaw, F: FnMut(&[StateCell]) -> Vec<Seal>> {
    left: u64,
    parent: OpReader<'r, Seal, R, F>,
}

impl<'r, Seal: RgbSeal, R: ReadRaw, F: FnMut(&[StateCell]) -> Vec<Seal>> ReadWitness
    for WitnessReader<'r, Seal, R, F>
{
    type Seal = Seal;
    type OpReader = OpReader<'r, Seal, R, F>;

    fn read_witness(mut self) -> Step<(SealWitness<Self::Seal>, Self), Self::OpReader> {
        if self.left == 0 {
            return Step::Complete(self.parent);
        }
        self.left -= 1;
        match SealWitness::strict_decode(self.parent.stream) {
            Ok(witness) => Step::Next((witness, self)),
            Err(e) => {
                // TODO: Report error via a side-channel
                panic!("Failed to read consignment stream: {}", e);
            }
        }
    }
}

impl<S: Supply<CAPS>, P: Pile, const CAPS: u32> ContractApi<P::Seal> for Stockpile<S, P, CAPS> {
    fn contract_id(&self) -> ContractId { self.stock.contract_id() }

    fn codex(&self) -> &Codex { &self.stock.articles().schema.codex }

    fn repo(&self) -> &impl LibRepo { &self.stock.articles().schema }

    fn memory(&self) -> &impl Memory { &self.stock.state().raw }

    fn apply_operation(&mut self, op: OperationSeals<P::Seal>) {
        self.pile
            .keep_mut()
            .append(op.operation.opid(), &op.defined_seals);
        self.stock.apply(op.operation);
    }

    fn apply_witness(&mut self, opid: Opid, witness: SealWitness<P::Seal>) {
        self.pile.append(opid, witness.client, &witness.published);
    }
}

#[derive(Display, From)]
#[display(inner)]
pub enum ConsumeError<Seal: RgbSeal> {
    #[display("unrecognized magic bytes in consignment stream ({0})")]
    UnrecognizedMagic(String),

    #[from]
    #[from(io::Error)]
    Io(IoError),

    #[from]
    Decode(DecodeError),

    #[from]
    Merge(MergeError),

    #[from]
    Verify(VerificationError<Seal>),
}

#[cfg(feature = "fs")]
mod fs {
    use std::fs::File;
    use std::path::Path;

    use hypersonic::FileSupply;
    use strict_encoding::{StreamWriter, StrictDecode, StrictDumb, StrictEncode};

    use super::*;
    use crate::FilePile;

    impl<Seal: RgbSeal, const CAPS: u32> Stockpile<FileSupply, FilePile<Seal>, CAPS>
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

        pub fn issue_to_file(
            schema: Schema,
            params: CreateParams<Seal>,
            path: impl AsRef<Path>,
        ) -> Self {
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
    }
}
