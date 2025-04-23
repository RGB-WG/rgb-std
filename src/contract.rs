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

use amplify::confinement::SmallOrdMap;
use amplify::hex::ToHex;
use amplify::IoError;
use chrono::{DateTime, Utc};
use commit_verify::ReservedBytes;
use hypersonic::sigs::ContentSigs;
use hypersonic::{
    AcceptError, Articles, AuthToken, CallParams, CellAddr, Codex, CodexId, Consensus, ContractId,
    CoreParams, DataCell, EffectiveState, IssueError, IssueParams, Ledger, LibRepo, LoadError,
    Memory, MergeError, MethodName, NamedState, Operation, Opid, Schema, StateAtom, StateName,
    Stock, StockError, Transition,
};
use rgb::{
    ContractApi, ContractVerify, OperationSeals, ReadOperation, ReadWitness, RgbSeal, RgbSealDef,
    Step, VerificationError,
};
use single_use_seals::{ClientSideWitness, PublishedWitness, SealWitness};
use strict_encoding::{
    DecodeError, ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter,
    TypeName, WriteRaw,
};
use strict_types::StrictVal;

use crate::{ContractMeta, Issue, OpRels, Pile, VerifiedOperation, Witness, WitnessStatus};

pub const CONSIGNMENT_MAGIC_NUMBER: [u8; 8] = *b"RGBCNSGN";
pub const CONSIGNMENT_VERSION: [u8; 2] = [0x00, 0x01];

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
    where Seal: RgbSealDef {
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
    serde(bound = "Seal: serde::Serialize + for<'d> serde::Deserialize<'d>")
)]
pub struct Assignment<Seal> {
    pub seal: Seal,
    pub data: StrictVal,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "Seal: serde::Serialize + for<'d> serde::Deserialize<'d>")
)]
pub struct OwnedState<Seal> {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub assignment: Assignment<Seal>,
    pub since: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ImmutableState {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub data: StateAtom,
    pub since: Option<u64>,
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
    pub immutable: BTreeMap<StateName, BTreeMap<CellAddr, ImmutableState>>,
    pub owned: BTreeMap<StateName, BTreeMap<CellAddr, OwnedState<Seal>>>,
    pub computed: BTreeMap<StateName, StrictVal>,
    // TODO: Add "computed pending"
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
                            (addr, OwnedState {
                                assignment: Assignment {
                                    seal: f(data.assignment.seal),
                                    data: data.assignment.data,
                                },
                                since: data.since,
                            })
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
                            Some((addr, OwnedState {
                                assignment: Assignment {
                                    seal: f(data.assignment.seal)?,
                                    data: data.assignment.data,
                                },
                                since: data.since,
                            }))
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
    pub consensus: Consensus,
    pub testnet: bool,
    pub method: MethodName,
    pub name: TypeName,
    pub timestamp: Option<DateTime<Utc>>,
    pub global: Vec<NamedState<StateAtom>>,
    pub owned: Vec<NamedState<Assignment<EitherSeal<Seal>>>>,
}

pub struct Contract<S: Stock, P: Pile> {
    /// Cached contract id
    contract_id: ContractId,
    ledger: Ledger<S>,
    pile: P,
}

impl<S: Stock, P: Pile> Contract<S, P> {
    pub fn issue(
        schema: Schema,
        params: CreateParams<<P::Seal as RgbSeal>::Definiton>,
        conf: impl FnOnce(&Articles) -> S::Conf,
    ) -> Result<Self, IssueError<S::Error>>
    where
        P::Conf: From<S::Conf>,
        S::Error: From<P::Error>,
    {
        assert_eq!(params.codex_id, schema.codex.codex_id());

        let seals = SmallOrdMap::try_from_iter(params.owned.iter().enumerate().filter_map(
            |(pos, assignment)| {
                assignment
                    .state
                    .seal
                    .to_explicit()
                    .map(|seal| (pos as u16, seal))
            },
        ))
        .expect("too many outputs");
        let params = IssueParams {
            name: params.name,
            consensus: params.consensus,
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

        let articles = schema.issue(params);
        let conf = conf(&articles);
        let ledger = Ledger::new(articles, conf)?;
        let conf: S::Conf = ledger.config();
        let contract_id = ledger.contract_id();

        // Init seals
        let mut pile = P::new(conf.into()).map_err(|e| IssueError::OtherPersistence(e.into()))?;
        pile.add_seals(ledger.articles().issue.genesis_opid(), seals);

        Ok(Self { ledger, pile, contract_id })
    }

    pub fn load(stock_conf: S::Conf, pile_conf: P::Conf) -> Result<Self, LoadError<S::Error>>
    where S::Error: From<P::Error> {
        let ledger = Ledger::load(stock_conf)?;
        let contract_id = ledger.contract_id();
        let pile = P::load(pile_conf).map_err(|e| LoadError::OtherPersistence(e.into()))?;
        Ok(Self { ledger, pile, contract_id })
    }

    /// Get mining status for a given operation.
    fn witness_height(&self, opid: Opid) -> Option<u64> {
        self.pile
            .op_witness_ids(opid)
            .flat_map(|wid| self.pile.witness_status(wid).height())
            .max()
    }

    fn retrieve(
        &self,
        opid: Opid,
    ) -> impl ExactSizeIterator<Item = SealWitness<P::Seal>> + use<'_, S, P> {
        self.pile.op_witness_ids(opid).map(|wid| {
            let client = self.pile.cli_witness(wid);
            let published = self.pile.pub_witness(wid);
            SealWitness::new(published, client)
        })
    }

    pub fn contract_id(&self) -> ContractId { self.contract_id }

    pub fn articles(&self) -> &Articles { self.ledger.articles() }

    pub fn operations(
        &self,
    ) -> impl Iterator<Item = (Opid, Operation, OpRels<P::Seal>)> + use<'_, S, P> {
        self.ledger
            .operations()
            .zip(self.pile.op_relations())
            .map(|((opid, op), rels)| {
                debug_assert_eq!(opid, rels.opid);
                (opid, op, rels)
            })
    }

    pub fn trace(&self) -> impl Iterator<Item = (Opid, Transition)> + use<'_, S, P> {
        self.ledger.trace()
    }

    pub fn witness_ids(
        &self,
    ) -> impl Iterator<Item = <P::Seal as RgbSeal>::WitnessId> + use<'_, S, P> {
        self.pile.witness_ids()
    }

    pub fn witnesses(&self) -> impl Iterator<Item = Witness<P::Seal>> + use<'_, S, P> {
        self.pile.witnesses()
    }

    pub fn seal(&self, seal: &<P::Seal as RgbSeal>::Definiton) -> Option<CellAddr> {
        let auth = seal.auth_token();
        self.ledger.state().raw.auth.get(&auth).copied()
    }

    pub fn state(&self) -> ContractState<P::Seal> {
        let mut cache = bmap! {};
        let state = self.ledger.state().main.clone();
        let mut owned = bmap! {};
        for (name, map) in state.owned {
            let mut state = bmap! {};
            for (addr, data) in map {
                let since = *cache
                    .entry(addr.opid)
                    .or_insert_with(|| self.witness_height(addr.opid));
                let seals = self.pile.op_seals(addr.opid);
                let Some(seal) = seals.get(&addr.pos) else {
                    continue;
                };
                if let Some(seal) = seal.to_src() {
                    state.insert(addr, OwnedState { assignment: Assignment { seal, data }, since });
                } else {
                    // We insert a copy of state for each of the witnesses created for the operation
                    for wid in self.pile.op_witness_ids(addr.opid) {
                        state.insert(addr, OwnedState {
                            assignment: Assignment { seal: seal.resolve(wid), data: data.clone() },
                            since,
                        });
                    }
                }
            }
            owned.insert(name, state);
        }
        let mut immutable = bmap! {};
        for (name, map) in state.immutable {
            let mut state = bmap! {};
            for (addr, data) in map {
                let since = *cache
                    .entry(addr.opid)
                    .or_insert_with(|| self.witness_height(addr.opid));
                state.insert(addr, ImmutableState { data, since });
            }
            immutable.insert(name, state);
        }
        ContractState { immutable, owned, computed: state.computed }
    }

    pub fn state_all(&self) -> &EffectiveState { self.ledger.state() }

    pub fn sync(
        &mut self,
        wid: <P::Seal as RgbSeal>::WitnessId,
        status: WitnessStatus,
    ) -> Result<(), AcceptError> {
        let prev_status = self.pile.witness_status(wid);
        if status == prev_status {
            return Ok(());
        }

        self.pile.update_witness_status(wid, status);

        let opids = self.pile.ops_by_witness_id(wid);
        if status.is_valid() != prev_status.is_valid() {
            if status.is_valid() {
                self.ledger.forward(opids)?;
            } else {
                self.ledger.rollback(opids)?;
            }
        }
        Ok(())
    }

    pub fn call(
        &mut self,
        call: CallParams,
        seals: SmallOrdMap<u16, <P::Seal as RgbSeal>::Definiton>,
    ) -> Result<Operation, AcceptError> {
        let opid = self.ledger.call(call)?;
        let operation = self.ledger.operation(opid);
        debug_assert_eq!(operation.opid(), opid);
        self.pile.add_seals(opid, seals);
        debug_assert_eq!(operation.contract_id, self.contract_id());
        Ok(operation)
    }

    pub fn include(
        &mut self,
        opid: Opid,
        anchor: <P::Seal as RgbSeal>::Client,
        published: &<P::Seal as RgbSeal>::Published,
    ) {
        let wid = published.pub_id();
        let anchor = if self.pile.has_witness(wid) {
            let mut prev_anchor = self.pile.cli_witness(wid);
            if prev_anchor != anchor {
                prev_anchor.merge(anchor).expect(
                    "existing anchor is not compatible with new one; this indicates either bug in \
                     RGB standard library or a compromised storage",
                );
            }
            prev_anchor
        } else {
            anchor
        };
        self.pile.add_witness(opid, wid, published, &anchor);
    }

    pub fn consign(
        &mut self,
        terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        mut writer: StrictWriter<impl WriteRaw>,
    ) -> io::Result<()>
    where
        <P::Seal as RgbSeal>::Client: StrictDumb + StrictEncode,
        <P::Seal as RgbSeal>::Published: StrictDumb + StrictEncode,
        <P::Seal as RgbSeal>::WitnessId: StrictEncode,
    {
        // This is compatible with BinFile
        writer = CONSIGNMENT_MAGIC_NUMBER.strict_encode(writer)?;
        // Version
        writer = CONSIGNMENT_VERSION.strict_encode(writer)?;
        writer = self.contract_id().strict_encode(writer)?;
        self.ledger
            .export_aux(terminals, writer, |opid, mut writer| {
                // Write seal definitions
                let seals = self.pile.op_seals(opid);
                writer = seals.strict_encode(writer)?;

                // Write witnesses
                let iter = self.retrieve(opid);
                let len = iter.len();
                writer = (len as u64).strict_encode(writer)?;
                for witness in iter {
                    writer = witness.strict_encode(writer)?;
                }

                Ok(writer)
            })
    }

    pub fn consume(
        &mut self,
        reader: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(&Operation) -> BTreeMap<u16, <P::Seal as RgbSeal>::Definiton>,
    ) -> Result<(), ConsumeError<<P::Seal as RgbSeal>::Definiton>>
    where
        <P::Seal as RgbSeal>::Client: StrictDecode,
        <P::Seal as RgbSeal>::Published: StrictDecode,
        <P::Seal as RgbSeal>::WitnessId: StrictDecode,
    {
        // We need to read articles field by field since we have to evaluate genesis separately
        let schema = Schema::strict_decode(reader)?;
        let contract_sigs = ContentSigs::strict_decode(reader)?;
        let codex_version = ReservedBytes::<2>::strict_decode(reader)?;
        let meta = ContractMeta::strict_decode(reader)?;
        let codex = Codex::strict_decode(reader)?;

        let op_reader = OpReader { stream: reader, seal_resolver, _phantom: PhantomData };
        self.evaluate(op_reader)?;
        self.pile.commit_transaction();

        // We need to clone due to a borrow checker.
        let genesis = self.ledger.articles().issue.genesis.clone();
        let articles = Articles {
            issue: Issue { version: codex_version, meta, codex, genesis },
            contract_sigs,
            schema,
        };
        self.ledger.merge_articles(articles)?;
        Ok(())
    }

    pub fn parse_consignment(
        reader: &mut StrictReader<impl ReadRaw>,
    ) -> Result<ContractId, ConsumeError<<P::Seal as RgbSeal>::Definiton>> {
        let magic_bytes = <[u8; 8]>::strict_decode(reader)?;
        if magic_bytes != CONSIGNMENT_MAGIC_NUMBER {
            return Err(ConsumeError::UnrecognizedMagic(magic_bytes.to_hex()));
        }
        let version = <[u8; 2]>::strict_decode(reader)?;
        if version != CONSIGNMENT_VERSION {
            return Err(ConsumeError::UnsupportedVersion(u16::from_be_bytes(version)));
        }
        Ok(ContractId::strict_decode(reader)?)
    }
}

pub struct OpReader<
    'r,
    SealDef: RgbSealDef,
    R: ReadRaw,
    F: FnMut(&Operation) -> BTreeMap<u16, SealDef>,
> {
    stream: &'r mut StrictReader<R>,
    seal_resolver: F,
    _phantom: PhantomData<SealDef>,
}

impl<'r, SealDef: RgbSealDef, R: ReadRaw, F: FnMut(&Operation) -> BTreeMap<u16, SealDef>>
    ReadOperation for OpReader<'r, SealDef, R, F>
{
    type SealDef = SealDef;
    type WitnessReader = WitnessReader<'r, SealDef, R, F>;

    fn read_operation(mut self) -> Option<(OperationSeals<Self::SealDef>, Self::WitnessReader)> {
        match Operation::strict_decode(self.stream) {
            Ok(operation) => {
                let mut defined_seals = SmallOrdMap::strict_decode(self.stream)
                    .expect("Failed to read consignment stream");
                defined_seals
                    .extend((self.seal_resolver)(&operation))
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

pub struct WitnessReader<
    'r,
    SealDef: RgbSealDef,
    R: ReadRaw,
    F: FnMut(&Operation) -> BTreeMap<u16, SealDef>,
> {
    left: u64,
    parent: OpReader<'r, SealDef, R, F>,
}

impl<'r, SealDef: RgbSealDef, R: ReadRaw, F: FnMut(&Operation) -> BTreeMap<u16, SealDef>>
    ReadWitness for WitnessReader<'r, SealDef, R, F>
{
    type SealDef = SealDef;
    type OperationReader = OpReader<'r, SealDef, R, F>;

    fn read_witness(
        mut self,
    ) -> Step<(SealWitness<<Self::SealDef as RgbSealDef>::Src>, Self), Self::OperationReader> {
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

impl<S: Stock, P: Pile> ContractApi<P::Seal> for Contract<S, P> {
    fn contract_id(&self) -> ContractId { self.ledger.contract_id() }

    fn codex(&self) -> &Codex { &self.ledger.articles().schema.codex }

    fn repo(&self) -> &impl LibRepo { &self.ledger.articles().schema }

    fn memory(&self) -> &impl Memory { &self.ledger.state().raw }

    fn is_known(&self, opid: Opid) -> bool { self.ledger.has_operation(opid) }

    fn apply_operation(
        &mut self,
        op: VerifiedOperation,
        seals: SmallOrdMap<u16, <P::Seal as RgbSeal>::Definiton>,
    ) {
        self.pile.add_seals(op.opid(), seals);
        self.ledger.apply(op).expect("unable to apply operation");
    }

    fn apply_witness(&mut self, opid: Opid, witness: SealWitness<P::Seal>) {
        self.include(opid, witness.client, &witness.published)
    }
}

// TODO: Add Error and Debug
#[derive(Display, From)]
#[display(inner)]
pub enum ConsumeError<Seal: RgbSealDef> {
    #[from]
    #[from(io::Error)]
    Io(IoError),

    /// unrecognized magic bytes {0} in the consignment stream
    UnrecognizedMagic(String),

    /// unsupported version {0} of the consignment stream
    UnsupportedVersion(u16),

    /// unknown {0} can't be consumed; please import contract articles first.
    UnknownContract(ContractId),

    #[from]
    Decode(DecodeError),

    #[from]
    Merge(StockError<MergeError>),

    #[from]
    Verify(VerificationError<Seal::Src>),
}

#[cfg(feature = "fs")]
mod fs {
    use std::fs::File;
    use std::path::Path;

    use hypersonic::persistance::StockFs;
    use strict_encoding::{StreamWriter, StrictDecode, StrictDumb, StrictEncode};

    use super::*;
    use crate::pile::fs::PileFs;

    impl<SealSrc: RgbSeal> Contract<StockFs, PileFs<SealSrc>>
    where
        SealSrc::Client: StrictEncode + StrictDecode,
        SealSrc::Published: Eq + StrictEncode + StrictDecode,
        SealSrc::WitnessId: Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        pub fn consign_to_file(
            &mut self,
            path: impl AsRef<Path>,
            terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        ) -> io::Result<()>
        where
            SealSrc::Client: StrictDumb,
            SealSrc::Published: StrictDumb,
            SealSrc::WitnessId: StrictEncode,
        {
            let file = File::create_new(path)?;
            let writer = StrictWriter::with(StreamWriter::new::<{ usize::MAX }>(file));
            self.consign(terminals, writer)
        }
    }
}
