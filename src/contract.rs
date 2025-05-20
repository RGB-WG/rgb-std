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
use core::error::Error;
use core::marker::PhantomData;
use std::io;

use amplify::confinement::SmallOrdMap;
use amplify::hex::ToHex;
use amplify::IoError;
use chrono::{DateTime, Utc};
use commit_verify::ReservedBytes;
use hypersonic::{
    AcceptError, Articles, ArticlesError, AuthToken, CallParams, CellAddr, Codex, CodexId,
    Consensus, ContractId, CoreParams, DataCell, EffectiveState, EitherError, IssueError,
    IssueParams, Ledger, LibRepo, Memory, MethodName, NamedState, Operation, Opid, SigValidator,
    StateAtom, StateName, Stock, Transition,
};
use indexmap::{IndexMap, IndexSet};
use rgb::{
    ContractApi, ContractVerify, OperationSeals, ReadOperation, RgbSeal, RgbSealDef,
    VerificationError,
};
use single_use_seals::{ClientSideWitness, PublishedWitness, SealWitness};
use strict_encoding::{
    DecodeError, ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter,
    TypeName, WriteRaw,
};
use strict_types::StrictVal;

use crate::{
    ApiDescriptor, ContractMeta, Issue, Issuer, OpRels, Pile, TripleError, VerifiedOperation,
    Witness, WitnessStatus,
};

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

impl<Seal> Assignment<Seal> {
    pub fn new(seal: Seal, data: impl Into<StrictVal>) -> Self { Self { seal, data: data.into() } }
}

impl<Seal> Assignment<EitherSeal<Seal>> {
    pub fn new_external(auth: AuthToken, data: impl Into<StrictVal>) -> Self {
        Self { seal: EitherSeal::Token(auth), data: data.into() }
    }
    pub fn new_internal(seal: Seal, data: impl Into<StrictVal>) -> Self {
        Self { seal: EitherSeal::Alt(seal), data: data.into() }
    }
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
    pub status: WitnessStatus,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ImmutableState {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub data: StateAtom,
    pub status: WitnessStatus,
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
    pub aggregated: BTreeMap<StateName, StrictVal>,
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
                                status: data.status,
                            })
                        })
                        .collect();
                    (name, map)
                })
                .collect(),
            aggregated: self.aggregated,
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
                                status: data.status,
                            }))
                        })
                        .collect();
                    (name, map)
                })
                .collect(),
            aggregated: self.aggregated,
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

impl<Seal: Clone> CreateParams<Seal> {
    pub fn new_testnet(codex_id: CodexId, consensus: Consensus, name: impl Into<TypeName>) -> Self {
        Self {
            codex_id,
            consensus,
            testnet: true,
            method: vname!("issue"),
            name: name.into(),
            timestamp: None,
            global: none![],
            owned: none![],
        }
    }

    pub fn with_global_verified(
        mut self,
        name: impl Into<StateName>,
        data: impl Into<StrictVal>,
    ) -> Self {
        self.global
            .push(NamedState { name: name.into(), state: StateAtom::new_verified(data) });
        self
    }

    pub fn push_owned_unlocked(
        &mut self,
        name: impl Into<StateName>,
        assignment: Assignment<EitherSeal<Seal>>,
    ) {
        self.owned
            .push(NamedState { name: name.into(), state: assignment });
    }
}

#[derive(Clone, Debug)]
pub struct Contract<S: Stock, P: Pile> {
    /// Cached contract id
    contract_id: ContractId,
    ledger: Ledger<S>,
    pile: P,
}

impl<S: Stock, P: Pile> Contract<S, P> {
    /// Initializes contract from contract articles, with a given persistence configuration.
    pub fn with_articles(
        articles: Articles,
        conf: S::Conf,
    ) -> Result<Self, TripleError<IssueError, S::Error, P::Error>>
    where
        P::Conf: From<S::Conf>,
    {
        let contract_id = articles.contract_id();
        let genesis_opid = articles.genesis_opid();
        let ledger = Ledger::new(articles, conf).map_err(TripleError::from)?;
        let conf: S::Conf = ledger.config();
        let mut pile = P::new(conf.into()).map_err(TripleError::C)?;
        pile.add_seals(genesis_opid, none!());
        Ok(Self { ledger, pile, contract_id })
    }

    pub fn issue(
        issuer: Issuer,
        params: CreateParams<<P::Seal as RgbSeal>::Definition>,
        conf: impl FnOnce(&Articles) -> Result<S::Conf, S::Error>,
    ) -> Result<Self, TripleError<IssueError, S::Error, P::Error>>
    where
        P::Conf: From<S::Conf>,
    {
        assert_eq!(params.codex_id, issuer.codex.codex_id());

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

        let articles = issuer.issue(params);
        let conf = conf(&articles).map_err(TripleError::B)?;
        let ledger = Ledger::new(articles, conf)?;
        let conf: S::Conf = ledger.config();
        let contract_id = ledger.contract_id();

        // Init seals
        let mut pile = P::new(conf.into()).map_err(TripleError::C)?;
        pile.add_seals(ledger.articles().genesis_opid(), seals);

        Ok(Self { ledger, pile, contract_id })
    }

    pub fn load(
        stock_conf: S::Conf,
        pile_conf: P::Conf,
    ) -> Result<Self, EitherError<S::Error, P::Error>> {
        let ledger = Ledger::load(stock_conf).map_err(EitherError::A)?;
        let contract_id = ledger.contract_id();
        let pile = P::load(pile_conf).map_err(EitherError::B)?;
        Ok(Self { ledger, pile, contract_id })
    }

    /// Get mining status for a given operation.
    fn witness_status(&self, opid: Opid) -> WitnessStatus {
        self.pile
            .op_witness_ids(opid)
            .map(|wid| self.pile.witness_status(wid))
            .max()
            .unwrap_or(WitnessStatus::Genesis)
    }

    fn retrieve(&self, opid: Opid) -> Option<SealWitness<P::Seal>> {
        let (status, wid) = self
            .pile
            .op_witness_ids(opid)
            .map(|wid| (self.pile.witness_status(wid), wid))
            .max()?;
        if !status.is_valid() {
            return None;
        }
        let client = self.pile.cli_witness(wid);
        let published = self.pile.pub_witness(wid);
        Some(SealWitness::new(published, client))
    }

    pub fn contract_id(&self) -> ContractId { self.contract_id }

    pub fn articles(&self) -> &Articles { self.ledger.articles() }

    /// # Nota bene
    ///
    /// Does not include genesis
    pub fn operations(
        &self,
    ) -> impl Iterator<Item = (Opid, Operation, OpRels<P::Seal>)> + use<'_, S, P> {
        self.ledger.operations().map(|(opid, op)| {
            let rels = self.pile.op_relations(opid, op.destructible_out.len_u16());
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

    pub fn ops_by_witness_id(
        &self,
        wid: <P::Seal as RgbSeal>::WitnessId,
    ) -> impl Iterator<Item = Opid> + use<'_, S, P> {
        self.pile.ops_by_witness_id(wid)
    }

    pub fn op_seals(&self, opid: Opid, up_to: u16) -> OpRels<P::Seal> {
        self.pile.op_relations(opid, up_to)
    }

    pub fn seal(&self, seal: &<P::Seal as RgbSeal>::Definition) -> Option<CellAddr> {
        let auth = seal.auth_token();
        self.ledger.state().raw.auth.get(&auth).copied()
    }

    pub fn state(&self) -> ContractState<P::Seal> {
        let mut cache = bmap! {};
        let state = self.ledger.state().main.clone();
        let mut owned = bmap! {};
        for (name, map) in state.destructible {
            let mut state = bmap! {};
            for (addr, data) in map {
                let since = *cache
                    .entry(addr.opid)
                    .or_insert_with(|| self.witness_status(addr.opid));
                let Some(seal) = self.pile.seal(addr) else {
                    continue;
                };
                if let Some(seal) = seal.to_src() {
                    state.insert(addr, OwnedState {
                        assignment: Assignment { seal, data },
                        status: since,
                    });
                } else {
                    // We insert a copy of state for each of the witnesses created for the operation
                    for wid in self.pile.op_witness_ids(addr.opid) {
                        state.insert(addr, OwnedState {
                            assignment: Assignment { seal: seal.resolve(wid), data: data.clone() },
                            status: since,
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
                let status = *cache
                    .entry(addr.opid)
                    .or_insert_with(|| self.witness_status(addr.opid));
                state.insert(addr, ImmutableState { data, status });
            }
            immutable.insert(name, state);
        }
        ContractState { immutable, owned, aggregated: state.aggregated }
    }

    pub fn state_all(&self) -> &EffectiveState { self.ledger.state() }

    pub fn sync(
        &mut self,
        changed: impl IntoIterator<Item = (<P::Seal as RgbSeal>::WitnessId, WitnessStatus)>,
    ) -> Result<(), EitherError<AcceptError, S::Error>> {
        // Step 1: Sanitize the list of changed wids
        let mut affected_wids = IndexMap::new();
        for (wid, status) in changed {
            if !self.pile.has_witness(wid) {
                continue;
            }
            let prev_status = self.pile.witness_status(wid);
            if status == prev_status {
                continue;
            }

            let old_status = affected_wids.insert(wid, status);
            debug_assert!(
                old_status.is_none() || old_status == Some(status),
                "the same transaction with different status passed to a sync operation"
            );
        }

        // Step 2: Select opdis which may be affected by the changed witnesses and their pre-sync
        // operation status
        let mut affected_ops = IndexMap::new();
        for wid in affected_wids.keys() {
            for opid in self.pile.ops_by_witness_id(*wid) {
                let op_status = self.witness_status(opid);
                let old = affected_ops.insert(opid, op_status);
                debug_assert!(old.is_none() || old == Some(op_status));
            }
        }

        // Step 3: Update witness status.
        // NB: This cannot be done at the same time as step 2 due to many-to-many relation between
        // witnesses and operations, such that one witness change may affect other operation witness
        // status.
        for (wid, status) in affected_wids {
            self.pile.update_witness_status(wid, status);
        }

        // Step 4: Filter opids and leave only those whose status has changed after the witness
        // update
        let mut roll_back = IndexSet::new();
        let mut forward = IndexSet::new();
        for (opid, old_status) in affected_ops {
            let new_status = self.witness_status(opid);
            if old_status.is_valid() == new_status.is_valid() {
                continue;
            }
            if new_status.is_valid() {
                forward.insert(opid);
            } else {
                roll_back.insert(opid);
            }
        }
        debug_assert_eq!(forward.intersection(&roll_back).count(), 0);

        // Step 5: Perform rollback and forward operations
        self.ledger.rollback(roll_back).map_err(EitherError::B)?;
        // Ledger has already committed as a part of `rollback`
        self.pile.commit_transaction();

        self.ledger.forward(forward)?;
        // Ledger has already committed as a part of `forward`
        self.pile.commit_transaction();

        Ok(())
    }

    pub fn call(
        &mut self,
        call: CallParams,
        seals: SmallOrdMap<u16, <P::Seal as RgbSeal>::Definition>,
    ) -> Result<Operation, EitherError<AcceptError, S::Error>> {
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
                    "the existing anchor is not compatible with the new one; this indicates \
                     either a bug in the RGB standard library or a compromised storage",
                );
            }
            prev_anchor
        } else {
            anchor
        };
        self.pile
            .add_witness(opid, wid, published, &anchor, WitnessStatus::Tentative);
        self.pile.commit_transaction();
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
            .export_aux(terminals, writer, |opid, op, mut writer| {
                // Write seal definitions
                let seals = self.pile.seals(opid, op.destructible_out.len_u16());
                writer = seals.strict_encode(writer)?;

                // Write witnesses
                let witness = self.retrieve(opid);
                writer = witness.is_some().strict_encode(writer)?;
                if let Some(witness) = witness {
                    writer = witness.strict_encode(writer)?;
                }

                Ok(writer)
            })
    }

    pub fn consume(
        &mut self,
        reader: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(&Operation) -> BTreeMap<u16, <P::Seal as RgbSeal>::Definition>,
        sig_validator: impl SigValidator,
    ) -> Result<(), EitherError<ConsumeError<<P::Seal as RgbSeal>::Definition>, S::Error>>
    where
        <P::Seal as RgbSeal>::Client: StrictDecode,
        <P::Seal as RgbSeal>::Published: StrictDecode,
        <P::Seal as RgbSeal>::WitnessId: StrictDecode,
    {
        let articles = (|| -> Result<Articles, ConsumeError<_>> {
            // We need to read articles field by field since we have to evaluate genesis separately
            let apis = ApiDescriptor::strict_decode(reader)?;

            let issue_version = ReservedBytes::<1>::strict_decode(reader)?;
            let meta = ContractMeta::strict_decode(reader)?;
            let codex = Codex::strict_decode(reader)?;

            let op_reader = OpReader { stream: reader, seal_resolver, _phantom: PhantomData };
            self.evaluate(op_reader)
                .unwrap_or_else(|err| panic!("Error: {err}"));
            self.ledger.commit_transaction();
            self.pile.commit_transaction();

            // We need to clone due to a borrow checker.
            let genesis = self.ledger.articles().genesis().clone();
            let issue = Issue { version: issue_version, meta, codex, genesis };
            let articles = Articles::with(apis, issue)?;

            Ok(articles)
        })()
        .map_err(EitherError::A)?;

        self.ledger
            .merge_articles(articles, sig_validator)
            .map_err(EitherError::from_other_a)?;
        Ok(())
    }

    pub fn parse_consignment(
        reader: &mut StrictReader<impl ReadRaw>,
    ) -> Result<ContractId, ConsumeError<<P::Seal as RgbSeal>::Definition>> {
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
    Seal: RgbSeal,
    R: ReadRaw,
    F: FnMut(&Operation) -> BTreeMap<u16, Seal::Definition>,
> {
    stream: &'r mut StrictReader<R>,
    seal_resolver: F,
    _phantom: PhantomData<Seal>,
}

impl<'r, Seal: RgbSeal, R: ReadRaw, F: FnMut(&Operation) -> BTreeMap<u16, Seal::Definition>>
    ReadOperation for OpReader<'r, Seal, R, F>
{
    type Seal = Seal;

    fn read_operation(
        &mut self,
    ) -> Result<Option<OperationSeals<Self::Seal>>, impl Error + 'static> {
        let Some(operation) =
            Operation::strict_decode(self.stream)
                .map(Some)
                .or_else(|e| match e {
                    DecodeError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
                    e => Err(e),
                })?
        else {
            return Result::<_, DecodeError>::Ok(None);
        };

        let mut defined_seals = SmallOrdMap::strict_decode(self.stream)?;
        defined_seals
            .extend((self.seal_resolver)(&operation))
            .map_err(|_| {
                DecodeError::DataIntegrityError(format!(
                    "too many seals defined for the operation {}",
                    operation.opid()
                ))
            })?;
        let has_witness = bool::strict_decode(self.stream)?;

        let witness = if has_witness {
            SealWitness::strict_decode(self.stream)
                .map(Some)
                .or_else(|e| match e {
                    DecodeError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
                    e => Err(e),
                })?
        } else {
            None
        };

        Ok(Some(OperationSeals { operation, defined_seals, witness }))
    }
}

impl<S: Stock, P: Pile> ContractApi<P::Seal> for Contract<S, P> {
    fn contract_id(&self) -> ContractId { self.ledger.contract_id() }

    fn codex(&self) -> &Codex { self.ledger.articles().codex() }

    fn repo(&self) -> &impl LibRepo { self.ledger.articles() }

    fn memory(&self) -> &impl Memory { &self.ledger.state().raw }

    fn is_known(&self, opid: Opid) -> bool { self.ledger.is_valid(opid) }

    fn apply_operation(&mut self, op: VerifiedOperation) {
        self.ledger.apply(op).expect("unable to apply operation");
    }

    fn apply_seals(
        &mut self,
        opid: Opid,
        seals: SmallOrdMap<u16, <P::Seal as RgbSeal>::Definition>,
    ) {
        self.pile.add_seals(opid, seals);
    }

    fn apply_witness(&mut self, opid: Opid, witness: SealWitness<P::Seal>) {
        self.include(opid, witness.client, &witness.published)
    }
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum ConsumeError<Seal: RgbSealDef> {
    #[from]
    #[from(io::Error)]
    Io(IoError),

    /// unrecognized magic bytes {0} in the consignment stream
    #[display(doc_comments)]
    UnrecognizedMagic(String),

    /// unsupported version {0} of the consignment stream
    #[display(doc_comments)]
    UnsupportedVersion(u16),

    /// unknown {0} can't be consumed; please import contract articles first.
    #[display(doc_comments)]
    UnknownContract(ContractId),

    #[from]
    Articles(ArticlesError),

    #[from]
    Decode(DecodeError),

    #[from]
    Verify(VerificationError<Seal::Src>),
}

#[cfg(feature = "fs")]
mod fs {
    use std::fs::File;
    use std::path::Path;

    use sonic_persist_fs::StockFs;
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
