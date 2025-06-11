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
use amplify::{IoError, MultiError};
use chrono::{DateTime, Utc};
use commit_verify::{ReservedBytes, StrictHash};
use hypersonic::{
    AcceptError, Articles, AuthToken, CallParams, CellAddr, Codex, Consensus, ContractId,
    CoreParams, DataCell, EffectiveState, IssueError, IssueParams, Ledger, LibRepo, Memory,
    MethodName, NamedState, Operation, Opid, SemanticError, Semantics, SigBlob, StateAtom,
    StateName, Stock, Transition,
};
use indexmap::{IndexMap, IndexSet};
use rgb::{
    ContractApi, ContractVerify, OperationSeals, ReadOperation, RgbSeal, RgbSealDef,
    VerificationError,
};
use single_use_seals::{ClientSideWitness, PublishedWitness, SealWitness};
use strict_encoding::{
    DecodeError, ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter,
    TypeName, TypedRead, WriteRaw,
};
use strict_types::StrictVal;

use crate::{
    parse_consignment, Consignment, ContractMeta, Identity, Issue, Issuer, IssuerError, IssuerSpec,
    OpRels, Pile, VerifiedOperation, Witness, WitnessStatus,
};

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

/// Element of the contract owned state, carrying information about its confirmation status.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "Seal: serde::Serialize + for<'d> serde::Deserialize<'d>")
)]
pub struct OwnedState<Seal> {
    /// Operation output defining this element of owned state.
    pub addr: CellAddr,

    /// State assignment.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub assignment: Assignment<Seal>,

    /// Status of the state: the maximal confirmation depth for the whole history of operations
    /// leading to this status, since genesis.
    ///
    /// If any operation has known multiple witnesses (related to RBF'ed transactions or lightning
    /// channels), the best confirmation is used for that specific operation (i.e., the deepest
    /// mined).
    ///
    /// Formally, if $H$ is a set of all operations in the history between genesis and this state,
    /// and $W_o$ is a set of all witnesses for operation $o \in H$, the status here is defined as
    /// $max_{o \in H} min_{w \in W_o} status(w)$.
    pub status: WitnessStatus,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ImmutableState {
    pub addr: CellAddr,
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
    pub immutable: BTreeMap<StateName, Vec<ImmutableState>>,
    pub owned: BTreeMap<StateName, Vec<OwnedState<Seal>>>,
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
                        .map(|owned| OwnedState {
                            addr: owned.addr,
                            assignment: Assignment {
                                seal: f(owned.assignment.seal),
                                data: owned.assignment.data,
                            },
                            status: owned.status,
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
                        .filter_map(|owned| {
                            Some(OwnedState {
                                addr: owned.addr,
                                assignment: Assignment {
                                    seal: f(owned.assignment.seal)?,
                                    data: owned.assignment.data,
                                },
                                status: owned.status,
                            })
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
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound = "Seal: serde::Serialize + for<'d> serde::Deserialize<'d>"
    )
)]
pub struct CreateParams<Seal: Clone> {
    pub issuer: IssuerSpec,
    pub consensus: Consensus,
    pub testnet: bool,
    pub method: MethodName,
    pub name: TypeName,
    pub timestamp: Option<DateTime<Utc>>,
    pub global: Vec<NamedState<StateAtom>>,
    pub owned: Vec<NamedState<Assignment<EitherSeal<Seal>>>>,
}

impl<Seal: Clone> CreateParams<Seal> {
    pub fn new_testnet(
        issuer: impl Into<IssuerSpec>,
        consensus: Consensus,
        name: impl Into<TypeName>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
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
    /// Initializes contract from contract articles, consignment and a persistence configuration.
    pub fn with(
        articles: Articles,
        consignment: Consignment<P::Seal>,
        conf: S::Conf,
    ) -> Result<Self, MultiError<ConsumeError<<P::Seal as RgbSeal>::Definition>, S::Error, P::Error>>
    where
        P::Conf: From<S::Conf>,
        <P::Seal as RgbSeal>::Client: StrictDecode,
        <P::Seal as RgbSeal>::Published: StrictDecode,
        <P::Seal as RgbSeal>::WitnessId: StrictDecode,
    {
        let contract_id = articles.contract_id();
        let genesis_opid = articles.genesis_opid();
        let ledger = Ledger::new(articles, conf)
            .map_err(MultiError::with_third)
            .map_err(MultiError::from_other_a)?;
        let conf: S::Conf = ledger.config();
        let mut pile = P::new(conf.into()).map_err(MultiError::C)?;
        pile.add_seals(genesis_opid, none!());
        let mut contract = Self { ledger, pile, contract_id };
        contract
            .evaluate_commit(consignment.into_operations())
            .map_err(MultiError::from_a)?;
        Ok(contract)
    }

    pub fn issue(
        issuer: Issuer,
        params: CreateParams<<P::Seal as RgbSeal>::Definition>,
        conf: impl FnOnce(&Articles) -> Result<S::Conf, S::Error>,
    ) -> Result<Self, MultiError<IssuerError, S::Error, P::Error>>
    where
        P::Conf: From<S::Conf>,
    {
        if !params.issuer.check(issuer.issuer_id()) {
            return Err(MultiError::A(IssuerError::IssuerMismatch));
        }

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
            issuer: params.issuer,
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
        let conf = conf(&articles).map_err(MultiError::B)?;
        let ledger = Ledger::new(articles, conf)
            .map_err(MultiError::with_third)
            .map_err(MultiError::from_other_a)?;
        let conf: S::Conf = ledger.config();
        let contract_id = ledger.contract_id();

        // Init seals
        let mut pile = P::new(conf.into()).map_err(MultiError::C)?;
        pile.add_seals(ledger.articles().genesis_opid(), seals);

        Ok(Self { ledger, pile, contract_id })
    }

    pub fn load(
        stock_conf: S::Conf,
        pile_conf: P::Conf,
    ) -> Result<Self, MultiError<S::Error, P::Error>> {
        let ledger = Ledger::load(stock_conf).map_err(MultiError::A)?;
        let contract_id = ledger.contract_id();
        let pile = P::load(pile_conf).map_err(MultiError::B)?;
        Ok(Self { ledger, pile, contract_id })
    }

    /// Get the best mining status for a given operation ("best" means "the most deeply mined").
    fn witness_status(&self, opid: Opid) -> WitnessStatus {
        self.pile
            .op_witness_ids(opid)
            .map(|wid| self.pile.witness_status(wid))
            // "best" means "the most deeply mined"
            .reduce(|best, other| best.best(other))
            .unwrap_or(WitnessStatus::Genesis)
    }

    fn retrieve(&self, opid: Opid) -> Option<SealWitness<P::Seal>> {
        let (status, wid) = self
            .pile
            .op_witness_ids(opid)
            .map(|wid| (self.pile.witness_status(wid), wid))
            .reduce(|best, other| if best.0.is_better(other.0) { best } else { other })?;
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

    /// Get the contract state.
    ///
    /// The call does not recompute the contract state, but does a seal resolution,
    /// taking into account the status of the witnesses in the whole history.
    pub fn state(&self) -> ContractState<P::Seal> {
        let mut cache = bmap! {};
        let mut ancestor_cache = bmap! {};
        let mut cached_status = |opid: Opid| {
            *cache
                .entry(opid)
                .or_insert_with(|| self.witness_status(opid))
        };
        let mut get_status = |opid: Opid, or: WitnessStatus| {
            (*ancestor_cache.entry(opid).or_insert_with(|| {
                self.ledger
                    .ancestors([opid])
                    .map(|ancestor| self.witness_status(ancestor))
                    .fold(WitnessStatus::Genesis, |worst, other| worst.worst(other))
            }))
            .worst(or)
        };
        let state = self.ledger.state().main.clone();
        let mut owned = bmap! {};
        for (name, map) in state.owned {
            let mut state = vec![];
            for (addr, data) in map {
                let Some(seal) = self.pile.seal(addr) else {
                    continue;
                };
                if let Some(seal) = seal.to_src() {
                    state.push(OwnedState {
                        addr,
                        assignment: Assignment { seal, data },
                        status: get_status(addr.opid, cached_status(addr.opid)),
                    });
                } else {
                    // We insert a copy of state for each of the witnesses created for the operation
                    for wid in self.pile.op_witness_ids(addr.opid) {
                        state.push(OwnedState {
                            addr,
                            assignment: Assignment { seal: seal.resolve(wid), data: data.clone() },
                            status: get_status(addr.opid, self.pile.witness_status(wid)),
                        });
                    }
                }
            }
            owned.insert(name, state);
        }
        let mut immutable = bmap! {};
        for (name, map) in state.global {
            let mut state = vec![];
            for (addr, data) in map {
                let status = get_status(addr.opid, cached_status(addr.opid));
                state.push(ImmutableState { addr, data, status });
            }
            immutable.insert(name, state);
        }
        ContractState { immutable, owned, aggregated: state.aggregated }
    }

    pub fn full_state(&self) -> &EffectiveState { self.ledger.state() }

    /// Synchronize the status of all witnesses and single-use seal definitions.
    ///
    /// # Panics
    ///
    /// If the contract id is not known.
    pub fn sync(
        &mut self,
        changed: impl IntoIterator<Item = (<P::Seal as RgbSeal>::WitnessId, WitnessStatus)>,
    ) -> Result<(), MultiError<AcceptError, S::Error>> {
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
        self.ledger.rollback(roll_back).map_err(MultiError::B)?;
        // Ledger has already committed as a part of `rollback`
        self.pile.commit_transaction();

        self.ledger.forward(forward)?;
        // Ledger has already committed as a part of `forward`
        self.pile.commit_transaction();

        Ok(())
    }

    /// Do a call to the contract method, creating and operation.
    ///
    /// The operation is automatically included in the contract history.
    ///
    /// The state of the contract is not automatically updated, but on the next update it will
    /// reflect the call results.
    pub fn call(
        &mut self,
        call: CallParams,
        seals: SmallOrdMap<u16, <P::Seal as RgbSeal>::Definition>,
    ) -> Result<Operation, MultiError<AcceptError, S::Error>> {
        let opid = self.ledger.call(call)?;
        let operation = self.ledger.operation(opid);
        debug_assert_eq!(operation.opid(), opid);
        self.pile.add_seals(opid, seals);
        debug_assert_eq!(operation.contract_id, self.contract_id());
        Ok(operation)
    }

    /// Include an operation and its witness to the history of known operations and the contract
    /// state.
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

    fn aux<W: WriteRaw>(
        &self,
        opid: Opid,
        op: &Operation,
        mut writer: StrictWriter<W>,
    ) -> io::Result<StrictWriter<W>> {
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
    }

    /// Export a contract to a strictly encoded stream.
    ///
    /// # Errors
    ///
    /// If the output stream failures, like when the stream cannot accept more data or got
    /// disconnected.
    pub fn export(&self, writer: StrictWriter<impl WriteRaw>) -> io::Result<()>
    where
        <P::Seal as RgbSeal>::Client: StrictDumb + StrictEncode,
        <P::Seal as RgbSeal>::Published: StrictDumb + StrictEncode,
        <P::Seal as RgbSeal>::WitnessId: StrictEncode,
    {
        self.ledger
            .export_all_aux(writer, |opid, op, writer| self.aux(opid, op, writer))
    }

    /// Create a consignment with a history from the genesis to each of the `terminals`, and
    /// serialize it to a strictly encoded stream `writer`.
    ///
    /// # Errors
    ///
    /// If the output stream failures, like when the stream cannot accept more data or got
    /// disconnected.
    pub fn consign(
        &self,
        terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        writer: StrictWriter<impl WriteRaw>,
    ) -> io::Result<()>
    where
        <P::Seal as RgbSeal>::Client: StrictDumb + StrictEncode,
        <P::Seal as RgbSeal>::Published: StrictDumb + StrictEncode,
        <P::Seal as RgbSeal>::WitnessId: StrictEncode,
    {
        self.ledger
            .export_aux(terminals, writer, |opid, op, writer| self.aux(opid, op, writer))
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
        reader: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(&Operation) -> BTreeMap<u16, <P::Seal as RgbSeal>::Definition>,
        sig_validator: impl FnOnce(StrictHash, &Identity, &SigBlob) -> Result<(), E>,
    ) -> Result<(), MultiError<ConsumeError<<P::Seal as RgbSeal>::Definition>, S::Error>>
    where
        <P::Seal as RgbSeal>::Client: StrictDecode,
        <P::Seal as RgbSeal>::Published: StrictDecode,
        <P::Seal as RgbSeal>::WitnessId: StrictDecode,
    {
        let contract_id = parse_consignment(reader).map_err(MultiError::from_a)?;
        if contract_id != self.contract_id() {
            return Err(MultiError::A(ConsumeError::UnknownContract(contract_id)));
        }
        self.consume_internal(reader, seal_resolver, sig_validator)
    }

    pub(crate) fn consume_internal<E>(
        &mut self,
        reader: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(&Operation) -> BTreeMap<u16, <P::Seal as RgbSeal>::Definition>,
        sig_validator: impl FnOnce(StrictHash, &Identity, &SigBlob) -> Result<(), E>,
    ) -> Result<(), MultiError<ConsumeError<<P::Seal as RgbSeal>::Definition>, S::Error>>
    where
        <P::Seal as RgbSeal>::Client: StrictDecode,
        <P::Seal as RgbSeal>::Published: StrictDecode,
        <P::Seal as RgbSeal>::WitnessId: StrictDecode,
    {
        let articles = (|| -> Result<Articles, ConsumeError<_>> {
            // Read and ignore the extension block
            let ext_blocks = u8::strict_decode(reader)?;
            for _ in 0..ext_blocks {
                let len = u16::strict_decode(reader)?;
                let r = unsafe { reader.raw_reader() };
                let _ = r.read_raw::<{ u16::MAX as usize }>(len as usize)?;
            }

            // We need to read articles field by field since we have to evaluate genesis separately
            let semantics = Semantics::strict_decode(reader)?;
            let sig = Option::<SigBlob>::strict_decode(reader)?;

            let issue_version = ReservedBytes::<1>::strict_decode(reader)?;
            let meta = ContractMeta::strict_decode(reader)?;
            let codex = Codex::strict_decode(reader)?;

            let op_reader = OpReader {
                stream: reader,
                seal_resolver,
                // We start with this hardcoded value to signal that we need to read the actual
                // count right after the genesis (first operation).
                count: u32::MAX,
                _phantom: PhantomData,
            };
            self.evaluate_commit(op_reader)?;

            // We need to clone due to a borrow checker.
            let genesis = self.ledger.articles().genesis().clone();
            let issue = Issue { version: issue_version, meta, codex, genesis };
            let articles = Articles::with(semantics, issue, sig, sig_validator)?;

            Ok(articles)
        })()
        .map_err(MultiError::A)?;

        // Here we do not check for the end of the stream,
        // so in the future we can have arbitrary extensions
        // put here with no backward compatibility issues.

        self.ledger
            .upgrade_apis(articles)
            .map_err(MultiError::from_other_a)?;
        Ok(())
    }

    pub(crate) fn evaluate_commit<R: ReadOperation<Seal = P::Seal>>(
        &mut self,
        reader: R,
    ) -> Result<(), VerificationError<P::Seal>>
    where
        <P::Seal as RgbSeal>::Client: StrictDecode,
        <P::Seal as RgbSeal>::Published: StrictDecode,
        <P::Seal as RgbSeal>::WitnessId: StrictDecode,
    {
        self.evaluate(reader)?;
        self.ledger.commit_transaction();
        self.pile.commit_transaction();
        Ok(())
    }
}

pub struct OpReader<
    'r,
    Seal: RgbSeal,
    R: ReadRaw,
    F: FnMut(&Operation) -> BTreeMap<u16, Seal::Definition>,
> {
    stream: &'r mut StrictReader<R>,
    count: u32,
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
        if self.count == 0 {
            return Result::<_, DecodeError>::Ok(None);
        }
        let operation = Operation::strict_decode(self.stream)?;

        let mut defined_seals = SmallOrdMap::strict_decode(self.stream)?;
        defined_seals
            .extend((self.seal_resolver)(&operation))
            .map_err(|_| {
                DecodeError::DataIntegrityError(format!(
                    "too many seals defined for the operation {}",
                    operation.opid()
                ))
            })?;

        let witness = Option::<SealWitness<Seal>>::strict_decode(self.stream)?;

        // We start with this hardcoded value to signal that we need to read the actual
        // count right after the genesis (first operation).
        if self.count == u32::MAX {
            self.count = u32::strict_decode(self.stream)?;
        } else {
            self.count -= 1;
        }

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

    /// unknown {0} can't be consumed; please import contract articles first.
    #[display(doc_comments)]
    UnknownContract(ContractId),

    #[from]
    Semantics(SemanticError),

    #[from]
    Decode(DecodeError),

    #[from]
    Verify(VerificationError<Seal::Src>),

    #[from]
    #[from(IssueError)]
    // FIXME
    Issue(IssuerError),
}

#[cfg(feature = "binfile")]
mod fs {
    use std::path::Path;

    use binfile::BinFile;
    use strict_encoding::{StreamWriter, StrictDumb, StrictEncode};

    use super::*;
    use crate::{CONSIGN_MAGIC_NUMBER, CONSIGN_VERSION};

    impl<S: Stock, P: Pile> Contract<S, P> {
        /// Export a contract to a file at `path`.
        ///
        /// # Errors
        ///
        /// If writing to the file failures, like when the file already exists, there is no write
        /// access to it, or no sufficient disk space.
        pub fn export_to_file(&self, path: impl AsRef<Path>) -> io::Result<()>
        where
            <P::Seal as RgbSeal>::Client: StrictDumb + StrictEncode,
            <P::Seal as RgbSeal>::Published: StrictDumb + StrictEncode,
            <P::Seal as RgbSeal>::WitnessId: StrictEncode,
        {
            let file = BinFile::<CONSIGN_MAGIC_NUMBER, CONSIGN_VERSION>::create_new(path)?;
            let writer = StrictWriter::with(StreamWriter::new::<{ usize::MAX }>(file));
            self.export(writer)
        }

        /// Create a consignment with a history from the genesis to each of the `terminals`, and
        /// serialize it to a `file`.
        ///
        /// # Errors
        ///
        /// If writing to the file failures, like when the file already exists, there is no write
        /// access to it, or no sufficient disk space.
        pub fn consign_to_file(
            &self,
            path: impl AsRef<Path>,
            terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        ) -> io::Result<()>
        where
            <P::Seal as RgbSeal>::Client: StrictDumb + StrictEncode,
            <P::Seal as RgbSeal>::Published: StrictDumb + StrictEncode,
            <P::Seal as RgbSeal>::WitnessId: StrictEncode,
        {
            let file = BinFile::<CONSIGN_MAGIC_NUMBER, CONSIGN_VERSION>::create_new(path)?;
            let writer = StrictWriter::with(StreamWriter::new::<{ usize::MAX }>(file));
            self.consign(terminals, writer)
        }
    }
}
