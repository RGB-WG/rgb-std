// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt::Debug;
use std::num::NonZeroU32;

use amplify::confinement::{Confined, LargeOrdSet};
use bp::dbc::{Anchor, Proof};
use bp::{Outpoint, Txid};
use nonasync::persistence::{CloneNoPersistence, PersistenceError, PersistenceProvider};
use rgb::validation::{ResolveWitness, UnsafeHistoryMap, WitnessResolverError};
use rgb::vm::WitnessOrd;
use rgb::{
    validation, AssignmentType, BundleId, ChainNet, ContractId, GraphSeal, Identity, OpId,
    Operation, Opout, OutputSeal, Schema, SchemaId, SecretSeal, Transition, TransitionType,
    UnrelatedTransition,
};
use strict_types::FieldName;

use super::{
    ContractStateRead, Index, IndexError, IndexInconsistency, IndexProvider, IndexReadProvider,
    IndexWriteProvider, MemIndex, MemStash, MemState, PersistedState, Stash, StashDataError,
    StashError, StashInconsistency, StashProvider, StashReadProvider, StashWriteProvider, State,
    StateError, StateInconsistency, StateProvider, StateReadProvider, StateWriteProvider,
    StoreTransaction,
};
use crate::containers::{
    Consignment, ContainerVer, ContentId, Contract, Fascia, Kit, Transfer, TransitionInfoError,
    ValidConsignment, ValidContract, ValidKit, ValidTransfer, WitnessBundle,
};
use crate::contract::{
    BuilderError, ContractBuilder, ContractData, IssuerWrapper, SchemaWrapper, TransitionBuilder,
};
use crate::info::{ContractInfo, SchemaInfo};
use crate::MergeRevealError;

pub type ContractAssignments = HashMap<OutputSeal, HashMap<Opout, PersistedState>>;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum StockError<
    S: StashProvider = MemStash,
    H: StateProvider = MemState,
    P: IndexProvider = MemIndex,
    E: Error = Infallible,
> {
    InvalidInput(E),
    Resolver(String),
    StashRead(<S as StashReadProvider>::Error),
    StashWrite(<S as StashWriteProvider>::Error),
    IndexRead(<P as IndexReadProvider>::Error),
    IndexWrite(<P as IndexWriteProvider>::Error),
    StateRead(<H as StateReadProvider>::Error),
    StateWrite(<H as StateWriteProvider>::Error),

    #[from]
    #[display(doc_comments)]
    /// {0}
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    StashInconsistency(StashInconsistency),

    #[from]
    #[display(doc_comments)]
    /// state for contract {0} is not known.
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    StateInconsistency(StateInconsistency),

    #[from]
    #[display(doc_comments)]
    /// {0}
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    IndexInconsistency(IndexInconsistency),

    #[from]
    StashData(StashDataError),

    /// valid (non-archived) witness is absent in the list of witnesses for a
    /// state transition bundle.
    AbsentValidWitness,

    /// witness {0} can't be resolved: {1}
    WitnessUnresolved(Txid, WitnessResolverError),
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider, E: Error> From<StashError<S>>
    for StockError<S, H, P, E>
{
    fn from(err: StashError<S>) -> Self {
        match err {
            StashError::ReadProvider(err) => Self::StashRead(err),
            StashError::WriteProvider(err) => Self::StashWrite(err),
            StashError::Data(e) => Self::StashData(e),
            StashError::Inconsistency(e) => Self::StashInconsistency(e),
        }
    }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider, E: Error> From<StateError<H>>
    for StockError<S, H, P, E>
{
    fn from(err: StateError<H>) -> Self {
        match err {
            StateError::ReadProvider(err) => Self::StateRead(err),
            StateError::WriteProvider(err) => Self::StateWrite(err),
            StateError::Inconsistency(e) => Self::StateInconsistency(e),
            StateError::Resolver(id, e) => Self::WitnessUnresolved(id, e),
            StateError::AbsentValidWitness => Self::AbsentValidWitness,
        }
    }
}
impl<S: StashProvider, H: StateProvider, P: IndexProvider, E: Error> From<IndexError<P>>
    for StockError<S, H, P, E>
{
    fn from(err: IndexError<P>) -> Self {
        match err {
            IndexError::ReadProvider(err) => Self::IndexRead(err),
            IndexError::WriteProvider(err) => Self::IndexWrite(err),
            IndexError::Inconsistency(e) => Self::IndexInconsistency(e),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ConsignError {
    /// unable to construct consignment: too many signatures provided.
    TooManySignatures,

    /// unable to construct consignment: too many terminals provided.
    TooManyTerminals,

    /// unable to construct consignment: history size too large, resulting in
    /// too many transitions.
    TooManyBundles,

    #[from]
    #[display(inner)]
    MergeReveal(MergeRevealError),

    #[from]
    #[display(inner)]
    Transition(UnrelatedTransition),

    /// the spent state from transition {1} inside bundle {0} is concealed.
    Concealed(BundleId, OpId),
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<ConsignError>
    for StockError<S, H, P, ConsignError>
{
    fn from(err: ConsignError) -> Self { Self::InvalidInput(err) }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<MergeRevealError>
    for StockError<S, H, P, ConsignError>
{
    fn from(err: MergeRevealError) -> Self { Self::InvalidInput(err.into()) }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<UnrelatedTransition>
    for StockError<S, H, P, ConsignError>
{
    fn from(err: UnrelatedTransition) -> Self { Self::InvalidInput(err.into()) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ComposeError {
    /// no outputs available to store state of type {0}
    NoExtraOrChange(AssignmentType),

    /// the provided PSBT doesn't pay any sats to the RGB beneficiary address.
    NoBeneficiaryOutput,

    /// beneficiary output number is given when secret seal is used.
    BeneficiaryVout,

    /// expired invoice.
    InvoiceExpired,

    /// the invoice contains no contract information.
    NoContract,

    /// the invoice requirements can't be fulfilled using available assets or
    /// smart contract state.
    InsufficientState,

    /// the spent UTXOs contain too many seals which can't fit the state
    /// transition input limit.
    TooManyInputs,

    #[from]
    #[display(inner)]
    Transition(TransitionInfoError),

    /// the operation produces too many extra state transitions which can't fit
    /// the container requirements.
    TooManyExtras,

    #[from]
    #[display(inner)]
    Builder(BuilderError),
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<ComposeError>
    for StockError<S, H, P, ComposeError>
{
    fn from(err: ComposeError) -> Self { Self::InvalidInput(err) }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<BuilderError>
    for StockError<S, H, P, ComposeError>
{
    fn from(err: BuilderError) -> Self { Self::InvalidInput(err.into()) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum FasciaError {
    /// bundle {1} for contract {0} contains invalid transition input map.
    InvalidBundle(ContractId, BundleId),
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<FasciaError>
    for StockError<S, H, P, FasciaError>
{
    fn from(err: FasciaError) -> Self { Self::InvalidInput(err) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum InputError {
    #[from]
    Compose(ComposeError),
    #[from]
    Consign(ConsignError),
    #[from]
    Fascia(FasciaError),
}

macro_rules! stock_err_conv {
    ($err1:ty, $err2:ty) => {
        impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<StockError<S, H, P, $err1>>
            for StockError<S, H, P, $err2>
        {
            fn from(err: StockError<S, H, P, $err1>) -> Self {
                match err {
                    StockError::InvalidInput(e) => StockError::InvalidInput(e.into()),
                    StockError::Resolver(e) => StockError::Resolver(e),
                    StockError::StashRead(e) => StockError::StashRead(e),
                    StockError::StashWrite(e) => StockError::StashWrite(e),
                    StockError::IndexRead(e) => StockError::IndexRead(e),
                    StockError::IndexWrite(e) => StockError::IndexWrite(e),
                    StockError::StateRead(e) => StockError::StateRead(e),
                    StockError::StateWrite(e) => StockError::StateWrite(e),
                    StockError::AbsentValidWitness => StockError::AbsentValidWitness,
                    StockError::StashData(e) => StockError::StashData(e),
                    StockError::StashInconsistency(e) => StockError::StashInconsistency(e),
                    StockError::StateInconsistency(e) => StockError::StateInconsistency(e),
                    StockError::IndexInconsistency(e) => StockError::IndexInconsistency(e),
                    StockError::WitnessUnresolved(id, e) => StockError::WitnessUnresolved(id, e),
                }
            }
        }
    };
}

impl From<Infallible> for InputError {
    fn from(_: Infallible) -> Self { unreachable!() }
}
impl From<Infallible> for ComposeError {
    fn from(_: Infallible) -> Self { unreachable!() }
}
impl From<Infallible> for ConsignError {
    fn from(_: Infallible) -> Self { unreachable!() }
}
impl From<Infallible> for FasciaError {
    fn from(_: Infallible) -> Self { unreachable!() }
}

stock_err_conv!(Infallible, ComposeError);
stock_err_conv!(Infallible, ConsignError);
stock_err_conv!(Infallible, FasciaError);
stock_err_conv!(Infallible, InputError);
stock_err_conv!(ComposeError, InputError);
stock_err_conv!(ConsignError, InputError);
stock_err_conv!(FasciaError, InputError);

pub type StockErrorMem<E = Infallible> = StockError<MemStash, MemState, MemIndex, E>;
pub type StockErrorAll<S = MemStash, H = MemState, P = MemIndex> = StockError<S, H, P, InputError>;

#[derive(Debug)]
pub struct Stock<
    S: StashProvider = MemStash,
    H: StateProvider = MemState,
    P: IndexProvider = MemIndex,
> {
    stash: Stash<S>,
    state: State<H>,
    index: Index<P>,
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> CloneNoPersistence for Stock<S, H, P> {
    fn clone_no_persistence(&self) -> Self {
        Self {
            stash: self.stash.clone_no_persistence(),
            state: self.state.clone_no_persistence(),
            index: self.index.clone_no_persistence(),
        }
    }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> Default for Stock<S, H, P>
where
    S: Default,
    H: Default,
    P: Default,
{
    fn default() -> Self {
        Self {
            stash: default!(),
            state: default!(),
            index: default!(),
        }
    }
}

impl Stock {
    #[inline]
    pub fn in_memory() -> Self {
        Self::with(MemStash::in_memory(), MemState::in_memory(), MemIndex::in_memory())
    }
}

impl<S: StashProvider, H: StateProvider, I: IndexProvider> Stock<S, H, I> {
    pub fn load<P>(provider: P, autosave: bool) -> Result<Self, PersistenceError>
    where P: Clone
            + PersistenceProvider<S>
            + PersistenceProvider<H>
            + PersistenceProvider<I>
            + 'static {
        let stash = S::load(provider.clone(), autosave)?;
        let state = H::load(provider.clone(), autosave)?;
        let index = I::load(provider, autosave)?;
        Ok(Self::with(stash, state, index))
    }

    pub fn make_persistent<P>(
        &mut self,
        provider: P,
        autosave: bool,
    ) -> Result<bool, PersistenceError>
    where
        P: Clone
            + PersistenceProvider<S>
            + PersistenceProvider<H>
            + PersistenceProvider<I>
            + 'static,
    {
        let a = self
            .as_stash_provider_mut()
            .make_persistent(provider.clone(), autosave)?;
        let b = self
            .as_state_provider_mut()
            .make_persistent(provider.clone(), autosave)?;
        let c = self
            .as_index_provider_mut()
            .make_persistent(provider, autosave)?;
        Ok(a && b && c)
    }

    pub fn store(&mut self) -> Result<(), PersistenceError> {
        // TODO: Revert on failure

        self.as_stash_provider_mut().store()?;
        self.as_state_provider_mut().store()?;
        self.as_index_provider_mut().store()?;

        Ok(())
    }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> Stock<S, H, P> {
    pub fn with(stash_provider: S, state_provider: H, index_provider: P) -> Self {
        Stock {
            stash: Stash::new(stash_provider),
            state: State::new(state_provider),
            index: Index::new(index_provider),
        }
    }

    #[doc(hidden)]
    pub fn as_stash_provider(&self) -> &S { self.stash.as_provider() }
    #[doc(hidden)]
    pub fn as_state_provider(&self) -> &H { self.state.as_provider() }
    #[doc(hidden)]
    pub fn as_index_provider(&self) -> &P { self.index.as_provider() }

    #[doc(hidden)]
    pub fn as_stash_provider_mut(&mut self) -> &mut S { self.stash.as_provider_mut() }
    #[doc(hidden)]
    pub fn as_state_provider_mut(&mut self) -> &mut H { self.state.as_provider_mut() }
    #[doc(hidden)]
    pub fn as_index_provider_mut(&mut self) -> &mut P { self.index.as_provider_mut() }

    pub fn schemata(&self) -> Result<impl Iterator<Item = SchemaInfo> + '_, StockError<S, H, P>> {
        Ok(self.stash.schemata()?.map(SchemaInfo::with))
    }
    pub fn schema(&self, schema_id: SchemaId) -> Result<&Schema, StockError<S, H, P>> {
        Ok(self.stash.schema(schema_id)?)
    }

    pub fn contracts(
        &self,
    ) -> Result<impl Iterator<Item = ContractInfo> + '_, StockError<S, H, P>> {
        Ok(self.stash.geneses()?.map(ContractInfo::with))
    }

    /// Iterates over ids of all contract assigning state to the provided set of
    /// output seals.
    pub fn contracts_assigning(
        &self,
        outputs: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<impl Iterator<Item = ContractId> + '_, StockError<S, H, P>> {
        let outputs = outputs
            .into_iter()
            .map(|o| o.into())
            .collect::<BTreeSet<_>>();
        Ok(self.index.contracts_assigning(outputs)?)
    }

    #[allow(clippy::type_complexity)]
    fn contract_raw(
        &self,
        contract_id: ContractId,
    ) -> Result<(&Schema, H::ContractRead<'_>, ContractInfo), StockError<S, H, P>> {
        let state = self.state.contract_state(contract_id)?;
        let schema_id = state.schema_id();
        let schema = self.stash.schema(schema_id)?;
        Ok((schema, state, self.contract_info(contract_id)?))
    }

    pub fn contract_info(
        &self,
        contract_id: ContractId,
    ) -> Result<ContractInfo, StockError<S, H, P>> {
        Ok(ContractInfo::with(self.stash.genesis(contract_id)?))
    }

    pub fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<H::ContractRead<'_>, StockError<S, H, P>> {
        self.state
            .contract_state(contract_id)
            .map_err(StockError::from)
    }

    pub fn contract_wrapper<C: IssuerWrapper>(
        &self,
        contract_id: ContractId,
    ) -> Result<C::Wrapper<H::ContractRead<'_>>, StockError<S, H, P>> {
        let contract_data = self.contract_data(contract_id)?;
        Ok(C::Wrapper::with(contract_data))
    }

    /// Returns the contract data for the given contract ID
    pub fn contract_data(
        &self,
        contract_id: ContractId,
    ) -> Result<ContractData<H::ContractRead<'_>>, StockError<S, H, P>> {
        let (schema, state, info) = self.contract_raw(contract_id)?;

        let (types, _) = self.stash.extract(schema)?;

        Ok(ContractData {
            state,
            schema: schema.clone(),
            types,
            info,
        })
    }

    pub fn contract_assignments_for(
        &self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<ContractAssignments, StockError<S, H, P>> {
        let outputs: BTreeSet<Outpoint> = outpoints.into_iter().map(|o| o.into()).collect();

        let state = self.contract_state(contract_id)?;

        let mut res =
            HashMap::<OutputSeal, HashMap<Opout, PersistedState>>::with_capacity(outputs.len());

        for item in state.fungible_all() {
            let outpoint = item.seal.into();
            if outputs.contains::<Outpoint>(&outpoint) {
                res.entry(item.seal)
                    .or_default()
                    .insert(item.opout, PersistedState::Amount(item.state.value.into()));
            }
        }

        for item in state.data_all() {
            let outpoint = item.seal.into();
            if outputs.contains::<Outpoint>(&outpoint) {
                res.entry(item.seal).or_default().insert(
                    item.opout,
                    PersistedState::Data(item.state.value.clone(), item.state.salt),
                );
            }
        }

        for item in state.rights_all() {
            let outpoint = item.seal.into();
            if outputs.contains::<Outpoint>(&outpoint) {
                res.entry(item.seal)
                    .or_default()
                    .insert(item.opout, PersistedState::Void);
            }
        }

        Ok(res)
    }

    pub fn contract_builder(
        &self,
        issuer: impl Into<Identity>,
        schema_id: SchemaId,
        chain_net: ChainNet,
    ) -> Result<ContractBuilder, StockError<S, H, P>> {
        Ok(self
            .stash
            .contract_builder(issuer.into(), schema_id, chain_net)?)
    }

    pub fn transition_builder(
        &self,
        contract_id: ContractId,
        transition_name: impl Into<FieldName>,
    ) -> Result<TransitionBuilder, StockError<S, H, P>> {
        Ok(self
            .stash
            .transition_builder(contract_id, transition_name)?)
    }

    pub fn transition_builder_raw(
        &self,
        contract_id: ContractId,
        transition_type: TransitionType,
    ) -> Result<TransitionBuilder, StockError<S, H, P>> {
        Ok(self
            .stash
            .transition_builder_raw(contract_id, transition_type)?)
    }

    pub fn export_schema(&self, schema_id: SchemaId) -> Result<ValidKit, StockError<S, H, P>> {
        let mut kit = Kit::default();
        let schema = self.schema(schema_id)?;
        kit.schemata.push(schema.clone()).expect("single item");
        let (types, scripts) = self.stash.extract(schema)?;
        kit.scripts
            .extend(scripts.into_values())
            .expect("type guarantees");
        kit.types = types;
        Ok(kit.validate().expect("stock produced invalid kit"))
    }

    pub fn export_contract(
        &self,
        contract_id: ContractId,
    ) -> Result<Contract, StockError<S, H, P, ConsignError>> {
        let consignment = self.consign::<false>(contract_id, [], None, None)?;
        Ok(consignment)
    }

    pub fn transfer(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seal: Option<SecretSeal>,
        witness_id: Option<Txid>,
    ) -> Result<Transfer, StockError<S, H, P, ConsignError>> {
        let consignment = self.consign(contract_id, outputs, secret_seal, witness_id)?;
        Ok(consignment)
    }

    fn consign<const TRANSFER: bool>(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seal: Option<SecretSeal>,
        witness_id: Option<Txid>,
    ) -> Result<Consignment<TRANSFER>, StockError<S, H, P, ConsignError>> {
        let outputs = outputs.as_ref();

        // Initialize signatures with btree map
        let mut signatures = bmap! {};
        // Get genesis signature by contract id
        self.stash
            .sigs_for(&ContentId::Genesis(contract_id))?
            .map(|genesis_sig| {
                signatures.insert(ContentId::Genesis(contract_id), genesis_sig.clone())
            });
        // 1. Collect initial set of anchored bundles
        // 1.1. Get all public outputs
        let mut opouts = self.index.public_opouts(contract_id)?;

        // 1.2. Add outputs requested by the caller
        opouts.extend(
            self.index
                .opouts_by_outputs(contract_id, outputs.iter().copied())?,
        );
        opouts.extend(self.index.opouts_by_terminals(secret_seal.into_iter())?);

        // 1.3. Collect all state transitions assigning state to the provided outpoints
        let mut bundles = BTreeMap::<BundleId, WitnessBundle>::new();
        let mut transitions = BTreeMap::<OpId, Transition>::new();
        let mut terminals = BTreeMap::<BundleId, SecretSeal>::new();
        for opout in opouts {
            if opout.op == contract_id {
                continue; // we skip genesis since it will be present anywhere
            }

            let transition = self.transition(opout.op)?;

            let bundle_id = self.index.bundle_id_for_op(transition.id())?;

            // skip bundles not associated to the terminals witness
            if let Some(witness_id) = witness_id {
                let (mut witness_ids, _) = self.index.bundle_info(bundle_id)?;
                if !witness_ids.any(|w| w == witness_id) {
                    continue;
                }
            }

            transitions.insert(opout.op, transition.clone());
            // 2. Collect secret seals from terminal transitions to add to the consignment terminals
            for typed_assignments in transition.assignments.values() {
                for index in 0..typed_assignments.len_u16() {
                    let seal = typed_assignments.to_confidential_seals()[index as usize];
                    if secret_seal == Some(seal) {
                        let res = terminals.insert(bundle_id, seal);
                        assert_eq!(res, None);
                    }
                }
            }

            if let Entry::Vacant(entry) = bundles.entry(bundle_id) {
                entry.insert(self.witness_bundle(bundle_id)?);
            }
        }

        // 2. Collect all state transitions between terminals and genesis
        let mut ids = vec![];
        for transition in transitions.values() {
            ids.extend(transition.inputs().iter().map(|input| input.prev_out.op));
        }
        while let Some(id) = ids.pop() {
            if id == contract_id {
                continue; // we skip genesis since it will be present anywhere
            }
            let transition = self.transition(id)?;
            ids.extend(transition.inputs().iter().map(|input| input.prev_out.op));
            transitions.insert(id, transition.clone());
            let bundle_id = self.index.bundle_id_for_op(transition.id())?;
            bundles
                .entry(bundle_id)
                .or_insert(self.witness_bundle(bundle_id)?.clone())
                .bundle
                .reveal_transition(transition.clone())?;
        }

        let genesis = self.stash.genesis(contract_id)?.clone();
        // Get schema signature by schema id
        self.stash
            .sigs_for(&ContentId::Schema(genesis.schema_id))?
            .map(|schema_signature| {
                signatures.insert(ContentId::Schema(genesis.schema_id), schema_signature.clone())
            });

        let schema = self.stash.schema(genesis.schema_id)?.clone();

        let bundles = Confined::try_from_iter(bundles.into_values())
            .map_err(|_| ConsignError::TooManyBundles)?;
        let terminals =
            Confined::try_from(terminals).map_err(|_| ConsignError::TooManyTerminals)?;

        let (types, scripts) = self.stash.extract(&schema)?;
        let scripts = Confined::from_iter_checked(scripts.into_values());
        let signatures =
            Confined::try_from(signatures).map_err(|_| ConsignError::TooManySignatures)?;
        // TODO: Conceal everything we do not need
        // TODO: Add known sigs to the consignment

        Ok(Consignment {
            version: ContainerVer::V2,
            transfer: TRANSFER,

            schema,
            genesis,
            terminals,
            bundles,

            signatures,
            types,
            scripts,
        })
    }

    fn store_transaction<E: Error>(
        &mut self,
        f: impl FnOnce(
            &mut Stash<S>,
            &mut State<H>,
            &mut Index<P>,
        ) -> Result<(), StockError<S, H, P, E>>,
    ) -> Result<(), StockError<S, H, P, E>> {
        self.state.begin_transaction()?;
        self.stash
            .begin_transaction()
            .inspect_err(|_| self.stash.rollback_transaction())?;
        self.index.begin_transaction().inspect_err(|_| {
            self.state.rollback_transaction();
            self.stash.rollback_transaction();
        })?;
        f(&mut self.stash, &mut self.state, &mut self.index)?;
        self.index
            .commit_transaction()
            .map_err(StockError::from)
            .and_then(|_| self.state.commit_transaction().map_err(StockError::from))
            .and_then(|_| self.stash.commit_transaction().map_err(StockError::from))
            .inspect_err(|_| {
                self.state.rollback_transaction();
                self.stash.rollback_transaction();
                self.index.rollback_transaction();
            })
    }

    pub fn import_kit(&mut self, kit: ValidKit) -> Result<validation::Status, StockError<S, H, P>> {
        let (kit, status) = kit.split();
        self.stash.begin_transaction()?;
        self.stash.consume_kit(kit)?;
        self.stash.commit_transaction()?;
        Ok(status)
    }

    pub fn import_contract<R: ResolveWitness>(
        &mut self,
        contract: ValidContract,
        resolver: R,
    ) -> Result<validation::Status, StockError<S, H, P>> {
        self.consume_consignment(contract, resolver)
    }

    pub fn accept_transfer<R: ResolveWitness>(
        &mut self,
        contract: ValidTransfer,
        resolver: R,
    ) -> Result<validation::Status, StockError<S, H, P>> {
        self.consume_consignment(contract, resolver)
    }

    fn consume_consignment<R: ResolveWitness, const TRANSFER: bool>(
        &mut self,
        consignment: ValidConsignment<TRANSFER>,
        resolver: R,
    ) -> Result<validation::Status, StockError<S, H, P>> {
        let (mut consignment, status) = consignment.split();

        consignment = self.stash.resolve_secrets(consignment)?;
        self.store_transaction(move |stash, state, index| {
            state.update_from_consignment(&consignment, &resolver)?;
            index.index_consignment(&consignment)?;
            stash.consume_consignment(consignment)?;
            Ok(())
        })?;

        Ok(status)
    }

    /// Imports fascia into the stash, index and inventory.
    ///
    /// Part of the transfer workflow. Called once PSBT is completed and an RGB
    /// fascia containing anchor and all state transitions is exported from
    /// it.
    ///
    /// Must be called before the consignment is created, when witness
    /// transaction is not yet mined.
    pub fn consume_fascia<R: ResolveWitness>(
        &mut self,
        fascia: Fascia,
        resolver: R,
    ) -> Result<(), StockError<S, H, P, FasciaError>> {
        self.store_transaction(move |stash, state, index| {
            let witness_id = fascia.witness_id();
            stash.consume_witness(&fascia.seal_witness)?;

            for (contract_id, bundle) in fascia.into_bundles() {
                let ids1 = bundle
                    .known_transitions
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>();
                let ids2 = bundle
                    .input_map
                    .values()
                    .flat_map(|opids| opids.to_unconfined())
                    .collect::<BTreeSet<_>>();
                if !ids1.is_subset(&ids2) {
                    return Err(FasciaError::InvalidBundle(contract_id, bundle.bundle_id()).into());
                }

                index.index_bundle(contract_id, &bundle, witness_id)?;
                state.update_from_bundle(contract_id, &bundle, witness_id, &resolver)?;
                stash.consume_bundle(bundle)?;
            }
            Ok(())
        })
    }

    fn transition(&self, opid: OpId) -> Result<&Transition, StockError<S, H, P, ConsignError>> {
        let bundle_id = self.index.bundle_id_for_op(opid)?;
        let bundle = self.stash.bundle(bundle_id)?;
        bundle
            .known_transitions
            .get(&opid)
            .ok_or(ConsignError::Concealed(bundle_id, opid).into())
    }

    fn witness_bundle(&self, bundle_id: BundleId) -> Result<WitnessBundle, StockError<S, H, P>> {
        let (witness_ids, contract_id) = self.index.bundle_info(bundle_id)?;
        let bundle = self.stash.bundle(bundle_id)?.clone();
        let (witness_id, _) = self.state.select_valid_witness(witness_ids)?;
        let witness = self.stash.witness(witness_id)?;
        let pub_witness = witness.public.clone();
        let Ok(mpc_proof) = witness.merkle_block.to_merkle_proof(contract_id.into()) else {
            return Err(StashInconsistency::WitnessMissesContract(
                witness_id,
                bundle_id,
                contract_id,
                witness.dbc_proof.method(),
            )
            .into());
        };
        let anchor = Anchor::new(mpc_proof, witness.dbc_proof.clone());

        // TODO: Conceal all transitions except the one we need

        Ok(WitnessBundle::with(pub_witness, anchor, bundle))
    }

    pub fn store_secret_seal(&mut self, seal: GraphSeal) -> Result<bool, StockError<S, H, P>> {
        Ok(self.stash.store_secret_seal(seal)?)
    }

    fn set_bundles_as_invalid(&mut self, bundle_id: &BundleId) -> Result<(), StockError<S, H, P>> {
        // add bundle to set of invalid bundles
        self.state.update_bundle(*bundle_id, false)?;
        let bundle = self.stash.bundle(*bundle_id)?.clone();
        // recursively set all bundle descendants as invalid
        for opid in bundle.known_transitions.keys() {
            let children_bundle_ids = match self.index.bundle_ids_children_of_op(*opid) {
                Ok(bundle_ids) => bundle_ids,
                Err(IndexError::Inconsistency(IndexInconsistency::BundleAbsent(_))) => {
                    // this transition has no children yet
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            };

            for child_bundle_id in children_bundle_ids {
                self.set_bundles_as_invalid(&child_bundle_id)?;
            }
        }
        Ok(())
    }

    fn maybe_update_bundles_as_valid(
        &mut self,
        bundle_id: &BundleId,
        invalid_bundles: &mut LargeOrdSet<BundleId>,
        maybe_became_valid_bundle_ids: &mut BTreeSet<BundleId>,
    ) -> Result<bool, StockError<S, H, P>> {
        let bundle = self.stash.bundle(*bundle_id)?.clone();
        let mut valid = true;
        // recursively visit bundle ancestors
        for transition in bundle.known_transitions.values() {
            for input in &transition.inputs {
                let input_opid = input.prev_out.op;
                let input_bundle_id = match self.index.bundle_id_for_op(input_opid) {
                    Ok(id) => Some(id),
                    Err(IndexError::Inconsistency(IndexInconsistency::BundleAbsent(_))) => {
                        // reached genesis
                        None
                    }
                    Err(e) => return Err(e.into()),
                };

                if let Some(input_bundle_id) = input_bundle_id {
                    // process parent first if its status is also uncertain
                    if maybe_became_valid_bundle_ids.contains(&input_bundle_id) {
                        valid = self.maybe_update_bundles_as_valid(
                            &input_bundle_id,
                            invalid_bundles,
                            maybe_became_valid_bundle_ids,
                        )?;
                    // a single invalid parent is enough to consider the bundle as invalid
                    } else if invalid_bundles.contains(&input_bundle_id) {
                        valid = false;
                        break;
                    }
                }
            }
        }

        // remove bundle since at this point we are sure about its status
        maybe_became_valid_bundle_ids.remove(bundle_id);

        if valid {
            // remove bundle from set of invalid bundles
            self.state.update_bundle(*bundle_id, true)?;
            invalid_bundles.remove(bundle_id).unwrap();
            // recursively visit bundle descendants to check if they became valid as well
            for (opid, _transition) in bundle.known_transitions {
                let children_bundle_ids = match self.index.bundle_ids_children_of_op(opid) {
                    Ok(bundle_ids) => bundle_ids,
                    Err(IndexError::Inconsistency(IndexInconsistency::BundleAbsent(_))) => {
                        // this transition has no children yet
                        tiny_bset![]
                    }
                    Err(e) => return Err(e.into()),
                };
                for child_bundle_id in children_bundle_ids {
                    self.maybe_update_bundles_as_valid(
                        &child_bundle_id,
                        invalid_bundles,
                        maybe_became_valid_bundle_ids,
                    )?;
                }
            }
        }

        Ok(valid)
    }

    fn update_witness_ord(
        &mut self,
        resolver: impl ResolveWitness,
        id: &Txid,
        ord: &mut WitnessOrd,
        became_invalid_witnesses: &mut BTreeMap<Txid, BTreeSet<BundleId>>,
        became_valid_witnesses: &mut BTreeMap<Txid, BTreeSet<BundleId>>,
    ) -> Result<(), StockError<S, H, P>> {
        let new = resolver
            .resolve_pub_witness_ord(*id)
            .map_err(|e| StockError::WitnessUnresolved(*id, e))?;
        let changed = *ord != new;
        if changed {
            let bundle_valid = match (*ord, new) {
                (WitnessOrd::Archived, _) => Some(true),
                (_, WitnessOrd::Archived) => Some(false),
                _ => None,
            };
            // save witnesses that became valid or invalid
            if let Some(valid) = bundle_valid {
                let seal_witness = self.stash.witness(*id)?;
                let bundle_ids: BTreeSet<_> = seal_witness.known_bundle_ids().collect();
                if valid {
                    became_valid_witnesses.insert(*id, bundle_ids);
                } else {
                    became_invalid_witnesses.insert(*id, bundle_ids);
                }
            }
            // save the changed witness ord
            self.state.upsert_witness(*id, new)?;
            *ord = new
        }
        Ok(())
    }

    pub fn update_witnesses(
        &mut self,
        resolver: impl ResolveWitness,
        after_height: u32,
        force_witnesses: Vec<Txid>,
    ) -> Result<UpdateRes, StockError<S, H, P>> {
        let after_height = NonZeroU32::new(after_height).unwrap_or(NonZeroU32::MIN);
        let mut succeeded = 0;
        let mut failed = map![];
        self.state.begin_transaction()?;
        let witnesses = self.as_state_provider().witnesses();
        let mut witnesses = witnesses.release();
        let mut became_invalid_witnesses = bmap!();
        let mut became_valid_witnesses = bmap!();
        // 1. update witness ord of all witnesses
        for (id, ord) in &mut witnesses {
            if matches!(ord, WitnessOrd::Ignored) && !force_witnesses.contains(id) {
                continue;
            }
            if matches!(ord, WitnessOrd::Mined(pos) if pos.height() < after_height) {
                continue;
            }
            match self.update_witness_ord(
                &resolver,
                id,
                ord,
                &mut became_invalid_witnesses,
                &mut became_valid_witnesses,
            ) {
                Ok(()) => {
                    succeeded += 1;
                }
                Err(err) => {
                    failed.insert(*id, err.to_string());
                }
            }
        }

        // 2. set invalidity of bundles
        for bundle_ids in became_invalid_witnesses.values() {
            for bundle_id in bundle_ids {
                let bundle_witness_ids: BTreeSet<Txid> =
                    self.index.bundle_info(*bundle_id)?.0.collect();
                // set bundle as invalid only if there are no valid witnesses associated to it
                if bundle_witness_ids
                    .iter()
                    .all(|id| !witnesses.get(id).unwrap().is_valid())
                {
                    // set this bundle and all its descendants as invalid
                    self.set_bundles_as_invalid(bundle_id)?;
                }
            }
        }

        // 3. set validity of bundles
        let mut maybe_became_valid_bundle_ids = bset!();
        // get all bundles that became invalid and ones that were already invalid
        let mut invalid_bundles_pre = self.as_state_provider().invalid_bundles();
        for bundle_ids in became_valid_witnesses.values() {
            // store bundles that may become valid (to be sure its ancestors are checked)
            maybe_became_valid_bundle_ids.extend(bundle_ids);
        }
        for bundle_ids in became_valid_witnesses.values() {
            for bundle_id in bundle_ids {
                // check if this bundle and its descendants are now valid
                self.maybe_update_bundles_as_valid(
                    bundle_id,
                    &mut invalid_bundles_pre,
                    &mut maybe_became_valid_bundle_ids,
                )?;
            }
        }

        self.state.commit_transaction()?;
        Ok(UpdateRes { succeeded, failed })
    }

    fn _check_bundle_history(
        &self,
        bundle_id: &BundleId,
        safe_height: NonZeroU32,
        contract_history: &mut HashMap<ContractId, HashMap<u32, HashSet<Txid>>>,
    ) -> Result<(), StockError<S, H, P>> {
        let (bundle_witness_ids, contract_id) = self.index.bundle_info(*bundle_id)?;
        let (witness_id, ord) = self.state.select_valid_witness(bundle_witness_ids)?;
        match ord {
            WitnessOrd::Mined(witness_pos) => {
                let witness_height = witness_pos.height();
                if witness_height > safe_height {
                    contract_history
                        .entry(contract_id)
                        .or_default()
                        .entry(witness_height.into())
                        .or_default()
                        .insert(witness_id);
                }
            }
            WitnessOrd::Tentative | WitnessOrd::Ignored | WitnessOrd::Archived => {
                contract_history
                    .entry(contract_id)
                    .or_default()
                    .entry(0)
                    .or_default()
                    .insert(witness_id);
            }
        }

        // recursively check bundle ancestors
        let bundle = self.stash.bundle(*bundle_id)?.clone();
        for transition in bundle.known_transitions.values() {
            for input in &transition.inputs {
                let input_opid = input.prev_out.op;
                let input_bundle_id = match self.index.bundle_id_for_op(input_opid) {
                    Ok(id) => Some(id),
                    Err(IndexError::Inconsistency(IndexInconsistency::BundleAbsent(_))) => {
                        // reached genesis
                        None
                    }
                    Err(e) => return Err(e.into()),
                };

                if let Some(input_bundle_id) = input_bundle_id {
                    self._check_bundle_history(&input_bundle_id, safe_height, contract_history)?;
                }
            }
        }

        Ok(())
    }

    pub fn get_outpoint_unsafe_history(
        &self,
        outpoint: Outpoint,
        safe_height: NonZeroU32,
    ) -> Result<HashMap<ContractId, UnsafeHistoryMap>, StockError<S, H, P>> {
        let mut contract_history: HashMap<ContractId, HashMap<u32, HashSet<Txid>>> = HashMap::new();

        for id in self.contracts_assigning([outpoint])? {
            let state = self.contract_assignments_for(id, [outpoint])?;
            for opid in state
                .iter()
                .flat_map(|(_, assigns)| assigns.keys().map(|opout| opout.op))
            {
                let bundle_id = self.index.bundle_id_for_op(opid)?;
                self._check_bundle_history(&bundle_id, safe_height, &mut contract_history)?;
            }
        }

        Ok(contract_history)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct UpdateRes {
    pub succeeded: usize,
    pub failed: HashMap<Txid, String>,
}

#[cfg(test)]
mod test {
    use baid64::FromBaid64Str;
    use bp::Vout;
    use commit_verify::{Conceal, DigestExt, Sha256};

    use super::*;
    use crate::containers::ConsignmentExt;

    #[test]
    fn test_consign() {
        let mut stock = Stock::in_memory();
        let seal = GraphSeal::new_random_vout(Vout::from_u32(0));
        let secret_seal = seal.conceal();

        stock.store_secret_seal(seal).unwrap();
        let contract_id =
            ContractId::from_baid64_str("rgb:qFuT6DN8-9AuO95M-7R8R8Mc-AZvs7zG-obum1Va-BRnweKk")
                .unwrap();
        if let Ok(transfer) = stock.consign::<true>(contract_id, [], Some(secret_seal), None) {
            println!("{:?}", transfer)
        }
    }

    #[test]
    fn test_export_contract() {
        let stock = Stock::in_memory();
        let contract_id =
            ContractId::from_baid64_str("rgb:qFuT6DN8-9AuO95M-7R8R8Mc-AZvs7zG-obum1Va-BRnweKk")
                .unwrap();
        if let Ok(contract) = stock.export_contract(contract_id) {
            println!("{:?}", contract.contract_id())
        }
    }

    #[test]
    fn test_export_schema() {
        let stock = Stock::in_memory();
        let hasher = Sha256::default();
        let schema_id = SchemaId::from(hasher);
        if let Ok(schema) = stock.export_schema(schema_id) {
            println!("{:?}", schema.kit_id())
        }
    }

    #[test]
    fn test_transition_builder() {
        let stock = Stock::in_memory();
        let hasher = Sha256::default();

        let bytes_hash = hasher.finish();
        let contract_id = ContractId::copy_from_slice(bytes_hash).unwrap();

        if let Ok(builder) = stock.transition_builder(contract_id, "transfer") {
            println!("{:?}", builder.transition_type())
        }
    }
}
