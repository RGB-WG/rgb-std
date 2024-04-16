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

use std::cmp::Ordering;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt::Debug;

use amplify::confinement::{Confined, U24};
use bp::seals::txout::CloseMethod;
use bp::Vout;
use chrono::Utc;
use commit_verify::Conceal;
use invoice::{Amount, Beneficiary, InvoiceState, NonFungible, RgbInvoice};
use rgb::{
    validation, AssignmentType, BlindingFactor, BundleId, ContractHistory, ContractId,
    ContractState, DbcProof, EAnchor, GraphSeal, OpId, Operation, Opout, SchemaId, SecretSeal,
    Transition, WitnessAnchor, XChain, XOutpoint, XOutputSeal, XWitnessId,
};
use strict_encoding::FieldName;

use super::{
    Index, IndexError, IndexInconsistency, IndexProvider, IndexReadProvider, IndexWriteProvider,
    MemIndex, MemStash, MemState, PersistedState, SchemaIfaces, Stash, StashDataError, StashError,
    StashInconsistency, StashProvider, StashReadProvider, StashWriteProvider, StateProvider,
    StateReadProvider, StateUpdateError, StateWriteProvider,
};
use crate::accessors::{MergeRevealError, RevealError};
use crate::containers::{
    AnchorSet, AnchoredBundles, Batch, BuilderSeal, BundledWitness, Consignment, ContainerVer,
    Contract, Fascia, PubWitness, SealWitness, Terminal, TerminalSeal, Transfer, TransitionInfo,
    TransitionInfoError, ValidConsignment, ValidContract, ValidKit, ValidTransfer,
};
use crate::info::{IfaceInfo, SchemaInfo};
use crate::interface::resolver::DumbResolver;
use crate::interface::{
    BuilderError, ContractBuilder, ContractIface, Iface, IfaceId, IfaceRef, TransitionBuilder,
    VelocityHint,
};
use crate::resolvers::ResolveHeight;

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
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
    /// state for contract {0} is now known.
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    StateInconsistency(ContractId),

    #[from]
    #[display(doc_comments)]
    /// {0}
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    IndexInconsistency(IndexInconsistency),

    #[from]
    StashData(StashDataError),
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

impl<S: StashProvider, H: StateProvider, P: IndexProvider, E: Error>
    From<StateUpdateError<<H as StateWriteProvider>::Error>> for StockError<S, H, P, E>
{
    fn from(err: StateUpdateError<<H as StateWriteProvider>::Error>) -> Self {
        match err {
            StateUpdateError::Resolver(err) => Self::Resolver(err),
            StateUpdateError::Connectivity(err) => Self::StateWrite(err),
            StateUpdateError::UnknownContract(err) => Self::StateInconsistency(err),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ConsignError {
    /// unable to construct consignment: too many terminals provided.
    TooManyTerminals,

    /// unable to construct consignment: history size too large, resulting in
    /// too many transitions.
    TooManyBundles,

    /// public state at operation output {0} is concealed.
    ConcealedPublicState(Opout),

    #[from]
    #[display(inner)]
    MergeReveal(MergeRevealError),

    #[from]
    #[display(inner)]
    Reveal(RevealError),

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

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<RevealError>
    for StockError<S, H, P, ConsignError>
{
    fn from(err: RevealError) -> Self { Self::InvalidInput(err.into()) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ComposeError {
    /// no outputs available to store state of type {1} with velocity class
    /// '{0}'.
    NoBlankOrChange(VelocityHint, AssignmentType),

    /// the provided PSBT doesn't pay any sats to the RGB beneficiary address.
    NoBeneficiaryOutput,

    /// expired invoice.
    InvoiceExpired,

    /// the invoice contains no contract information.
    NoContract,

    /// the invoice contains no interface information.
    NoIface,

    /// the invoice requirements can't be fulfilled using available assets or
    /// smart contract state.
    InsufficientState,

    /// the spent UTXOs contain too many seals which can't fit the state
    /// transition input limit.
    TooManyInputs,

    #[from]
    #[display(inner)]
    Transition(TransitionInfoError),

    /// the operation produces too many blank state transitions which can't fit
    /// the container requirements.
    TooManyBlanks,

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
#[display(doc_comments)]
pub enum ContractIfaceError {
    /// no known implementations of {0::<0} parent interfaces for
    /// the schema {1::<0}.
    NoAbstractImpl(IfaceId, SchemaId),
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<ContractIfaceError>
    for StockError<S, H, P, ContractIfaceError>
{
    fn from(err: ContractIfaceError) -> Self { Self::InvalidInput(err) }
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
    #[from]
    ContractIface(ContractIfaceError),
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
                    StockError::StashData(e) => StockError::StashData(e),
                    StockError::StashInconsistency(e) => StockError::StashInconsistency(e),
                    StockError::StateInconsistency(e) => StockError::StateInconsistency(e),
                    StockError::IndexInconsistency(e) => StockError::IndexInconsistency(e),
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
impl From<Infallible> for ContractIfaceError {
    fn from(_: Infallible) -> Self { unreachable!() }
}

stock_err_conv!(Infallible, ComposeError);
stock_err_conv!(Infallible, ConsignError);
stock_err_conv!(Infallible, FasciaError);
stock_err_conv!(Infallible, ContractIfaceError);
stock_err_conv!(Infallible, InputError);
stock_err_conv!(ComposeError, InputError);
stock_err_conv!(ConsignError, InputError);
stock_err_conv!(FasciaError, InputError);
stock_err_conv!(ContractIfaceError, InputError);

pub type StockErrorMem<E = Infallible> = StockError<MemStash, MemState, MemIndex, E>;
pub type StockErrorAll<S = MemStash, H = MemState, P = MemIndex> = StockError<S, H, P, InputError>;

#[derive(Debug)]
pub struct Stock<
    S: StashProvider = MemStash,
    H: StateProvider = MemState,
    P: IndexProvider = MemIndex,
> {
    stash: Stash<S>,
    state: H,
    index: Index<P>,
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

impl<S: StashProvider, H: StateProvider, P: IndexProvider> Stock<S, H, P> {
    pub fn with(stash_provider: S, state_provider: H, index_provider: P) -> Self {
        Stock {
            stash: Stash::new(stash_provider),
            state: state_provider,
            index: Index::new(index_provider),
        }
    }

    #[doc(hidden)]
    pub fn as_stash_provider(&self) -> &S { self.stash.as_provider() }
    #[doc(hidden)]
    pub fn as_state_provider(&self) -> &H { &self.state }
    #[doc(hidden)]
    pub fn as_index_provider(&self) -> &P { self.index.as_provider() }

    pub fn ifaces(&self) -> Result<impl Iterator<Item = IfaceInfo> + '_, StockError<S, H, P>> {
        Ok(self.stash.ifaces()?.map(IfaceInfo::with))
    }
    pub fn iface(&self, iface: impl Into<IfaceRef>) -> Result<&Iface, StockError<S, H, P>> {
        Ok(self.stash.iface(iface)?)
    }
    pub fn schemata(&self) -> Result<impl Iterator<Item = SchemaInfo> + '_, StockError<S, H, P>> {
        Ok(self.stash.schemata()?.map(SchemaInfo::with))
    }
    pub fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, StockError<S, H, P>> {
        Ok(self.stash.schema(schema_id)?)
    }
    pub fn contract_ids(
        &self,
    ) -> Result<impl Iterator<Item = ContractId> + '_, StockError<S, H, P>> {
        Ok(self.stash.contract_ids()?)
    }

    /// Iterates over all contract ids which can be interfaced using a specific
    /// interface.
    pub fn contracts_ifaceable(
        &self,
        iface: impl Into<IfaceRef>,
    ) -> Result<impl Iterator<Item = ContractId> + '_, StockError<S, H, P>> {
        Ok(self.stash.contract_ids_by_iface(iface)?)
    }

    /// Iterates over ids of all contract assigning state to the provided set of
    /// witness outputs.
    pub fn contracts_assigning(
        &self,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<impl Iterator<Item = ContractId> + '_, StockError<S, H, P>> {
        let outputs = outputs
            .into_iter()
            .map(|o| o.into())
            .collect::<BTreeSet<_>>();
        Ok(self.index.contracts_assigning(outputs)?)
    }

    fn contract_raw(
        &self,
        contract_id: ContractId,
    ) -> Result<(&SchemaIfaces, &ContractHistory), StockError<S, H, P>> {
        let history = self
            .state
            .contract_state(contract_id)
            .map_err(StockError::StateRead)?
            .ok_or(StockError::StateInconsistency(contract_id))?;
        let schema_id = history.schema_id();
        let schema_ifaces = self.stash.schema(schema_id)?;
        Ok((schema_ifaces, history))
    }

    pub fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<ContractState, StockError<S, H, P>> {
        let (schema_ifaces, history) = self.contract_raw(contract_id)?;
        Ok(ContractState {
            schema: schema_ifaces.schema.clone(),
            history: history.clone(),
        })
    }

    /// Returns the best matching abstract interface to a contract.
    pub fn contract_iface(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
    ) -> Result<ContractIface, StockError<S, H, P, ContractIfaceError>> {
        let (schema_ifaces, history) = self.contract_raw(contract_id)?;
        let iface = self.stash.iface(iface)?;
        let iface_id = iface.iface_id();

        let iimpl = schema_ifaces
            .iimpls
            .get(&iface_id)
            .or_else(|| {
                iface
                    .inherits
                    .iter()
                    .rev()
                    .find_map(|parent| schema_ifaces.iimpls.get(parent))
            })
            .ok_or_else(|| {
                ContractIfaceError::NoAbstractImpl(iface_id, schema_ifaces.schema.schema_id())
            })?;

        let (types, _) = self.stash.extract(&schema_ifaces.schema, [iface])?;

        let state = ContractState {
            schema: schema_ifaces.schema.clone(),
            history: history.clone(),
        };
        Ok(ContractIface {
            state,
            iface: iimpl.clone(),
            types,
        })
    }

    pub fn contract_state_for_outpoints(
        &self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<XOutpoint>>,
    ) -> Result<HashMap<XOutputSeal, HashMap<Opout, PersistedState>>, StockError<S, H, P>> {
        let outputs: BTreeSet<XOutpoint> = outpoints.into_iter().map(|o| o.into()).collect();

        let history = self.contract_state(contract_id)?;

        let mut res =
            HashMap::<XOutputSeal, HashMap<Opout, PersistedState>>::with_capacity(outputs.len());

        for item in history.fungibles() {
            let outpoint = item.seal.into();
            if outputs.contains::<XOutpoint>(&outpoint) {
                res.entry(item.seal).or_default().insert(
                    item.opout,
                    PersistedState::Amount(
                        item.state.value.into(),
                        item.state.blinding,
                        item.state.tag,
                    ),
                );
            }
        }

        for item in history.data() {
            let outpoint = item.seal.into();
            if outputs.contains::<XOutpoint>(&outpoint) {
                res.entry(item.seal).or_default().insert(
                    item.opout,
                    PersistedState::Data(item.state.value.clone(), item.state.salt),
                );
            }
        }

        for item in history.rights() {
            let outpoint = item.seal.into();
            if outputs.contains::<XOutpoint>(&outpoint) {
                res.entry(item.seal)
                    .or_default()
                    .insert(item.opout, PersistedState::Void);
            }
        }

        for item in history.attach() {
            let outpoint = item.seal.into();
            if outputs.contains::<XOutpoint>(&outpoint) {
                res.entry(item.seal).or_default().insert(
                    item.opout,
                    PersistedState::Attachment(item.state.clone().into(), item.state.salt),
                );
            }
        }

        Ok(res)
    }

    pub fn contract_builder(
        &self,
        schema_id: SchemaId,
        iface: impl Into<IfaceRef>,
    ) -> Result<ContractBuilder, StockError<S, H, P>> {
        Ok(self.stash.contract_builder(schema_id, iface)?)
    }

    pub fn transition_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
        transition_name: Option<impl Into<FieldName>>,
    ) -> Result<TransitionBuilder, StockError<S, H, P>> {
        Ok(self
            .stash
            .transition_builder(contract_id, iface, transition_name)?)
    }

    pub fn blank_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
    ) -> Result<TransitionBuilder, StockError<S, H, P>> {
        Ok(self.stash.blank_builder(contract_id, iface)?)
    }

    pub fn export_contract(
        &self,
        contract_id: ContractId,
    ) -> Result<Contract, StockError<S, H, P, ConsignError>> {
        let mut consignment = self.consign::<false>(contract_id, [], [])?;
        consignment.transfer = false;
        Ok(consignment)
    }

    pub fn transfer(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[XOutputSeal]>,
        secret_seals: impl AsRef<[XChain<SecretSeal>]>,
    ) -> Result<Transfer, StockError<S, H, P, ConsignError>> {
        let mut consignment = self.consign(contract_id, outputs, secret_seals)?;
        consignment.transfer = true;
        Ok(consignment)
    }

    fn consign<const TRANSFER: bool>(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[XOutputSeal]>,
        secret_seals: impl AsRef<[XChain<SecretSeal>]>,
    ) -> Result<Consignment<TRANSFER>, StockError<S, H, P, ConsignError>> {
        let outputs = outputs.as_ref();
        let secret_seals = secret_seals.as_ref();

        // 1. Collect initial set of anchored bundles
        // 1.1. Get all public outputs
        let mut opouts = self.index.public_opouts(contract_id)?;

        // 1.2. Add outputs requested by the caller
        opouts.extend(
            self.index
                .opouts_by_outputs(contract_id, outputs.iter().copied())?,
        );
        opouts.extend(
            self.index
                .opouts_by_terminals(secret_seals.iter().copied())?,
        );

        // 1.3. Collect all state transitions assigning state to the provided outpoints
        let mut bundled_witnesses = BTreeMap::<BundleId, BundledWitness>::new();
        let mut transitions = BTreeMap::<OpId, Transition>::new();
        let mut terminals = BTreeMap::<BundleId, Terminal>::new();
        for opout in opouts {
            if opout.op == contract_id {
                continue; // we skip genesis since it will be present anywhere
            }

            let transition = self.transition(opout.op)?;
            transitions.insert(opout.op, transition.clone());

            let bundle_id = self.index.bundle_id_for_op(transition.id())?;
            // 2. Collect seals from terminal transitions to add to the consignment
            //    terminals
            for (type_id, typed_assignments) in transition.assignments.iter() {
                for index in 0..typed_assignments.len_u16() {
                    let seal = typed_assignments.to_confidential_seals()[index as usize];
                    if secret_seals.contains(&seal) {
                        terminals.insert(bundle_id, Terminal::new(seal.map(TerminalSeal::from)));
                    } else if opout.no == index && opout.ty == *type_id {
                        if let Some(seal) = typed_assignments
                            .revealed_seal_at(index)
                            .expect("index exists")
                        {
                            let seal = seal.map(|s| s.conceal()).map(TerminalSeal::from);
                            terminals.insert(bundle_id, Terminal::new(seal));
                        } else {
                            return Err(ConsignError::ConcealedPublicState(opout).into());
                        }
                    }
                }
            }

            if let Entry::Vacant(entry) = bundled_witnesses.entry(bundle_id) {
                let bw = self.bundled_witness(bundle_id)?;
                entry.insert(bw);
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
            bundled_witnesses
                .entry(bundle_id)
                .or_insert(self.bundled_witness(bundle_id)?.clone())
                .anchored_bundles
                .reveal_transition(transition.clone())?;
        }

        let genesis = self.stash.genesis(contract_id)?.clone();
        let schema_ifaces = self.stash.schema(genesis.schema_id)?.clone();
        let mut ifaces = BTreeMap::new();
        for (iface_id, iimpl) in schema_ifaces.iimpls {
            let iface = self.stash.iface(iface_id)?;
            ifaces.insert(iface.clone(), iimpl);
        }
        let ifaces = Confined::from_collection_unsafe(ifaces);

        let mut bundles = BTreeMap::<XWitnessId, BundledWitness>::new();
        for bw in bundled_witnesses.into_values() {
            let witness_id = bw.witness_id();
            match bundles.get_mut(&witness_id) {
                Some(prev) => {
                    *prev = prev.clone().merge_reveal(bw)?;
                }
                None => {
                    bundles.insert(witness_id, bw);
                }
            }
        }
        let bundles = Confined::try_from_iter(bundles.into_values())
            .map_err(|_| ConsignError::TooManyBundles)?;
        let terminals =
            Confined::try_from(terminals).map_err(|_| ConsignError::TooManyTerminals)?;

        let (types, scripts) = self.stash.extract(&schema_ifaces.schema, ifaces.keys())?;
        let scripts = Confined::from_iter_unsafe(scripts.into_values());

        // TODO: Conceal everything we do not need
        // TODO: Add known sigs to the consignment

        Ok(Consignment {
            version: ContainerVer::V2,
            transfer: TRANSFER,

            schema: schema_ifaces.schema,
            ifaces,
            genesis,
            terminals,
            bundles,
            extensions: none!(),
            attachments: none!(),

            signatures: none!(),  // TODO: Collect signatures
            supplements: none!(), // TODO: Collect supplements
            types,
            scripts,
        })
    }

    /// Composes a batch of state transitions updating state for the provided
    /// set of previous outputs, satisfying requirements of the invoice, paying
    /// the change back and including the necessary blank state transitions.
    pub fn compose(
        &self,
        invoice: &RgbInvoice,
        prev_outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
        method: CloseMethod,
        beneficiary_vout: Option<impl Into<Vout>>,
        allocator: impl Fn(ContractId, AssignmentType, VelocityHint) -> Option<Vout>,
    ) -> Result<Batch, StockError<S, H, P, ComposeError>> {
        self.compose_deterministic(
            invoice,
            prev_outputs,
            method,
            beneficiary_vout,
            allocator,
            |_, _| BlindingFactor::random(),
            |_, _| rand::random(),
        )
    }

    /// Composes a batch of state transitions updating state for the provided
    /// set of previous outputs, satisfying requirements of the invoice, paying
    /// the change back and including the necessary blank state transitions.
    #[allow(clippy::too_many_arguments)]
    pub fn compose_deterministic(
        &self,
        invoice: &RgbInvoice,
        prev_outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
        method: CloseMethod,
        beneficiary_vout: Option<impl Into<Vout>>,
        allocator: impl Fn(ContractId, AssignmentType, VelocityHint) -> Option<Vout>,
        pedersen_blinder: impl Fn(ContractId, AssignmentType) -> BlindingFactor,
        seal_blinder: impl Fn(ContractId, AssignmentType) -> u64,
    ) -> Result<Batch, StockError<S, H, P, ComposeError>> {
        let layer1 = invoice.layer1();
        let prev_outputs = prev_outputs
            .into_iter()
            .map(|o| o.into())
            .collect::<HashSet<XOutputSeal>>();

        #[allow(clippy::type_complexity)]
        let output_for_assignment =
            |id: ContractId,
             assignment_type: AssignmentType|
             -> Result<BuilderSeal<GraphSeal>, StockError<S, H, P, ComposeError>> {
                let mut suppl = self.stash.contract_supplements(id)?;
                let velocity = suppl
                    .next()
                    .and_then(|mut s| s.owned_state.remove(&assignment_type).ok().flatten())
                    .map(|s| s.velocity)
                    .unwrap_or_default();
                let vout = allocator(id, assignment_type, velocity)
                    .ok_or(ComposeError::NoBlankOrChange(velocity, assignment_type))?;
                let seal =
                    GraphSeal::with_blinded_vout(method, vout, seal_blinder(id, assignment_type));
                Ok(BuilderSeal::Revealed(XChain::with(layer1, seal)))
            };

        // 1. Prepare the data
        if let Some(expiry) = invoice.expiry {
            if expiry < Utc::now().timestamp() {
                return Err(ComposeError::InvoiceExpired.into());
            }
        }
        let contract_id = invoice.contract.ok_or(ComposeError::NoContract)?;
        let iface = invoice.iface.as_ref().ok_or(ComposeError::NoIface)?;
        let mut main_builder =
            self.transition_builder(contract_id, iface.clone(), invoice.operation.clone())?;
        let assignment_name = invoice
            .assignment
            .as_ref()
            .or_else(|| main_builder.default_assignment().ok())
            .ok_or(BuilderError::NoDefaultAssignment)?
            .clone();
        let assignment_id = main_builder
            .assignments_type(&assignment_name)
            .ok_or(BuilderError::InvalidStateField(assignment_name.clone()))?;

        let layer1 = invoice.beneficiary.chain_network().layer1();
        let beneficiary = match (invoice.beneficiary.into_inner(), beneficiary_vout) {
            (Beneficiary::BlindedSeal(seal), _) => {
                BuilderSeal::Concealed(XChain::with(layer1, seal))
            }
            (Beneficiary::WitnessVout(_), Some(vout)) => BuilderSeal::Revealed(XChain::with(
                layer1,
                GraphSeal::with_blinded_vout(
                    method,
                    vout,
                    seal_blinder(contract_id, assignment_id),
                ),
            )),
            (Beneficiary::WitnessVout(_), None) => {
                return Err(ComposeError::NoBeneficiaryOutput.into());
            }
        };

        // 2. Prepare transition
        let mut main_inputs = Vec::<XOutputSeal>::new();
        let mut sum_inputs = Amount::ZERO;
        let mut data_inputs = vec![];
        for (output, list) in
            self.contract_state_for_outpoints(contract_id, prev_outputs.iter().copied())?
        {
            main_inputs.push(output);
            for (opout, mut state) in list {
                main_builder = main_builder.add_input(opout, state.clone())?;
                if opout.ty != assignment_id {
                    let seal = output_for_assignment(contract_id, opout.ty)?;
                    state.update_blinding(pedersen_blinder(contract_id, assignment_id));
                    main_builder = main_builder.add_owned_state_raw(opout.ty, seal, state)?;
                } else if let PersistedState::Amount(value, _, _) = state {
                    sum_inputs += value;
                } else if let PersistedState::Data(value, _) = state {
                    data_inputs.push(value);
                }
            }
        }
        // Add change
        let main_transition = match invoice.owned_state.clone() {
            InvoiceState::Amount(amt) => {
                match sum_inputs.cmp(&amt) {
                    Ordering::Greater => {
                        let seal = output_for_assignment(contract_id, assignment_id)?;
                        main_builder = main_builder.add_fungible_state_raw(
                            assignment_id,
                            seal,
                            sum_inputs - amt,
                            pedersen_blinder(contract_id, assignment_id),
                        )?;
                    }
                    Ordering::Less => return Err(ComposeError::InsufficientState.into()),
                    Ordering::Equal => {}
                }
                main_builder
                    .add_fungible_state_raw(
                        assignment_id,
                        beneficiary,
                        amt,
                        pedersen_blinder(contract_id, assignment_id),
                    )?
                    .complete_transition()?
            }
            InvoiceState::Data(data) => match data {
                NonFungible::RGB21(allocation) => {
                    if !data_inputs.into_iter().any(|x| x == allocation.into()) {
                        return Err(ComposeError::InsufficientState.into());
                    }

                    main_builder
                        .add_data_raw(
                            assignment_id,
                            beneficiary,
                            allocation,
                            seal_blinder(contract_id, assignment_id),
                        )?
                        .complete_transition()?
                }
            },
            _ => {
                todo!("only TypedState::Amount and TypedState::Allocation are currently supported")
            }
        };

        // 3. Prepare other transitions
        // Enumerate state
        let mut spent_state =
            HashMap::<ContractId, HashMap<XOutputSeal, HashMap<Opout, PersistedState>>>::new();
        for id in self.contracts_assigning(prev_outputs.iter().copied())? {
            // Skip current contract
            if id == contract_id {
                continue;
            }
            let state = self.contract_state_for_outpoints(id, prev_outputs.iter().copied())?;
            let entry = spent_state.entry(id).or_default();
            for (seal, assigns) in state {
                entry.entry(seal).or_default().extend(assigns);
            }
        }

        // Construct blank transitions
        let mut blanks = Confined::<Vec<_>, 0, { U24 - 1 }>::with_capacity(spent_state.len());
        for (id, list) in spent_state {
            let mut blank_builder = self.blank_builder(id, iface.clone())?;
            let mut outputs = Vec::with_capacity(list.len());
            for (output, assigns) in list {
                outputs.push(output);
                for (opout, state) in assigns {
                    let seal = output_for_assignment(id, opout.ty)?;
                    blank_builder = blank_builder
                        .add_input(opout, state.clone())?
                        .add_owned_state_raw(opout.ty, seal, state)?;
                }
            }

            let transition = blank_builder.complete_transition()?;
            let info = TransitionInfo::new(transition, outputs)
                .map_err(|_| ComposeError::TooManyInputs)?;
            blanks.push(info).map_err(|_| ComposeError::TooManyBlanks)?;
        }

        let main = TransitionInfo::new(main_transition, main_inputs)
            .map_err(|_| ComposeError::TooManyInputs)?;
        Ok(Batch { main, blanks })
    }

    pub fn import_kit(&mut self, kit: ValidKit) -> Result<validation::Status, StockError<S, H, P>> {
        let (kit, status) = kit.split();
        self.stash.consume_kit(kit)?;
        Ok(status)
    }

    pub fn import_contract<R: ResolveHeight>(
        &mut self,
        contract: ValidContract,
        resolver: &mut R,
    ) -> Result<validation::Status, StockError<S, H, P>> {
        self.consume_consignment(contract, resolver)
    }

    pub fn accept_transfer<R: ResolveHeight>(
        &mut self,
        contract: ValidTransfer,
        resolver: &mut R,
    ) -> Result<validation::Status, StockError<S, H, P>> {
        self.consume_consignment(contract, resolver)
    }

    fn consume_consignment<R: ResolveHeight, const TRANSFER: bool>(
        &mut self,
        consignment: ValidConsignment<TRANSFER>,
        resolver: &mut R,
    ) -> Result<validation::Status, StockError<S, H, P>> {
        let contract_id = consignment.contract_id();
        let (consignment, status) = consignment.split();

        self.state
            .create_or_update_state::<R>(contract_id, |history| {
                consignment.update_history(history, resolver)
            })?;
        self.index.index_consignment(&consignment)?;
        self.stash.consume_consignment(consignment)?;

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
    pub fn consume_fascia(
        &mut self,
        fascia: Fascia,
    ) -> Result<(), StockError<S, H, P, FasciaError>> {
        let witness_id = fascia.witness_id;

        self.stash
            .consume_witness(SealWitness::new(fascia.witness_id, fascia.anchor.clone()))?;

        for (contract_id, bundle) in fascia.into_bundles() {
            let ids1 = bundle
                .known_transitions
                .keys()
                .copied()
                .collect::<BTreeSet<_>>();
            let ids2 = bundle.input_map.values().copied().collect::<BTreeSet<_>>();
            if !ids1.is_subset(&ids2) {
                return Err(FasciaError::InvalidBundle(contract_id, bundle.bundle_id()).into());
            }

            self.index.index_bundle(contract_id, &bundle, witness_id)?;

            self.state
                .update_state::<DumbResolver>(contract_id, |history| {
                    for transition in bundle.known_transitions.values() {
                        let witness_anchor = WitnessAnchor::from_mempool(witness_id);
                        history.add_transition(transition, witness_anchor);
                    }
                    Ok(())
                })?;

            self.stash.consume_bundle(bundle)?;
        }
        Ok(())
    }

    fn transition(&self, opid: OpId) -> Result<&Transition, StockError<S, H, P, ConsignError>> {
        let bundle_id = self.index.bundle_id_for_op(opid)?;
        let bundle = self.stash.bundle(bundle_id)?;
        bundle
            .known_transitions
            .get(&opid)
            .ok_or(ConsignError::Concealed(bundle_id, opid).into())
    }

    fn bundled_witness(&self, bundle_id: BundleId) -> Result<BundledWitness, StockError<S, H, P>> {
        let (witness_id, contract_id) = self.index.bundle_info(bundle_id)?;

        let bundle = self.stash.bundle(bundle_id)?.clone();
        let anchor = self.stash.witness(witness_id)?.anchors.clone();
        let (tapret, opret) = match anchor {
            AnchorSet::Tapret(tapret) => (Some(tapret), None),
            AnchorSet::Opret(opret) => (None, Some(opret)),
            AnchorSet::Double { tapret, opret } => (Some(tapret), Some(opret)),
        };
        let mut anchor = None;
        if let Some(a) = tapret {
            if let Ok(a) = a.to_merkle_proof(contract_id) {
                anchor = Some(EAnchor::new(a.mpc_proof, DbcProof::Tapret(a.dbc_proof)));
            }
        }
        if anchor.is_none() {
            if let Some(a) = opret {
                if let Ok(a) = a.to_merkle_proof(contract_id) {
                    anchor = Some(EAnchor::new(a.mpc_proof, DbcProof::Opret(a.dbc_proof)));
                }
            }
        }
        let Some(anchor) = anchor else {
            return Err(StashInconsistency::BundleMissedInAnchors(bundle_id, contract_id).into());
        };

        let anchored_bundles = AnchoredBundles::with(anchor, bundle);
        // TODO: Conceal all transitions except the one we need

        // TODO: recover Tx and SPV
        Ok(BundledWitness {
            pub_witness: witness_id.map(PubWitness::new),
            anchored_bundles,
        })
    }

    pub fn store_secret_seal(
        &mut self,
        seal: XChain<GraphSeal>,
    ) -> Result<bool, StockError<S, H, P>> {
        Ok(self.stash.store_secret_seal(seal)?)
    }
}
