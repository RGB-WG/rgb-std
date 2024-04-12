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
    validation, AssetTag, AssignmentType, BlindingFactor, BundleId, ContractId, DataState,
    GraphSeal, OpId, Operation, Opout, SchemaId, SecretSeal, Transition, XChain, XOutpoint,
    XOutputSeal, XWitnessId,
};
use strict_encoding::FieldName;

use super::{
    IndexProvider, IndexReadProvider, IndexWriteProvider, Stash, StashDataError, StashError,
    StashInconsistency, StashProvider, StashReadProvider, StashWriteProvider,
};
use crate::accessors::{MergeRevealError, RevealError};
use crate::containers::{
    Batch, BuilderSeal, BundledWitness, Consignment, ContainerVer, Contract, Fascia, SealWitness,
    Terminal, TerminalSeal, Transfer, TransitionInfo, TransitionInfoError,
};
use crate::interface::{
    AttachedState, BuilderError, ContractBuilder, ContractIface, IfaceRef, TransitionBuilder,
    VelocityHint,
};
use crate::resolvers::ResolveHeight;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum StockError<S: StashProvider, P: IndexProvider, E: Error = Infallible> {
    InvalidInput(E),
    StashRead(<S as StashReadProvider>::Error),
    StashWrite(<S as StashWriteProvider>::Error),
    IndexRead(<P as IndexReadProvider>::Error),
    IndexWrite(<P as IndexWriteProvider>::Error),
    StashInconsistency(StashInconsistency),
    #[from]
    StashData(StashDataError),
}

impl<S: StashProvider, P: IndexProvider, E: Error> From<StashError<S>> for StockError<S, P, E> {
    fn from(err: StashError<S>) -> Self {
        match err {
            StashError::ReadProvider(err) => Self::StashRead(err),
            StashError::WriteProvider(err) => Self::StashWrite(err),
            StashError::Data(e) => Self::StashData(e),
            StashError::Inconsistency(e) => Self::StashInconsistency(e),
        }
    }
}

#[derive(Debug, Display, Error, From)]
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
}

impl<S: StashProvider, P: IndexProvider> From<ConsignError> for StockError<S, P, ConsignError> {
    fn from(err: ConsignError) -> Self { Self::InvalidInput(err) }
}

impl<S: StashProvider, P: IndexProvider> From<MergeRevealError> for StockError<S, P, ConsignError> {
    fn from(err: MergeRevealError) -> Self { Self::InvalidInput(err.into()) }
}

impl<S: StashProvider, P: IndexProvider> From<RevealError> for StockError<S, P, ConsignError> {
    fn from(err: RevealError) -> Self { Self::InvalidInput(err.into()) }
}

impl<S: StashProvider, P: IndexProvider> From<StockError<S, P, Infallible>>
    for StockError<S, P, ConsignError>
{
    fn from(err: StockError<S, P, Infallible>) -> Self {
        match err {
            StockError::InvalidInput(_) => unreachable!(),
            StockError::StashRead(e) => StockError::StashRead(e),
            StockError::StashWrite(e) => StockError::StashWrite(e),
            StockError::IndexRead(e) => StockError::IndexRead(e),
            StockError::IndexWrite(e) => StockError::IndexWrite(e),
            StockError::StashData(e) => StockError::StashData(e),
            StockError::StashInconsistency(e) => StockError::StashInconsistency(e),
        }
    }
}

#[derive(Debug, Display, Error, From)]
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

impl<S: StashProvider, P: IndexProvider> From<ComposeError> for StockError<S, P, ComposeError> {
    fn from(err: ComposeError) -> Self { Self::InvalidInput(err) }
}

impl<S: StashProvider, P: IndexProvider> From<BuilderError> for StockError<S, P, ComposeError> {
    fn from(err: BuilderError) -> Self { Self::InvalidInput(err.into()) }
}

impl<S: StashProvider, P: IndexProvider> From<StockError<S, P, Infallible>>
    for StockError<S, P, ComposeError>
{
    fn from(err: StockError<S, P, Infallible>) -> Self {
        match err {
            StockError::InvalidInput(_) => unreachable!(),
            StockError::StashRead(e) => StockError::StashRead(e),
            StockError::StashWrite(e) => StockError::StashWrite(e),
            StockError::IndexRead(e) => StockError::IndexRead(e),
            StockError::IndexWrite(e) => StockError::IndexWrite(e),
            StockError::StashData(e) => StockError::StashData(e),
            StockError::StashInconsistency(e) => StockError::StashInconsistency(e),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum FasciaError {
    /// bundle {1} for contract {0} contains invalid transition input map.
    InvalidBundle(ContractId, BundleId),
}

impl<S: StashProvider, P: IndexProvider> From<FasciaError> for StockError<S, P, FasciaError> {
    fn from(err: FasciaError) -> Self { Self::InvalidInput(err) }
}

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub enum PersistedState {
    Void,
    Amount(Amount, BlindingFactor, AssetTag),
    Data(DataState, u128),
    Attachment(AttachedState, u64),
}

impl PersistedState {
    fn update_blinding(&mut self, blinding: BlindingFactor) {
        match self {
            PersistedState::Void => {}
            PersistedState::Amount(_, b, _) => *b = blinding,
            PersistedState::Data(_, _) => {}
            PersistedState::Attachment(_, _) => {}
        }
    }
}

#[derive(Debug)]
pub struct Stock<S: StashProvider, P: IndexProvider> {
    stash: Stash<S>,
    index: P,
}

impl<S: StashProvider, P: IndexProvider> Stock<S, P> {
    pub fn new(stash_provider: S, index_provider: P) -> Self {
        Stock {
            stash: Stash::new(stash_provider),
            index: index_provider,
        }
    }

    pub fn with(stash: Stash<S>, cache: P) -> Self {
        Stock {
            stash,
            index: cache,
        }
    }

    pub fn contracts_by_iface(
        &self,
        iface: impl Into<IfaceRef>,
    ) -> Result<Vec<ContractIface>, StockError<S, P>> {
        let iface_id = self.stash.iface(iface)?.iface_id();
        self.stash
            .contract_ids_by_iface(iface_id)?
            .into_iter()
            .map(|id| self.contract_iface(id, iface_id))
            .collect()
    }

    pub fn contracts_by_outputs(
        &self,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<BTreeSet<ContractId>, StockError<S, P>> {
        self.index
            .contracts_by_outputs(outputs)
            .map_err(StockError::IndexRead)
    }

    pub fn contract_iface(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
    ) -> Result<ContractIface, StockError<S, P>> {
        self.index
            .contract_iface(contract_id, iface)
            .map_err(StockError::IndexRead)
    }

    pub fn public_opouts(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, StockError<S, P>> {
        self.index
            .public_opouts(contract_id)
            .map_err(StockError::IndexRead)
    }

    pub fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<BTreeSet<Opout>, StockError<S, P>> {
        self.index
            .opouts_by_outputs(contract_id, outputs)
            .map_err(StockError::IndexRead)
    }

    pub fn opouts_by_terminals(
        &self,
        terminals: impl IntoIterator<Item = XChain<SecretSeal>>,
    ) -> Result<BTreeSet<Opout>, StockError<S, P>> {
        self.index
            .opouts_by_terminals(terminals)
            .map_err(StockError::IndexRead)
    }

    pub fn state_for_outpoints(
        &self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<XOutpoint>>,
    ) -> Result<BTreeMap<(Opout, XOutputSeal), PersistedState>, StockError<S, P>> {
        self.index
            .state_for_outpoints(contract_id, outpoints)
            .map_err(StockError::IndexRead)
    }

    pub fn import_contract<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, StockError<S, P>>
    where
        R::Error: 'static,
    {
        self.index
            .import_contract(contract, resolver)
            .map_err(StockError::IndexWrite)
    }

    pub fn accept_transfer<R: ResolveHeight>(
        &mut self,
        transfer: Transfer,
        resolver: &mut R,
        force: bool,
    ) -> Result<validation::Status, StockError<S, P>>
    where
        R::Error: 'static,
    {
        self.index
            .accept_transfer(transfer, resolver, force)
            .map_err(StockError::IndexWrite)
    }

    /// Imports fascia into the stash, index and inventory.
    ///
    /// Part of the transfer workflow. Called once PSBT is completed and an RGB
    /// fascia containing anchor and all state transitions is exported from
    /// it.
    ///
    /// Must be called before the consignment is created, when witness
    /// transaction is not yet mined.
    pub fn consume_fascia(&mut self, fascia: Fascia) -> Result<(), StockError<S, P, FasciaError>> {
        let witness_id = fascia.witness_id;
        self.index
            .consume_witness(SealWitness::new(fascia.witness_id, fascia.anchor.clone()))
            .map_err(StockError::IndexWrite)?;
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
            self.index
                .consume_bundle(contract_id, bundle, witness_id)
                .map_err(StockError::IndexWrite)?;
        }
        Ok(())
    }

    pub fn contract_builder(
        &self,
        schema_id: SchemaId,
        iface: impl Into<IfaceRef>,
    ) -> Result<ContractBuilder, StashError<S>> {
        self.stash.contract_builder(schema_id, iface)
    }

    pub fn transition_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
        transition_name: Option<impl Into<FieldName>>,
    ) -> Result<TransitionBuilder, StashError<S>> {
        self.stash
            .transition_builder(contract_id, iface, transition_name)
    }

    pub fn blank_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
    ) -> Result<TransitionBuilder, StashError<S>> {
        self.stash.blank_builder(contract_id, iface)
    }

    pub fn export_contract(
        &self,
        contract_id: ContractId,
    ) -> Result<Contract, StockError<S, P, ConsignError>> {
        let mut consignment = self.consign::<false>(contract_id, [], [])?;
        consignment.transfer = false;
        Ok(consignment)
        // TODO: Add known sigs to the bindle
    }

    pub fn transfer(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[XOutputSeal]>,
        secret_seals: impl AsRef<[XChain<SecretSeal>]>,
    ) -> Result<Transfer, StockError<S, P, ConsignError>> {
        let mut consignment = self.consign(contract_id, outputs, secret_seals)?;
        consignment.transfer = true;
        Ok(consignment)
    }

    pub fn consign<const TYPE: bool>(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[XOutputSeal]>,
        secret_seals: impl AsRef<[XChain<SecretSeal>]>,
    ) -> Result<Consignment<TYPE>, StockError<S, P, ConsignError>> {
        let outputs = outputs.as_ref();
        let secret_seals = secret_seals.as_ref();

        // 1. Collect initial set of anchored bundles
        // 1.1. Get all public outputs
        let mut opouts = self.public_opouts(contract_id)?;

        // 1.2. Add outputs requested by the caller
        opouts.extend(self.opouts_by_outputs(contract_id, outputs.iter().copied())?);
        opouts.extend(self.opouts_by_terminals(secret_seals.iter().copied())?);

        // 1.3. Collect all state transitions assigning state to the provided outpoints
        let mut bundled_witnesses = BTreeMap::<BundleId, BundledWitness>::new();
        let mut transitions = BTreeMap::<OpId, Transition>::new();
        let mut terminals = BTreeMap::<BundleId, Terminal>::new();
        for opout in opouts {
            if opout.op == contract_id {
                continue; // we skip genesis since it will be present anywhere
            }
            let transition = self
                .index
                .transition(opout.op)
                .map_err(StockError::<_, _, Infallible>::IndexRead)?;
            transitions.insert(opout.op, transition.clone());

            let bundle_id = self
                .index
                .op_bundle_id(transition.id())
                .map_err(StockError::<_, _, Infallible>::IndexRead)?;
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
                let bw = self
                    .index
                    .bundled_witness(bundle_id)
                    .map_err(StockError::<_, _, Infallible>::IndexRead)?;
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
            let transition = self
                .index
                .transition(id)
                .map_err(StockError::<_, _, Infallible>::IndexRead)?;
            ids.extend(transition.inputs().iter().map(|input| input.prev_out.op));
            transitions.insert(id, transition.clone());
            let bundle_id = self
                .index
                .op_bundle_id(transition.id())
                .map_err(StockError::<_, _, Infallible>::IndexRead)?;
            bundled_witnesses
                .entry(bundle_id)
                .or_insert(
                    self.index
                        .bundled_witness(bundle_id)
                        .map_err(StockError::<_, _, Infallible>::IndexRead)?
                        .clone(),
                )
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
            transfer: TYPE,

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
    ) -> Result<Batch, StockError<S, P, ComposeError>> {
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
    ) -> Result<Batch, StockError<S, P, ComposeError>> {
        let layer1 = invoice.layer1();
        let prev_outputs = prev_outputs
            .into_iter()
            .map(|o| o.into())
            .collect::<HashSet<XOutputSeal>>();

        #[allow(clippy::type_complexity)]
        let output_for_assignment =
            |id: ContractId,
             assignment_type: AssignmentType|
             -> Result<BuilderSeal<GraphSeal>, StockError<S, P, ComposeError>> {
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
        for ((opout, output), mut state) in
            self.state_for_outpoints(contract_id, prev_outputs.iter().cloned())?
        {
            main_builder = main_builder.add_input(opout, state.clone())?;
            main_inputs.push(output);
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
            HashMap::<ContractId, BTreeMap<(Opout, XOutputSeal), PersistedState>>::new();
        for output in prev_outputs {
            for id in self.contracts_by_outputs([output])? {
                if id == contract_id {
                    continue;
                }
                spent_state
                    .entry(id)
                    .or_default()
                    .extend(self.state_for_outpoints(id, [output])?);
            }
        }
        // Construct blank transitions
        let mut blanks = Confined::<Vec<_>, 0, { U24 - 1 }>::with_capacity(spent_state.len());
        for (id, opouts) in spent_state {
            let mut blank_builder = self.blank_builder(id, iface.clone())?;
            let mut outputs = Vec::with_capacity(opouts.len());
            for ((opout, output), state) in opouts {
                let seal = output_for_assignment(id, opout.ty)?;
                outputs.push(output);
                blank_builder = blank_builder
                    .add_input(opout, state.clone())?
                    .add_owned_state_raw(opout.ty, seal, state)?;
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
}
