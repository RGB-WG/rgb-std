// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::ops::Deref;

use amplify::confinement::{self, Confined, MediumVec, U24};
use bp::seals::txout::CloseMethod;
use bp::{Txid, Vout};
use chrono::Utc;
use commit_verify::{mpc, Conceal};
use invoice::{Amount, Beneficiary, InvoiceState, NonFungible, RgbInvoice};
use rgb::{
    validation, AnchoredBundle, AssignmentType, BlindingFactor, BundleId, ContractId, GraphSeal,
    OpId, Operation, Opout, SchemaId, SecretSeal, SubSchema, Transition, TransitionBundle,
    WitnessId, XAnchor, XChain, XOutpoint, XOutputSeal,
};
use strict_encoding::TypeName;

use crate::accessors::{BundleExt, MergeRevealError, RevealError};
use crate::containers::{
    Batch, Bindle, BuilderSeal, Cert, Consignment, ContentId, Contract, Fascia, Terminal,
    TerminalSeal, Transfer, TransitionInfo,
};
use crate::interface::{
    BuilderError, ContractIface, Iface, IfaceId, IfaceImpl, IfacePair, IfaceWrapper,
    TransitionBuilder, VelocityHint,
};
use crate::persistence::hoard::ConsumeError;
use crate::persistence::stash::StashInconsistency;
use crate::persistence::{PresistedState, Stash, StashError};
use crate::resolvers::ResolveHeight;

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ConsignerError<E1: Error, E2: Error> {
    /// unable to construct consignment: too many terminals provided.
    TooManyTerminals,

    /// unable to construct consignment: history size too large, resulting in
    /// too many transitions.
    TooManyBundles,

    /// public state at operation output {0} is concealed.
    ConcealedPublicState(Opout),

    #[from]
    #[display(inner)]
    Reveal(RevealError),

    #[from]
    #[from(InventoryInconsistency)]
    #[display(inner)]
    InventoryError(InventoryError<E1>),

    #[from]
    #[from(StashInconsistency)]
    #[display(inner)]
    StashError(StashError<E2>),
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ComposeError<E1: Error, E2: Error> {
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

    /// the operation produces too many state transitions which can't fit the
    /// container requirements.
    #[from]
    Confinement(confinement::Error),

    #[from]
    #[display(inner)]
    Builder(BuilderError),

    #[from]
    #[display(inner)]
    InventoryError(InventoryError<E1>),

    #[from]
    #[display(inner)]
    StashError(StashError<E2>),
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum InventoryError<E: Error> {
    /// I/O or connectivity error.
    Connectivity(E),

    /// errors during consume operation.
    // TODO: Make part of connectivity error
    #[from]
    Consume(ConsumeError),

    /// error in input data.
    #[from]
    #[from(confinement::Error)]
    DataError(DataError),

    /// Permanent errors caused by bugs in the business logic of this library.
    /// Must be reported to LNP/BP Standards Association.
    #[from]
    #[from(mpc::LeafNotKnown)]
    #[from(mpc::InvalidProof)]
    #[from(RevealError)]
    #[from(StashInconsistency)]
    InternalInconsistency(InventoryInconsistency),
}

impl<E1: Error, E2: Error> From<StashError<E1>> for InventoryError<E2>
where E2: From<E1>
{
    fn from(err: StashError<E1>) -> Self {
        match err {
            StashError::Connectivity(err) => Self::Connectivity(err.into()),
            StashError::InternalInconsistency(e) => {
                Self::InternalInconsistency(InventoryInconsistency::Stash(e))
            }
        }
    }
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum InventoryDataError<E: Error> {
    /// I/O or connectivity error.
    Connectivity(E),

    /// error in input data.
    #[from]
    #[from(validation::Status)]
    #[from(confinement::Error)]
    #[from(IfaceImplError)]
    #[from(RevealError)]
    #[from(MergeRevealError)]
    DataError(DataError),
}

impl<E: Error> From<InventoryDataError<E>> for InventoryError<E> {
    fn from(err: InventoryDataError<E>) -> Self {
        match err {
            InventoryDataError::Connectivity(e) => InventoryError::Connectivity(e),
            InventoryDataError::DataError(e) => InventoryError::DataError(e),
        }
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum DataError {
    /// the consignment was not validated by the local host and thus can't be
    /// imported.
    NotValidated,

    /// consignment is invalid and can't be imported.
    #[from]
    Invalid(validation::Status),

    /// consignment has transactions which are not known and thus the contract
    /// can't be imported. If you are sure that you'd like to take the risc,
    /// call `import_contract_force`.
    UnresolvedTransactions,

    /// consignment final transactions are not yet mined. If you are sure that
    /// you'd like to take the risc, call `import_contract_force`.
    TerminalsUnmined,

    /// mismatch between witness seal chain and anchor chain.
    ChainMismatch,

    #[from]
    #[display(inner)]
    Reveal(RevealError),

    #[from]
    #[display(inner)]
    Merge(MergeRevealError),

    /// outpoint {0} is not part of the contract {1}.
    OutpointUnknown(XOutputSeal, ContractId),

    #[from]
    #[display(inner)]
    Confinement(confinement::Error),

    #[from]
    #[display(inner)]
    IfaceImpl(IfaceImplError),

    /// schema {0} doesn't implement interface {1}.
    NoIfaceImpl(SchemaId, IfaceId),

    #[from]
    #[display(inner)]
    HeightResolver(Box<dyn Error>),

    /// Information is concealed.
    Concealed,
}

#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IfaceImplError {
    /// interface implementation references unknown schema {0::<0}
    UnknownSchema(SchemaId),

    /// interface implementation references unknown interface {0::<0}
    UnknownIface(IfaceId),
}

/// These errors indicate internal business logic error. We report them instead
/// of panicking to make sure that the software doesn't crash and gracefully
/// handles situation, allowing users to report the problem back to the devs.
#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum InventoryInconsistency {
    /// state for contract {0} is not known or absent in the database.
    StateAbsent(ContractId),

    /// disclosure for txid {0} is absent.
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// inventory inconsistency and compromised inventory data storage.
    DisclosureAbsent(Txid),

    /// absent information about bundle for operation {0}.
    ///
    /// It may happen due to RGB library bug, or indicate internal inventory
    /// inconsistency and compromised inventory data storage.
    BundleAbsent(OpId),

    /// absent information about anchor for bundle {0}.
    ///
    /// It may happen due to RGB library bug, or indicate internal inventory
    /// inconsistency and compromised inventory data storage.
    NoBundleAnchor(BundleId),

    /// the anchor is not related to the contract.
    ///
    /// It may happen due to RGB library bug, or indicate internal inventory
    /// inconsistency and compromised inventory data storage.
    #[from(mpc::LeafNotKnown)]
    #[from(mpc::InvalidProof)]
    UnrelatedAnchor,

    /// bundle reveal error. Details: {0}
    ///
    /// It may happen due to RGB library bug, or indicate internal inventory
    /// inconsistency and compromised inventory data storage.
    #[from]
    BundleReveal(RevealError),

    /// the resulting bundle size exceeds consensus restrictions.
    ///
    /// It may happen due to RGB library bug, or indicate internal inventory
    /// inconsistency and compromised inventory data storage.
    OutsizedBundle,

    #[from]
    #[display(inner)]
    Stash(StashInconsistency),
}

#[allow(clippy::result_large_err)]
pub trait Inventory: Deref<Target = Self::Stash> {
    type Stash: Stash;
    /// Error type which must indicate problems on data retrieval.
    type Error: Error;

    fn stash(&self) -> &Self::Stash;

    fn import_sigs<I>(
        &mut self,
        content_id: ContentId,
        sigs: I,
    ) -> Result<(), InventoryDataError<Self::Error>>
    where
        I: IntoIterator<Item = Cert>,
        I::IntoIter: ExactSizeIterator<Item = Cert>;

    fn import_schema(
        &mut self,
        schema: impl Into<Bindle<SubSchema>>,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>>;

    fn import_iface(
        &mut self,
        iface: impl Into<Bindle<Iface>>,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>>;

    fn import_iface_impl(
        &mut self,
        iimpl: impl Into<Bindle<IfaceImpl>>,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>>;

    fn import_contract<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, InventoryError<Self::Error>>
    where
        R::Error: 'static;

    fn accept_transfer<R: ResolveHeight>(
        &mut self,
        transfer: Transfer,
        resolver: &mut R,
        force: bool,
    ) -> Result<validation::Status, InventoryError<Self::Error>>
    where
        R::Error: 'static;

    /// Imports fascia into the stash, index and inventory.
    ///
    /// Part of the transfer workflow. Called once PSBT is completed and an RGB
    /// fascia containing anchor and all state transitions is exported from
    /// it.
    ///
    /// Must be called before the consignment is created, when witness
    /// transaction is not yet mined.
    fn consume(&mut self, fascia: Fascia) -> Result<(), InventoryError<Self::Error>> {
        let witness_id = fascia.anchor.witness_id().ok_or_else(|| {
            ConsumeError::AnchorInconsistent(fascia.anchor.witness_id_unchecked())
        })?;
        unsafe { self.consume_anchor(fascia.anchor)? };
        for (contract_id, bundle) in fascia.bundles {
            let ids1 = bundle
                .known_transitions
                .keys()
                .copied()
                .collect::<BTreeSet<_>>();
            let ids2 = bundle.input_map.values().copied().collect::<BTreeSet<_>>();
            if !ids1.is_subset(&ids2) {
                return Err(ConsumeError::InvalidBundle(contract_id, bundle.bundle_id()).into());
            }
            unsafe { self.consume_bundle(contract_id, bundle, witness_id)? };
        }
        Ok(())
    }

    #[doc(hidden)]
    unsafe fn consume_anchor(
        &mut self,
        anchor: XAnchor<mpc::MerkleBlock>,
    ) -> Result<(), InventoryError<Self::Error>>;

    #[doc(hidden)]
    unsafe fn consume_bundle(
        &mut self,
        contract_id: ContractId,
        bundle: TransitionBundle,
        witness_id: WitnessId,
    ) -> Result<(), InventoryError<Self::Error>>;

    /// # Safety
    ///
    /// Calling this method may lead to including into the stash asset
    /// information which may be invalid.
    unsafe fn import_contract_force<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, InventoryError<Self::Error>>
    where
        R::Error: 'static;

    fn contracts_by_iface<W: IfaceWrapper>(&self) -> Result<Vec<W>, InventoryError<Self::Error>>
    where
        Self::Error: From<<Self::Stash as Stash>::Error>,
        InventoryError<Self::Error>: From<<Self::Stash as Stash>::Error>,
    {
        self.contract_ids_by_iface(&W::IFACE_NAME.into())?
            .into_iter()
            .map(|id| self.contract_iface_wrapped(id))
            .collect()
    }

    fn contracts_by_iface_name(
        &self,
        iface: impl Into<TypeName>,
    ) -> Result<Vec<ContractIface>, InventoryError<Self::Error>>
    where
        Self::Error: From<<Self::Stash as Stash>::Error>,
        InventoryError<Self::Error>: From<<Self::Stash as Stash>::Error>,
    {
        let iface = iface.into();
        let iface_id = self.iface_by_name(&iface)?.iface_id();
        self.contract_ids_by_iface(&iface)?
            .into_iter()
            .map(|id| self.contract_iface_id(id, iface_id))
            .collect()
    }

    fn contract_iface_named(
        &self,
        contract_id: ContractId,
        iface: impl Into<TypeName>,
    ) -> Result<ContractIface, InventoryError<Self::Error>>
    where
        Self::Error: From<<Self::Stash as Stash>::Error>,
        InventoryError<Self::Error>: From<<Self::Stash as Stash>::Error>,
    {
        let iface = iface.into();
        let iface_id = self.iface_by_name(&iface)?.iface_id();
        self.contract_iface_id(contract_id, iface_id)
    }

    fn contract_iface_wrapped<W: IfaceWrapper>(
        &self,
        contract_id: ContractId,
    ) -> Result<W, InventoryError<Self::Error>> {
        self.contract_iface_id(contract_id, W::IFACE_ID)
            .map(W::from)
    }

    fn contract_iface_id(
        &self,
        contract_id: ContractId,
        iface_id: IfaceId,
    ) -> Result<ContractIface, InventoryError<Self::Error>>;

    fn anchored_bundle(&self, opid: OpId) -> Result<AnchoredBundle, InventoryError<Self::Error>>;

    fn transition_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<TypeName>,
        transition_name: Option<impl Into<TypeName>>,
    ) -> Result<TransitionBuilder, InventoryError<Self::Error>>
    where
        Self::Error: From<<Self::Stash as Stash>::Error>,
    {
        let schema_ifaces = self.contract_schema(contract_id)?;
        let iface = self.iface_by_name(&iface.into())?;
        let schema = &schema_ifaces.schema;
        let iimpl = schema_ifaces
            .iimpls
            .get(&iface.iface_id())
            .ok_or(DataError::NoIfaceImpl(schema.schema_id(), iface.iface_id()))?;
        let mut builder = if let Some(transition_name) = transition_name {
            TransitionBuilder::named_transition(
                iface.clone(),
                schema.clone(),
                iimpl.clone(),
                transition_name.into(),
            )
        } else {
            TransitionBuilder::default_transition(iface.clone(), schema.clone(), iimpl.clone())
        }
        .expect("internal inconsistency");
        let tags = self.contract_asset_tags(contract_id)?;
        for (assignment_type, asset_tag) in tags {
            builder = builder
                .add_asset_tag_raw(*assignment_type, *asset_tag)
                .expect("tags are in bset and must not repeat");
        }
        Ok(builder)
    }

    fn blank_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<TypeName>,
    ) -> Result<TransitionBuilder, InventoryError<Self::Error>>
    where
        Self::Error: From<<Self::Stash as Stash>::Error>,
    {
        let schema_ifaces = self.contract_schema(contract_id)?;
        let iface = self.iface_by_name(&iface.into())?;
        let schema = &schema_ifaces.schema;
        if schema_ifaces.iimpls.is_empty() {
            return Err(InventoryError::DataError(DataError::NoIfaceImpl(
                schema.schema_id(),
                iface.iface_id(),
            )));
        }

        let mut builder = if let Some(iimpl) = schema_ifaces.iimpls.get(&iface.iface_id()) {
            TransitionBuilder::blank_transition(iface.clone(), schema.clone(), iimpl.clone())
                .expect("internal inconsistency")
        } else {
            let (default_iface_id, default_iimpl) = schema_ifaces.iimpls.first_key_value().unwrap();
            let default_iface = self.iface_by_id(*default_iface_id)?;

            TransitionBuilder::blank_transition(
                default_iface.clone(),
                schema.clone(),
                default_iimpl.clone(),
            )
            .expect("internal inconsistency")
        };
        let tags = self.contract_asset_tags(contract_id)?;
        for (assignment_type, asset_tag) in tags {
            builder = builder
                .add_asset_tag_raw(*assignment_type, *asset_tag)
                .expect("tags are in bset and must not repeat");
        }

        Ok(builder)
    }

    fn transition(&self, opid: OpId) -> Result<&Transition, InventoryError<Self::Error>>;

    fn contracts_by_outputs(
        &self,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<BTreeSet<ContractId>, InventoryError<Self::Error>>;

    fn public_opouts(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>>;

    fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>>;

    fn opouts_by_terminals(
        &self,
        terminals: impl IntoIterator<Item = XChain<SecretSeal>>,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>>;

    #[allow(clippy::type_complexity)]
    fn state_for_outpoints(
        &self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<XOutpoint>>,
    ) -> Result<BTreeMap<(Opout, XOutputSeal), PresistedState>, InventoryError<Self::Error>>;

    fn store_seal_secret(
        &mut self,
        seal: XChain<GraphSeal>,
    ) -> Result<(), InventoryError<Self::Error>>;

    fn seal_secrets(&self) -> Result<BTreeSet<XChain<GraphSeal>>, InventoryError<Self::Error>>;

    #[allow(clippy::type_complexity)]
    fn export_contract(
        &self,
        contract_id: ContractId,
    ) -> Result<
        Bindle<Contract>,
        ConsignerError<Self::Error, <<Self as Deref>::Target as Stash>::Error>,
    > {
        let mut consignment = self.consign::<false>(contract_id, [], [])?;
        consignment.transfer = false;
        Ok(consignment.into())
        // TODO: Add known sigs to the bindle
    }

    #[allow(clippy::type_complexity)]
    fn transfer(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[XOutputSeal]>,
        secret_seals: impl AsRef<[XChain<SecretSeal>]>,
    ) -> Result<
        Bindle<Transfer>,
        ConsignerError<Self::Error, <<Self as Deref>::Target as Stash>::Error>,
    > {
        let mut consignment = self.consign(contract_id, outputs, secret_seals)?;
        consignment.transfer = true;
        Ok(consignment.into())
        // TODO: Add known sigs to the bindle
    }

    fn consign<const TYPE: bool>(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[XOutputSeal]>,
        secret_seals: impl AsRef<[XChain<SecretSeal>]>,
    ) -> Result<
        Consignment<TYPE>,
        ConsignerError<Self::Error, <<Self as Deref>::Target as Stash>::Error>,
    > {
        let outputs = outputs.as_ref();
        let secret_seals = secret_seals.as_ref();

        // 1. Collect initial set of anchored bundles
        // 1.1. Get all public outputs
        let mut opouts = self.public_opouts(contract_id)?;

        // 1.2. Add outputs requested by the caller
        opouts.extend(self.opouts_by_outputs(contract_id, outputs.iter().copied())?);
        opouts.extend(self.opouts_by_terminals(secret_seals.iter().copied())?);

        // 1.3. Collect all state transitions assigning state to the provided outpoints
        let mut anchored_bundles = BTreeMap::<OpId, AnchoredBundle>::new();
        let mut transitions = BTreeMap::<OpId, Transition>::new();
        let mut terminals = BTreeMap::<BundleId, XChain<Terminal>>::new();
        for opout in opouts {
            if opout.op == contract_id {
                continue; // we skip genesis since it will be present anywhere
            }
            let transition = self.transition(opout.op)?;
            transitions.insert(opout.op, transition.clone());
            let anchored_bundle = self.anchored_bundle(opout.op)?;

            // 2. Collect seals from terminal transitions to add to the consignment
            // terminals
            let bundle_id = anchored_bundle.bundle.bundle_id();
            for (type_id, typed_assignments) in transition.assignments.iter() {
                for index in 0..typed_assignments.len_u16() {
                    let seal = typed_assignments.to_confidential_seals()[index as usize];
                    if secret_seals.contains(&seal) {
                        terminals
                            .insert(bundle_id, seal.map(TerminalSeal::from).map(Terminal::new));
                    } else if opout.no == index && opout.ty == *type_id {
                        if let Some(seal) = typed_assignments
                            .revealed_seal_at(index)
                            .expect("index exists")
                        {
                            terminals.insert(
                                bundle_id,
                                seal.map(|s| s.conceal())
                                    .map(TerminalSeal::from)
                                    .map(Terminal::new),
                            );
                        } else {
                            return Err(ConsignerError::ConcealedPublicState(opout));
                        }
                    }
                }
            }

            anchored_bundles.insert(opout.op, anchored_bundle.clone());
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
            anchored_bundles
                .entry(id)
                .or_insert(self.anchored_bundle(id)?.clone())
                .bundle
                .reveal_transition(transition.clone())?;
        }

        let genesis = self.genesis(contract_id)?;
        let schema_ifaces = self.schema(genesis.schema_id)?;
        let asset_tags = self.contract_asset_tags(contract_id)?;
        let mut consignment =
            Consignment::new(schema_ifaces.schema.clone(), genesis.clone(), asset_tags.clone());
        for (iface_id, iimpl) in &schema_ifaces.iimpls {
            let iface = self.iface_by_id(*iface_id)?;
            consignment
                .ifaces
                .insert(*iface_id, IfacePair::with(iface.clone(), iimpl.clone()))
                .expect("same collection size");
        }
        consignment.bundles = Confined::try_from_iter(anchored_bundles.into_values())
            .map_err(|_| ConsignerError::TooManyBundles)?;
        consignment.terminals =
            Confined::try_from(terminals).map_err(|_| ConsignerError::TooManyTerminals)?;

        // TODO: Conceal everything we do not need
        // TODO: Add known sigs to the consignment

        Ok(consignment)
    }

    /// Composes a batch of state transitions updating state for the provided
    /// set of previous outputs, satisfying requirements of the invoice, paying
    /// the change back and including the necessary blank state transitions.
    fn compose(
        &self,
        invoice: &RgbInvoice,
        prev_outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
        method: CloseMethod,
        beneficiary_vout: Option<impl Into<Vout>>,
        allocator: impl Fn(ContractId, AssignmentType, VelocityHint) -> Option<Vout>,
    ) -> Result<Batch, ComposeError<Self::Error, <<Self as Deref>::Target as Stash>::Error>>
    where
        Self::Error: From<<Self::Stash as Stash>::Error>,
    {
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
    fn compose_deterministic(
        &self,
        invoice: &RgbInvoice,
        prev_outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
        method: CloseMethod,
        beneficiary_vout: Option<impl Into<Vout>>,
        allocator: impl Fn(ContractId, AssignmentType, VelocityHint) -> Option<Vout>,
        pedersen_blinder: impl Fn(ContractId, AssignmentType) -> BlindingFactor,
        seal_blinder: impl Fn(ContractId, AssignmentType) -> u64,
    ) -> Result<Batch, ComposeError<Self::Error, <<Self as Deref>::Target as Stash>::Error>>
    where
        Self::Error: From<<Self::Stash as Stash>::Error>,
    {
        let layer1 = invoice.layer1();
        let prev_outputs = prev_outputs
            .into_iter()
            .map(|o| o.into())
            .collect::<HashSet<XOutputSeal>>();

        #[allow(clippy::type_complexity)]
        let output_for_assignment = |id: ContractId,
                                     assignment_type: AssignmentType|
         -> Result<
            BuilderSeal<GraphSeal>,
            ComposeError<Self::Error, <<Self as Deref>::Target as Stash>::Error>,
        > {
            let suppl = self.contract_suppl(id);
            let velocity = suppl
                .and_then(|suppl| suppl.owned_state.get(&assignment_type))
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
                return Err(ComposeError::InvoiceExpired);
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
                return Err(ComposeError::NoBeneficiaryOutput);
            }
        };

        // 2. Prepare transition
        let mut main_inputs = MediumVec::<XOutputSeal>::new();
        let mut sum_inputs = Amount::ZERO;
        let mut data_inputs = vec![];
        for ((opout, output), mut state) in
            self.state_for_outpoints(contract_id, prev_outputs.iter().cloned())?
        {
            main_builder = main_builder.add_input(opout, state.clone())?;
            main_inputs.push(output)?;
            if opout.ty != assignment_id {
                let seal = output_for_assignment(contract_id, opout.ty)?;
                state.update_blinding(pedersen_blinder(contract_id, assignment_id));
                main_builder = main_builder.add_owned_state_raw(opout.ty, seal, state)?;
            } else if let PresistedState::Amount(value, _, _) = state {
                sum_inputs += value;
            } else if let PresistedState::Data(value, _) = state {
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
                    Ordering::Less => return Err(ComposeError::InsufficientState),
                    Ordering::Equal => {}
                }
                main_builder
                    .add_fungible_state_raw(
                        assignment_id,
                        beneficiary,
                        amt,
                        pedersen_blinder(contract_id, assignment_id),
                    )?
                    .complete_transition(contract_id)?
            }
            InvoiceState::Data(data) => match data {
                NonFungible::RGB21(allocation) => {
                    if !data_inputs.into_iter().any(|x| x == allocation.into()) {
                        return Err(ComposeError::InsufficientState);
                    }

                    main_builder
                        .add_data_raw(
                            assignment_id,
                            beneficiary,
                            allocation,
                            seal_blinder(contract_id, assignment_id),
                        )?
                        .complete_transition(contract_id)?
                }
            },
            _ => {
                todo!("only TypedState::Amount and TypedState::Allocation are currently supported")
            }
        };

        // 3. Prepare other transitions
        // Enumerate state
        let mut spent_state =
            HashMap::<ContractId, BTreeMap<(Opout, XOutputSeal), PresistedState>>::new();
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
            for ((opout, output), mut state) in opouts {
                let seal = output_for_assignment(id, opout.ty)?;
                outputs.push(output);
                if let PresistedState::Amount(_, ref mut blinding, _) = state {
                    *blinding = pedersen_blinder(id, opout.ty);
                }
                blank_builder = blank_builder
                    .add_input(opout, state.clone())?
                    .add_owned_state_raw(opout.ty, seal, state)?;
            }

            let transition = blank_builder.complete_transition(id)?;
            blanks.push(TransitionInfo::new(transition, outputs)?)?;
        }

        Ok(Batch {
            main: TransitionInfo::new(main_transition, main_inputs)?,
            blanks,
        })
    }
}
