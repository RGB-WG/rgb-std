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

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ops::Deref;

use amplify::confinement::{self, Confined};
use bp::Txid;
use commit_verify::mpc;
use rgb::{
    validation, Anchor, AnchoredBundle, BundleId, ContractId, ExposedSeal, GraphSeal, OpId,
    Operation, Opout, SchemaId, SecretSeal, SubSchema, Transition, TransitionBundle,
};
use strict_encoding::TypeName;

use crate::accessors::{BundleExt, MergeRevealError, RevealError};
use crate::containers::{
    Bindle, BuilderSeal, Cert, Consignment, ContentId, Contract, Terminal, Transfer,
};
use crate::interface::{
    ContractIface, Iface, IfaceId, IfaceImpl, IfacePair, TransitionBuilder, TypedState,
};
use crate::persistence::hoard::ConsumeError;
use crate::persistence::stash::StashInconsistency;
use crate::persistence::{Stash, StashError};
use crate::resolvers::ResolveHeight;
use crate::Outpoint;

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ConsignerError<E1: Error, E2: Error> {
    /// unable to construct consignment: too many terminals provided.
    TooManyTerminals,

    /// unable to construct consignment: history size too large, resulting in
    /// too many transitions.
    TooManyBundles,

    #[display(inner)]
    #[from]
    Reveal(RevealError),

    #[display(inner)]
    #[from]
    #[from(InventoryInconsistency)]
    InventoryError(InventoryError<E1>),

    #[display(inner)]
    #[from]
    #[from(StashInconsistency)]
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
    #[from(mpc::UnrelatedProof)]
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
#[display(inner)]
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

    #[display(inner)]
    #[from]
    Reveal(RevealError),

    #[from]
    #[display(inner)]
    Merge(MergeRevealError),

    /// outpoint {0} is not part of the contract {1}.
    OutpointUnknown(Outpoint, ContractId),

    #[from]
    Confinement(confinement::Error),

    #[from]
    IfaceImpl(IfaceImplError),

    /// schema {0} doesn't implement interface {1}.
    NoIfaceImpl(SchemaId, IfaceId),

    #[from]
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
    #[from(mpc::UnrelatedProof)]
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

    fn consume_anchor(
        &mut self,
        anchor: Anchor<mpc::MerkleBlock>,
    ) -> Result<(), InventoryError<Self::Error>>;

    fn consume_bundle(
        &mut self,
        contract_id: ContractId,
        bundle: TransitionBundle,
        witness_txid: Txid,
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

    fn contract_iface(
        &mut self,
        contract_id: ContractId,
        iface_id: IfaceId,
    ) -> Result<ContractIface, InventoryError<Self::Error>>;

    fn anchored_bundle(&self, opid: OpId) -> Result<AnchoredBundle, InventoryError<Self::Error>>;

    fn transition_builder(
        &mut self,
        contract_id: ContractId,
        iface: impl Into<TypeName>,
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
        let builder = TransitionBuilder::with(iface.clone(), schema.clone(), iimpl.clone())
            .expect("internal inconsistency");
        Ok(builder)
    }

    fn transition(&self, opid: OpId) -> Result<&Transition, InventoryError<Self::Error>>;

    fn contracts_by_outpoints(
        &mut self,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeSet<ContractId>, InventoryError<Self::Error>>;

    fn public_opouts(
        &mut self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>>;

    fn opouts_by_outpoints(
        &mut self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>>;

    fn opouts_by_terminals(
        &mut self,
        terminals: impl IntoIterator<Item = SecretSeal>,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>>;

    fn state_for_outpoints(
        &mut self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeMap<Opout, TypedState>, InventoryError<Self::Error>>;

    fn store_seal_secret(&mut self, seal: GraphSeal) -> Result<(), InventoryError<Self::Error>>;

    fn export_contract(
        &mut self,
        contract_id: ContractId,
    ) -> Result<
        Bindle<Contract>,
        ConsignerError<Self::Error, <<Self as Deref>::Target as Stash>::Error>,
    > {
        let mut consignment =
            self.consign::<GraphSeal, false>(contract_id, [] as [GraphSeal; 0])?;
        consignment.transfer = false;
        Ok(consignment.into())
        // TODO: Add known sigs to the bindle
    }

    fn transfer(
        &mut self,
        contract_id: ContractId,
        seals: impl IntoIterator<Item = impl Into<BuilderSeal<GraphSeal>>>,
    ) -> Result<
        Bindle<Transfer>,
        ConsignerError<Self::Error, <<Self as Deref>::Target as Stash>::Error>,
    > {
        let mut consignment = self.consign(contract_id, seals)?;
        consignment.transfer = true;
        Ok(consignment.into())
        // TODO: Add known sigs to the bindle
    }

    fn consign<Seal: ExposedSeal, const TYPE: bool>(
        &mut self,
        contract_id: ContractId,
        seals: impl IntoIterator<Item = impl Into<BuilderSeal<Seal>>>,
    ) -> Result<
        Consignment<TYPE>,
        ConsignerError<Self::Error, <<Self as Deref>::Target as Stash>::Error>,
    > {
        // 1. Collect initial set of anchored bundles
        let mut opouts = self.public_opouts(contract_id)?;
        let (outpoint_seals, terminal_seals) = seals
            .into_iter()
            .map(|seal| match seal.into() {
                BuilderSeal::Revealed(seal) => (seal.outpoint(), None),
                BuilderSeal::Concealed(seal) => (None, Some(seal)),
            })
            .unzip::<_, _, Vec<_>, Vec<_>>();
        let terminal_seals = terminal_seals.into_iter().flatten().collect::<Vec<_>>();
        opouts.extend(self.opouts_by_outpoints(contract_id, outpoint_seals.into_iter().flatten())?);
        opouts.extend(self.opouts_by_terminals(terminal_seals.iter().copied())?);

        // 1.1. Get all public transitions
        // 1.2. Collect all state transitions assigning state to the provided
        // outpoints
        let mut anchored_bundles = BTreeMap::<OpId, AnchoredBundle>::new();
        let mut transitions = BTreeMap::<OpId, Transition>::new();
        let mut terminals = BTreeSet::<Terminal>::new();
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
            for typed_assignments in transition.assignments.values() {
                for index in 0..typed_assignments.len_u16() {
                    if let Some(seal) = typed_assignments
                        .revealed_seal_at(index)
                        .expect("index exists")
                    {
                        terminals.insert(Terminal::with(bundle_id, seal.into()));
                    } else {
                        let seal = typed_assignments.to_confidential_seals()[index as usize];
                        if terminal_seals.contains(&seal) {
                            terminals.insert(Terminal::with(bundle_id, seal.into()));
                        }
                    }
                }
            }

            anchored_bundles.insert(opout.op, anchored_bundle.clone());
        }

        // 3. Collect all state transitions between terminals and genesis
        let mut ids = vec![];
        for transition in transitions.values() {
            ids.extend(transition.prev_outs().iter().map(|opout| opout.op));
        }
        while let Some(id) = ids.pop() {
            if id == contract_id {
                continue; // we skip genesis since it will be present anywhere
            }
            let transition = self.transition(id)?;
            ids.extend(transition.prev_outs().iter().map(|opout| opout.op));
            transitions.insert(id, transition.clone());
            anchored_bundles
                .entry(id)
                .or_insert(self.anchored_bundle(id)?.clone())
                .bundle
                .reveal_transition(&transition)?;
        }

        let genesis = self.genesis(contract_id)?;
        let schema_ifaces = self.schema(genesis.schema_id)?;
        let mut consignment = Consignment::new(schema_ifaces.schema.clone(), genesis.clone());
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
}
