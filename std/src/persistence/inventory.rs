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

use std::collections::BTreeSet;
use std::error::Error;
use std::ops::Deref;

use amplify::confinement;
use bp::Txid;
use commit_verify::mpc;
use rgb::{validation, ContractId, OpId, SchemaId, SubSchema, TransitionType};

use crate::accessors::RevealError;
use crate::builders::{ConsignerError, ConsignmentBuilder, OutpointFilter};
use crate::containers::{Bindle, Cert, Consignment, ContentId, Contract, Transfer};
use crate::interface::{ContractIface, Iface, IfaceId, IfaceImpl};
use crate::persistence::stash::StashInconsistency;
use crate::persistence::{Stash, StashError};
use crate::resolvers::ResolveHeight;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum InventoryError<E: Error> {
    /// I/O or connectivity error.
    Connectivity(E),

    /// error in input data.
    #[from]
    DataError(DataError),

    /// Permanent errors caused by bugs in the business logic of this library.
    /// Must be reported to LNP/BP Standards Association.
    #[from]
    #[from(StashInconsistency)]
    InternalInconsistency(InventoryInconsistency),
}

impl<E1: Error, E2: Error> From<StashError<E1>> for InventoryError<E2>
where E2: From<E1>
{
    fn from(err: StashError<E1>) -> Self {
        match err {
            StashError::Connectivity(err) => Self::Connectivity(err.into()),
            StashError::InternalInconsistency(e) => Self::InternalInconsistency(e.into()),
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
    DataError(DataError),
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

    #[from]
    Confinement(confinement::Error),

    #[from]
    IfaceImpl(IfaceImplError),

    #[from]
    HeightResolver(Box<dyn Error>),
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

    /// disclosure for txid {0} is absent
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// inventory inconsistency and compromised inventory data storage.
    DisclosureAbsent(Txid),

    /// operation {0} is not related to any contract - or at least not present
    /// in operation-to-contract index.
    ///
    /// It may happen due to RGB Node bug, or indicate internal inventory
    /// inconsistency and compromised inventory data storage.
    OpContractAbsent(OpId),

    /// the anchor is not related to the contract
    ///
    /// It may happen due to RGB Node bug, or indicate internal inventory
    /// inconsistency and compromised inventory data storage.
    #[from(mpc::LeafNotKnown)]
    UnrelatedAnchor,

    /// bundle reveal error. Details: {0}
    ///
    /// It may happen due to RGB Node bug, or indicate internal inventory
    /// inconsistency and compromised inventory data storage.
    #[from]
    BundleReveal(RevealError),

    /// the resulting bundle size exceeds consensus restrictions
    ///
    /// It may happen due to RGB Node bug, or indicate internal inventory
    /// inconsistency and compromised inventory data storage.
    OutsizedBundle,

    #[from]
    #[display(inner)]
    Stash(StashInconsistency),
}

pub trait Inventory: Deref<Target = Self::Stash> {
    type Stash: Stash;
    /// Error type which must indicate problems on data retrieval.
    type Error: Error + From<<Self::Stash as Stash>::Error>;

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
    ) -> Result<validation::Status, InventoryDataError<Self::Error>>
    where
        R::Error: 'static;

    /// # Safety
    ///
    /// Calling this method may lead to including into the stash asset
    /// information which may be invalid.
    unsafe fn import_contract_force<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>>
    where
        R::Error: 'static;

    fn contract_iface(
        &mut self,
        contract_id: ContractId,
        iface_id: IfaceId,
    ) -> Result<ContractIface, InventoryError<Self::Error>>;

    fn contract_transition_ids(
        &mut self,
        contract_id: ContractId,
        transition_type: TransitionType,
    ) -> Result<BTreeSet<OpId>, InventoryError<Self::Error>>;

    fn export_contract(
        &mut self,
        contract_id: ContractId,
    ) -> Result<Bindle<Contract>, ConsignerError<Self::Error>> {
        // TODO: Add known sigs to the bindle
        self.consign(contract_id, &OutpointFilter::None)
            .map(Bindle::from)
    }

    fn transfer(
        &mut self,
        contract_id: ContractId,
        outpoint_filter: &OutpointFilter,
    ) -> Result<Bindle<Transfer>, ConsignerError<Self::Error>> {
        // TODO: Add known sigs to the bindle
        self.consign(contract_id, outpoint_filter).map(Bindle::from)
    }

    fn consign<const TYPE: bool>(
        &mut self,
        contract_id: ContractId,
        outpoint_filter: &OutpointFilter,
    ) -> Result<Consignment<TYPE>, ConsignerError<Self::Error>> {
        ConsignmentBuilder::build(self, contract_id, outpoint_filter)
    }

    /*
    fn accept<const TYPE: bool>(
        &mut self,
        consignment: Consignment<TYPE>,
    ) -> Result<(), Self::ImportError>;
     */
}
