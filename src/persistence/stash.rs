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

//use crate::containers::{Consignment, Contract, Transfer};

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use commit_verify::mpc;
use rgb::{
    AssetTag, AssignmentType, BundleId, ContractId, Extension, Genesis, OpId, SchemaId,
    TransitionBundle, WitnessId, XAnchor,
};
use strict_encoding::TypeName;

use crate::interface::{ContractSuppl, Iface, IfaceId, SchemaIfaces};

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum StashError<E: Error> {
    /// Connectivity errors which may be recoverable and temporary.
    Connectivity(E),

    /// Permanent errors caused by bugs in the business logic of this library.
    /// Must be reported to LNP/BP Standards Association.
    #[from]
    InternalInconsistency(StashInconsistency),
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StashInconsistency {
    /// interfae {0} is unknown; you need to import it first.
    IfaceNameAbsent(TypeName),

    /// interfae {0} is unknown; you need to import it first.
    IfaceAbsent(IfaceId),

    /// contract {0} is unknown. Probably you haven't imported the contract yet.
    ContractAbsent(ContractId),

    /// schema {0} is unknown.
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    SchemaAbsent(SchemaId),

    /// interface {0::<0} is not implemented for the schema {1::<0}.
    IfaceImplAbsent(IfaceId, SchemaId),

    /// transition {0} is absent.
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    OperationAbsent(OpId),

    /// anchor for txid {0} is absent.
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    AnchorAbsent(WitnessId),

    /// bundle {0} is absent.
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    BundleAbsent(BundleId),
}

pub trait Stash {
    /// Error type which must indicate problems on data retrieval.
    type Error: Error;

    fn schema_ids(&self) -> Result<BTreeSet<SchemaId>, Self::Error>;

    fn ifaces(&self) -> Result<BTreeMap<IfaceId, TypeName>, Self::Error>;

    fn iface_by_name(&self, name: &TypeName) -> Result<&Iface, StashError<Self::Error>>;

    fn iface_by_id(&self, id: IfaceId) -> Result<&Iface, StashError<Self::Error>>;

    fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, StashError<Self::Error>>;

    fn contract_ids(&self) -> Result<BTreeSet<ContractId>, Self::Error>;

    fn contract_ids_by_iface(&self, name: &TypeName) -> Result<BTreeSet<ContractId>, Self::Error>;

    fn contract_schema(
        &self,
        contract_id: ContractId,
    ) -> Result<&SchemaIfaces, StashError<Self::Error>> {
        let genesis = self.genesis(contract_id)?;
        self.schema(genesis.schema_id)
    }

    fn contract_suppl(&self, contract_id: ContractId) -> Option<&ContractSuppl>;
    fn contract_suppl_all(&self, contract_id: ContractId) -> Option<&TinyOrdSet<ContractSuppl>>;

    fn contract_asset_tags(
        &self,
        contract_id: ContractId,
    ) -> Result<&TinyOrdMap<AssignmentType, AssetTag>, StashError<Self::Error>>;

    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, StashError<Self::Error>>;

    fn bundle_ids(&self) -> Result<BTreeSet<BundleId>, Self::Error>;

    fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, StashError<Self::Error>>;

    fn extension_ids(&self) -> Result<BTreeSet<OpId>, Self::Error>;

    fn extension(&self, op_id: OpId) -> Result<&Extension, StashError<Self::Error>>;

    fn anchor(
        &self,
        witness_id: WitnessId,
    ) -> Result<&XAnchor<mpc::MerkleBlock>, StashError<Self::Error>>;
}
