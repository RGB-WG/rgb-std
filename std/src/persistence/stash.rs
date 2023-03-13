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

use std::collections::BTreeSet;
use std::error::Error;

use bp::Txid;
use commit_verify::mpc;
use rgb::{
    Anchor, ContractId, Genesis, OpId, SchemaId, Transition, TransitionBundle, TransitionType,
};

use crate::interface::{Iface, IfaceId, SchemaIfaces};

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
    IfaceNameAbsent(String),

    /// interfae {0} is unknown; you need to import it first.
    IfaceAbsent(IfaceId),

    /// contract is unknown. Probably you haven't imported the contract yet.
    GenesisAbsent(ContractId),

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
    TransitionAbsent(OpId),

    /// witness Txid is not known for transition {0}
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    TransitionTxidAbsent(OpId),

    /// anchor for txid {0} is absent
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    AnchorAbsent(Txid),

    /// bundle data for contract {0} txid {1} is absent
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    BundleAbsent(ContractId, Txid),
}

pub trait Stash {
    /// Error type which must indicate problems on data retrieval.
    type Error: Error;

    fn iface_by_name(&self, name: &str) -> Result<&Iface, StashError<Self::Error>>;

    fn iface_by_id(&self, id: IfaceId) -> Result<&Iface, StashError<Self::Error>>;

    fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, StashError<Self::Error>>;

    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, StashError<Self::Error>>;

    fn transition(&self, id: OpId) -> Result<&Transition, StashError<Self::Error>>;

    fn witness_txid(&self, id: OpId) -> Result<Txid, StashError<Self::Error>>;

    fn anchor(
        &self,
        witness_txid: Txid,
    ) -> Result<&Anchor<mpc::MerkleBlock>, StashError<Self::Error>>;

    fn bundle(
        &self,
        contract_id: ContractId,
        witness_txid: Txid,
    ) -> Result<&TransitionBundle, StashError<Self::Error>>;

    fn always_include_transitions(
        &self,
        schema_id: SchemaId,
    ) -> Result<BTreeSet<TransitionType>, StashError<Self::Error>> {
        let schema_ifaces = self.schema(schema_id)?;
        let mut set = BTreeSet::new();
        for (id, iimpl) in &schema_ifaces.iimpls {
            let iface = self.iface_by_id(*id)?;
            set.extend(
                iface
                    .transitions
                    .iter()
                    .filter(|(_, t)| t.always_include)
                    .filter_map(|(name, _)| iimpl.transition_type(name)),
            );
        }
        Ok(set)
    }
}
