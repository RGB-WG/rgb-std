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

use core::slice;
use std::collections::{btree_map, BTreeSet};

use bp::{Outpoint, Txid};
use commit_verify::mpc;
use rgb::validation::{ConsistencyError, ContainerApi, HistoryApi};
use rgb::{
    seal, Anchor, BundleId, Extension, Genesis, OpId, Operation, OwnedStateType, Schema,
    Transition, TransitionBundle,
};

pub trait ConsignmentApi {}

pub struct Consignment<C: ConsignmentApi>(pub C);

impl<C: ConsignmentApi> ContainerApi for Consignment<C> {
    fn node_by_id(&self, node_id: OpId) -> Option<&dyn Operation> { todo!() }

    fn bundle_by_id(&self, bundle_id: BundleId) -> Result<&TransitionBundle, ConsistencyError> {
        todo!()
    }

    fn known_transitions_by_bundle_id(
        &self,
        bundle_id: BundleId,
    ) -> Result<Vec<&Transition>, ConsistencyError> {
        todo!()
    }

    fn transition_by_id(&self, node_id: OpId) -> Result<&Transition, ConsistencyError> { todo!() }

    fn extension_by_id(&self, node_id: OpId) -> Result<&Extension, ConsistencyError> { todo!() }

    fn transition_witness_by_id(
        &self,
        node_id: OpId,
    ) -> Result<(&Transition, Txid), ConsistencyError> {
        todo!()
    }

    fn seals_closed_with(
        &self,
        node_id: OpId,
        owned_right_type: impl Into<OwnedStateType>,
        witness: Txid,
    ) -> Result<BTreeSet<Outpoint>, ConsistencyError> {
        todo!()
    }
}

impl<C: ConsignmentApi> HistoryApi for Consignment<C> {
    type EndpointIter<'container> = btree_map::Iter<'container, BundleId, seal::Confidential> where Self: 'container;
    type BundleIter<'container> =
        btree_map::Iter<'container, Anchor<mpc::MerkleProof>, TransitionBundle> where Self: 'container;
    type ExtensionsIter<'container> = slice::Iter<'container, Extension> where Self: 'container;

    fn schema(&self) -> &Schema { todo!() }

    fn root_schema(&self) -> Option<&Schema> { todo!() }

    fn genesis(&self) -> &Genesis { todo!() }

    fn node_ids(&self) -> BTreeSet<OpId> { todo!() }

    fn endpoints(&self) -> Self::EndpointIter<'_> { todo!() }

    fn anchored_bundles(&self) -> Self::BundleIter<'_> { todo!() }

    fn state_extensions(&self) -> Self::ExtensionsIter<'_> { todo!() }
}
