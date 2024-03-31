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

use std::collections::{btree_set, BTreeMap, BTreeSet};
use std::ops::Deref;
use std::rc::Rc;

use amplify::confinement::Collection;
use commit_verify::Conceal;
use rgb::validation::ConsignmentApi;
use rgb::{
    AssetTag, AssignmentType, BundleId, Genesis, OpId, OpRef, Operation, Schema,
    TransitionBundle, XChain, XGrip, XWitnessId,
};

use super::{AnchoredBundle, Consignment};
use crate::SecretSeal;

// TODO: Transform consignment into this type instead of composing over it
#[derive(Clone, Debug)]
pub struct IndexedConsignment<'c, const TYPE: bool> {
    consignment: &'c Consignment<TYPE>,
    op_witness_idx: BTreeMap<OpId, XWitnessId>,
}

impl<'c, const TYPE: bool> Deref for IndexedConsignment<'c, TYPE> {
    type Target = Consignment<TYPE>;

    fn deref(&self) -> &Self::Target { self.consignment }
}

impl<'c, const TYPE: bool> IndexedConsignment<'c, TYPE> {
    pub fn new(consignment: &'c Consignment<TYPE>) -> Self {
        let mut op_witness_idx = BTreeMap::new();
        for ab in &consignment.bundles {
            for opid in ab.bundle.known_transitions.keys() {
                op_witness_idx.insert(*opid, ab.grip.witness_id());
            }
        }
        Self {
            consignment,
            op_witness_idx,
        }
    }
}

impl<'c, const TYPE: bool> ConsignmentApi for IndexedConsignment<'c, TYPE> {
    type Iter<'a> = BundleIdIter;

    fn schema(&self) -> &Schema { &self.schema }

    #[inline]
    fn asset_tags(&self) -> &BTreeMap<AssignmentType, AssetTag> { self.asset_tags.as_inner() }

    fn operation(&self, opid: OpId) -> Option<OpRef> {
        if opid == self.genesis.id() {
            return Some(OpRef::Genesis(&self.genesis));
        }
        self.transition(opid)
            .map(OpRef::from)
            .or_else(|| self.extension(opid).map(OpRef::from))
    }

    fn genesis(&self) -> &Genesis { &self.genesis }

    fn terminals(&self) -> BTreeSet<(BundleId, XChain<SecretSeal>)> {
        let mut set = BTreeSet::new();
        for (bundle_id, terminal) in &self.terminals {
            for seal in &terminal.seals {
                set.push((*bundle_id, seal.conceal()));
            }
        }
        set
    }

    fn bundle_ids<'a>(&self) -> Self::Iter<'a> { BundleIdIter(self.bundles.clone().into_iter()) }

    fn bundle(&self, bundle_id: BundleId) -> Option<Rc<TransitionBundle>> {
        self.anchored_bundle(bundle_id)
            .map(|ab| Rc::new(ab.bundle.clone()))
    }

    fn grip(&self, bundle_id: BundleId) -> Option<XGrip> {
        self.anchored_bundle(bundle_id).map(|ab| ab.grip.clone())
    }

    fn op_witness_id(&self, opid: OpId) -> Option<XWitnessId> {
        self.op_witness_idx.get(&opid).copied()
    }
}

#[derive(Debug)]
pub struct BundleIdIter(btree_set::IntoIter<AnchoredBundle>);

impl Iterator for BundleIdIter {
    type Item = BundleId;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().as_ref().map(AnchoredBundle::bundle_id)
    }
}
