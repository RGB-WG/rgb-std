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

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::rc::Rc;

use amplify::confinement::Collection;
use commit_verify::Conceal;
use rgb::validation::ConsignmentApi;
use rgb::{
    AssetTag, AssignmentType, BundleId, Extension, Genesis, Grip, OpId, OpRef, Operation, Schema,
    Transition, TransitionBundle, XChain, XGrip, XWitnessId,
};

use super::Consignment;
use crate::containers::anchors::ToWitnessId;
use crate::SecretSeal;

// TODO: Transform consignment into this type instead of composing over it
#[derive(Clone, Debug)]
pub struct IndexedConsignment<'c, const TYPE: bool> {
    consignment: &'c Consignment<TYPE>,
    grip_idx: BTreeMap<BundleId, XGrip>,
    bundle_idx: BTreeMap<BundleId, &'c TransitionBundle>,
    op_witness_idx: BTreeMap<OpId, XWitnessId>,
    op_bundle_idx: BTreeMap<OpId, BundleId>,
    extension_idx: BTreeMap<OpId, &'c Extension>,
}

impl<'c, const TYPE: bool> Deref for IndexedConsignment<'c, TYPE> {
    type Target = Consignment<TYPE>;

    fn deref(&self) -> &Self::Target { self.consignment }
}

impl<'c, const TYPE: bool> IndexedConsignment<'c, TYPE> {
    pub fn new(consignment: &'c Consignment<TYPE>) -> Self {
        let mut grip_idx = BTreeMap::new();
        let mut bundle_idx = BTreeMap::new();
        let mut op_witness_idx = BTreeMap::new();
        let mut op_bundle_idx = BTreeMap::new();
        let mut extension_idx = BTreeMap::new();
        for bw in &consignment.bundles {
            for bundle in bw.anchored_bundle.bundles() {
                let bundle_id = bundle.bundle_id();
                let witness_id = bw.pub_witness.to_witness_id();
                bundle_idx.insert(bundle_id, bundle);
                grip_idx.insert(
                    bundle_id,
                    witness_id.map(|id| Grip {
                        id,
                        anchors: bw.anchored_bundle.to_anchor_set(),
                    }),
                );
                for opid in bundle.known_transitions.keys() {
                    op_witness_idx.insert(*opid, witness_id);
                    op_bundle_idx.insert(*opid, bundle_id);
                }
            }
        }
        for extension in &consignment.extensions {
            extension_idx.insert(extension.id(), extension);
        }
        Self {
            consignment,
            grip_idx,
            bundle_idx,
            op_witness_idx,
            op_bundle_idx,
            extension_idx,
        }
    }

    fn extension(&self, opid: OpId) -> Option<&Extension> { self.extension_idx.get(&opid).copied() }

    fn transition(&self, opid: OpId) -> Option<&Transition> {
        self.op_bundle_idx
            .get(&opid)
            .and_then(|id| self.bundle_idx.get(id))
            .and_then(|bundle| bundle.known_transitions.get(&opid))
    }
}

impl<'c, const TYPE: bool> ConsignmentApi for IndexedConsignment<'c, TYPE> {
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

    fn bundle_ids<'a>(&self) -> impl Iterator<Item = BundleId> + 'a {
        self.bundle_idx
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
    }

    fn bundle<'a>(&self, bundle_id: BundleId) -> Option<impl AsRef<TransitionBundle> + 'a> {
        self.bundle_idx
            .get(&bundle_id)
            .copied()
            .cloned()
            .map(Rc::new)
    }

    fn grip<'a>(&self, bundle_id: BundleId) -> Option<impl AsRef<XGrip> + 'a> {
        self.grip_idx.get(&bundle_id).cloned().map(Rc::new)
    }

    fn op_witness_id(&self, opid: OpId) -> Option<XWitnessId> {
        self.op_witness_idx.get(&opid).copied()
    }
}
