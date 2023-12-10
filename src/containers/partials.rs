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

use std::collections::{btree_map, BTreeMap};

use amplify::confinement::{MediumOrdMap, MediumVec};
use bp::Outpoint;
use commit_verify::mpc;
use rgb::{Anchor, ContractId, OpId, Transition, TransitionBundle};

use crate::LIB_NAME_RGB_STD;

/// A batch of state transitions under different contracts which are associated
/// with some specific transfer and will be anchored within a single layer 1
/// transaction.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Batch {
    pub main_id: OpId,
    pub main_transition: Transition,
    pub main_inputs: MediumVec<Outpoint>,
    pub blank_transitions: MediumOrdMap<OpId, (Transition, MediumVec<Outpoint>)>,
}

#[derive(Debug)]
pub struct BatchIter(btree_map::IntoIter<OpId, (Transition, MediumVec<Outpoint>)>);

impl Iterator for BatchIter {
    type Item = (OpId, Transition, Vec<Outpoint>);

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|(id, (op, inputs))| (id, op, inputs.into_inner()))
    }
}

impl IntoIterator for Batch {
    type Item = (OpId, Transition, Vec<Outpoint>);
    type IntoIter = BatchIter;

    fn into_iter(self) -> Self::IntoIter {
        let mut map = self.blank_transitions.into_inner();
        map.insert(self.main_id, (self.main_transition, self.main_inputs));
        BatchIter(map.into_iter())
    }
}

/// Structure exported from a PSBT for merging into the stash. It contains a set
/// of finalized state transitions (under multiple contracts), packed into
/// bundles, and anchored to a single layer 1 transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Fascia {
    pub anchor: Anchor<mpc::MerkleBlock>,
    pub bundles: MediumVec<TransitionBundle>,
}
