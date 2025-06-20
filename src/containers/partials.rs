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

use amplify::confinement::{Confined, NonEmptyOrdMap, U24};
use rgb::{ContractId, Transition, TransitionBundle, Txid};
use strict_encoding::{
    StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, StrictType,
};

use super::SealWitness;
use crate::LIB_NAME_RGB_STD;

/// A batch of state transitions under different contracts which are associated
/// with some specific transfer and will be anchored within a single layer 1
/// transaction.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Batch {
    pub main: Transition,
    pub extras: Confined<Vec<Transition>, 0, { U24 - 1 }>,
}

impl StrictSerialize for Batch {}
impl StrictDeserialize for Batch {}

impl IntoIterator for Batch {
    type Item = Transition;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let mut vec = self.extras.release();
        vec.push(self.main);
        vec.into_iter()
    }
}

impl Batch {
    pub fn set_priority(&mut self, priority: u64) {
        self.main.nonce = priority;
        for transition in &mut self.extras {
            transition.nonce = priority;
        }
    }
}

/// Structure exported from a PSBT for merging into the stash. It contains a set
/// of finalized state transitions (under multiple contracts), packed into
/// bundles, and anchored to a single layer 1 transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Fascia {
    pub seal_witness: SealWitness,
    pub bundles: NonEmptyOrdMap<ContractId, TransitionBundle, U24>,
}

impl StrictDumb for Fascia {
    fn strict_dumb() -> Self {
        Fascia {
            seal_witness: strict_dumb!(),
            bundles: NonEmptyOrdMap::with_key_value(strict_dumb!(), strict_dumb!()),
        }
    }
}
impl StrictSerialize for Fascia {}
impl StrictDeserialize for Fascia {}

impl Fascia {
    pub fn witness_id(&self) -> Txid { self.seal_witness.public.txid() }

    pub fn into_bundles(self) -> impl IntoIterator<Item = (ContractId, TransitionBundle)> {
        self.bundles.into_iter()
    }
}
