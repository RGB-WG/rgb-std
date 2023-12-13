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

use std::vec;

use amplify::confinement::MediumVec;
use commit_verify::mpc;
use rgb::{Anchor, OpId, Operation, Output, Transition, TransitionBundle};
use strict_encoding::{StrictDeserialize, StrictDumb, StrictSerialize};

use crate::LIB_NAME_RGB_STD;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct BatchItem {
    pub id: OpId,
    pub inputs: MediumVec<Output>,
    pub transition: Transition,
}

impl BatchItem {
    pub fn new(transition: Transition, inputs: MediumVec<Output>) -> Self {
        BatchItem {
            id: transition.id(),
            inputs,
            transition,
        }
    }
}

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
    pub main: BatchItem,
    pub blanks: MediumVec<BatchItem>,
}

impl StrictSerialize for Batch {}
impl StrictDeserialize for Batch {}

impl IntoIterator for Batch {
    type Item = BatchItem;
    type IntoIter = vec::IntoIter<BatchItem>;

    fn into_iter(self) -> Self::IntoIter {
        let mut vec = self.blanks.into_inner();
        vec.push(self.main);
        vec.into_iter()
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

impl StrictSerialize for Fascia {}
impl StrictDeserialize for Fascia {}
