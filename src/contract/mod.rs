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

mod assignments;
mod bundle;
mod merge_reveal;

pub use assignments::{KnownState, OutputAssignment, TypedAssignsExt};
pub use bundle::{BundleExt, RevealError};
pub use merge_reveal::{MergeReveal, MergeRevealError};
use rgb::vm::OrdOpRef;
use rgb::{OpId, XWitnessId};

use crate::LIB_NAME_RGB_STD;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum OpWitness {
    #[strict_type(dumb)]
    Genesis,
    Transition(XWitnessId),
    Extension(XWitnessId),
}

impl From<OrdOpRef<'_>> for OpWitness {
    fn from(aor: OrdOpRef) -> Self {
        match aor {
            OrdOpRef::Genesis(_) => OpWitness::Genesis,
            OrdOpRef::Transition(_, witness_id, ..) => OpWitness::Transition(witness_id),
            OrdOpRef::Extension(_, witness_id, ..) => OpWitness::Transition(witness_id),
        }
    }
}

impl OpWitness {
    #[inline]
    pub fn witness_id(&self) -> Option<XWitnessId> {
        match self {
            OpWitness::Genesis => None,
            OpWitness::Transition(witness_id) | OpWitness::Extension(witness_id) => {
                Some(*witness_id)
            }
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalOut {
    pub opid: OpId,
    pub nonce: u8,
    pub index: u16,
    pub op_witness: OpWitness,
}

impl GlobalOut {
    #[inline]
    pub fn witness_id(&self) -> Option<XWitnessId> { self.op_witness.witness_id() }
}
