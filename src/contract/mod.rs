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
use rgb::vm::AssignmentWitness;
use rgb::OpId;

use crate::LIB_NAME_RGB_STD;

/// Reference to operation element.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display("{op}/{no}")]
pub struct OpEl {
    pub op: OpId,
    pub no: u16,
    pub witness: AssignmentWitness,
}

impl OpEl {
    pub fn new(op: OpId, no: u16, witness: AssignmentWitness) -> OpEl { OpEl { op, no, witness } }
}
