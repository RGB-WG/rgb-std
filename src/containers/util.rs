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

use amplify::confinement::SmallOrdSet;
use rgb::{BundleId, WitnessId, XChain, XPubWitness};

use super::TerminalSeal;
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TerminalDisclose {
    pub bundle_id: BundleId,
    pub seal: XChain<TerminalSeal>,
    pub witness_id: Option<WitnessId>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Terminal {
    pub seals: SmallOrdSet<XChain<TerminalSeal>>,
    pub witness_tx: Option<XPubWitness>,
}

impl Terminal {
    pub fn new(seal: XChain<TerminalSeal>) -> Self {
        Terminal {
            seals: small_bset![seal],
            witness_tx: None,
        }
    }
    pub fn with_witness(seal: XChain<TerminalSeal>, witness_tx: XPubWitness) -> Self {
        Terminal {
            seals: small_bset![seal],
            witness_tx: Some(witness_tx),
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(lowercase)]
#[non_exhaustive]
#[repr(u8)]
pub enum ContainerVer {
    // V0 and V1 was a previous version before v0.11, currently not supported.
    #[default]
    V2 = 2,
}
