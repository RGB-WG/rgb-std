// Invoice Library for RGB smart contracts
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

#[macro_use]
extern crate amplify;
#[cfg(feature = "bp")]
#[macro_use]
extern crate strict_encoding;

#[cfg(feature = "bp")]
pub mod bp;

use core::str::FromStr;

use hypersonic::{AuthToken, ContractId};
use rgbcore::SealType;
use sonic_callreq::CallRequest;

#[derive(Clone, Eq, PartialEq, Debug, Display)]
pub enum RgbScope {
    #[display(inner)]
    ContractId(ContractId),

    #[display("contract:{seal}")]
    ContractQuery { seal: SealType, testnet: bool },
}

impl FromStr for RgbScope {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> { todo!() }
}

#[derive(Clone, Eq, PartialEq, Debug, Display)]
#[display(inner)]
pub enum RgbBeneficiary {
    Token(AuthToken),

    #[cfg(feature = "bp")]
    WitnessOut(bp::WitnessOut),
}

impl FromStr for RgbBeneficiary {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> { todo!() }
}

pub type RgbInvoice = CallRequest<RgbScope, RgbBeneficiary>;
