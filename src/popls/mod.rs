// Standard Library for RGB smart contracts
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

//! Proof of publication layers supported by RGB.

use core::str::FromStr;

#[cfg(any(feature = "bitcoin", feature = "liquid"))]
pub mod bp;
#[cfg(feature = "prime")]
pub mod prime;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[repr(u32)]
pub enum SealType {
    #[cfg(feature = "bitcoin")]
    #[display("bcor")]
    BitcoinOpret = rgb::BITCOIN_OPRET,

    #[cfg(feature = "bitcoin")]
    #[display("bctr")]
    BitcoinTapret = rgb::BITCOIN_TAPRET,

    #[cfg(feature = "liquid")]
    #[display("lqor")]
    LiquidOpret = rgb::LIQUID_OPRET,

    #[cfg(feature = "liquid")]
    #[display("lqtr")]
    LiquidTapret = rgb::LIQUID_TAPRET,

    #[cfg(feature = "prime")]
    #[display("prime")]
    Prime = rgb::PRIME_SEALS,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("unknown seal type `{0}`")]
pub struct UnknownType(String);

impl FromStr for SealType {
    type Err = UnknownType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "bitcoin")]
            "bcor" => Ok(SealType::BitcoinOpret),
            #[cfg(feature = "bitcoin")]
            "bctr" => Ok(SealType::BitcoinTapret),
            #[cfg(feature = "liquid")]
            "lqtr" => Ok(SealType::LiquidTapret),
            #[cfg(feature = "prime")]
            "prime" => Ok(SealType::Prime),
            _ => Err(UnknownType(s.to_string())),
        }
    }
}

impl From<u32> for SealType {
    fn from(caps: u32) -> Self {
        match caps {
            #[cfg(feature = "bitcoin")]
            rgb::BITCOIN_OPRET => Self::BitcoinOpret,
            #[cfg(feature = "bitcoin")]
            rgb::BITCOIN_TAPRET => Self::BitcoinTapret,
            #[cfg(feature = "liquid")]
            rgb::LIQUID_TAPRET => Self::LiquidTapret,
            #[cfg(feature = "prime")]
            rgb::PRIME_SEALS => Self::Prime,
            unknown => panic!("unknown seal type {unknown:#10x}"),
        }
    }
}
