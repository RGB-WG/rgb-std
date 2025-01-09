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

use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

use baid64::Baid64ParseError;
use hypersonic::{AuthToken, ContractId};
use rgbcore::{SealType, UnknownType};
use sonic_callreq::CallRequest;

pub type RgbInvoice = CallRequest<RgbScope, RgbBeneficiary>;

#[derive(Clone, Eq, PartialEq, Debug, Display)]
pub enum RgbScope {
    #[display(inner)]
    ContractId(ContractId),

    #[display("contract:{seal}")]
    ContractQuery { seal: SealType, testnet: bool },
}

impl FromStr for RgbScope {
    type Err = ParseInvoiceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("contract:") {
            return Err(ParseInvoiceError::NoScheme);
        }
        match ContractId::from_str(s) {
            Err(err1) => {
                let s = s.trim_start_matches("contract:");
                let query = ContractQuery::from_str(s)
                    .map_err(|_| ParseInvoiceError::Unrecognizable(err1))?;
                Ok(Self::ContractQuery { seal: query.seal, testnet: query.testnet })
            }
            Ok(id) => Ok(Self::ContractId(id)),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display)]
#[display(inner)]
pub enum RgbBeneficiary {
    Token(AuthToken),

    #[cfg(feature = "bp")]
    WitnessOut(bp::WitnessOut),
}

impl FromStr for RgbBeneficiary {
    type Err = ParseInvoiceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match AuthToken::from_str(s) {
            Ok(auth) => Ok(Self::Token(auth)),

            #[cfg(feature = "bp")]
            Err(_) => {
                let wout = bp::WitnessOut::from_str(s)?;
                Ok(Self::WitnessOut(wout))
            }
            #[cfg(not(feature = "bp"))]
            Err(err) => Err(err),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ContractQuery {
    pub seal: SealType,
    pub testnet: bool,
}

impl Display for ContractQuery {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.testnet {
            f.write_str("testnet@")?;
        }
        Display::fmt(&self.seal, f)
    }
}

impl FromStr for ContractQuery {
    type Err = UnknownType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let testnet = s.starts_with("testnet@");
        let s = s.trim_start_matches("testnet@");
        SealType::from_str(s).map(|seal| Self { seal, testnet })
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ParseInvoiceError {
    /// RGB invoice misses URI scheme prefix `contract:`.
    NoScheme,

    /// RGB invoice contains unrecognizable URI authority, which is neither contract id nor a
    /// contract query.
    Unrecognizable(Baid64ParseError),

    #[cfg(feature = "bp")]
    #[from]
    Bp(bp::ParseWitnessOutError),
}
