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
#[cfg(any(feature = "bitcoin", feature = "liquid"))]
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[cfg(any(feature = "bitcoin", feature = "liquid"))]
pub mod bp;

use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

use baid64::Baid64ParseError;
use chrono::{DateTime, Utc};
use hypersonic::{AuthToken, Consensus, ContractId};
use sonic_callreq::{CallRequest, CallScope};
use strict_types::value::StrictNum;
use strict_types::StrictVal;

pub type RgbInvoice<T = CallScope<ContractQuery>> = CallRequest<T, RgbBeneficiary>;

#[derive(Clone, Eq, PartialEq, Debug, Display)]
#[display(inner)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase", untagged)
)]
pub enum RgbBeneficiary {
    Token(AuthToken),

    #[cfg(any(feature = "bitcoin", feature = "liquid"))]
    WitnessOut(bp::WitnessOut),
}

impl FromStr for RgbBeneficiary {
    type Err = ParseInvoiceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match AuthToken::from_str(s) {
            Ok(auth) => Ok(Self::Token(auth)),

            #[cfg(any(feature = "bitcoin", feature = "liquid"))]
            Err(_) => {
                let wout = bp::WitnessOut::from_str(s)?;
                Ok(Self::WitnessOut(wout))
            }
            #[cfg(not(any(feature = "bitcoin", feature = "liquid")))]
            Err(err) => Err(err),
        }
    }
}

#[cfg(any(feature = "bitcoin", feature = "liquid"))]
impl RgbBeneficiary {
    pub fn witness_out(&self) -> Option<&bp::WitnessOut> {
        match self {
            Self::WitnessOut(wout) => Some(wout),
            _ => None,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ContractQuery {
    pub consensus: Consensus,
    pub testnet: bool,
}

impl Display for ContractQuery {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.testnet {
            f.write_str("testnet@")?;
        }
        Display::fmt(&self.consensus, f)
    }
}

impl FromStr for ContractQuery {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let testnet = s.starts_with("testnet@");
        let s = s.trim_start_matches("testnet@");
        Consensus::from_str(s).map(|consensus| Self { consensus, testnet })
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

    #[cfg(any(feature = "bitcoin", feature = "liquid"))]
    #[from]
    Bp(bp::ParseWitnessOutError),
}

pub fn new_invoice(
    contract_id: ContractId,
    beneficiary: RgbBeneficiary,
    value: Option<u64>,
    expiry_time: Option<DateTime<Utc>>,
) -> RgbInvoice {
    let mut req = CallRequest::new(
        CallScope::ContractId(contract_id),
        beneficiary,
        value.map(|v: u64| StrictVal::num(v)),
    );

    if let Some(time) = expiry_time {
        req = req.use_expiry(time);
    }

    req
}
