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
use std::ops::{Deref, DerefMut};

use amplify::confinement::{ConfinedVec, TinyBlob};
use baid64::Baid64ParseError;
use chrono::{DateTime, Utc};
use hypersonic::{AuthToken, CallState, Consensus, ContractId, Endpoint};
use sonic_callreq::{CallRequest, CallScope};
use strict_types::{StrictVal, TypeName};

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

pub struct RgbInvoice<T: Display + FromStr>(CallRequest<T, RgbBeneficiary>);

impl<T: Display + FromStr> RgbInvoice<T> {
    pub fn new(
        scope: T,
        beneficiary: RgbBeneficiary,
        // Core parameters
        value: Option<u64>,
        expiry_time: Option<DateTime<Utc>>,
        // Additional fields
        api: Option<TypeName>,
        call: Option<CallState>,
        lock: Option<TinyBlob>,
        endpoints: Option<impl Into<ConfinedVec<Endpoint, 0, 10>>>,
    ) -> Self {
        Self(CallRequest {
            scope,
            auth: beneficiary,
            data: value.map(StrictVal::num),
            expiry: expiry_time,
            api,
            call,
            lock,
            endpoints: endpoints.map(|e| e.into()).unwrap_or_default(),
            unknown_query: Default::default(),
        })
    }
}

impl<T: Display + FromStr> From<RgbInvoice<T>> for CallRequest<T, RgbBeneficiary> {
    fn from(val: RgbInvoice<T>) -> Self { val.0 }
}

impl<T: Display + FromStr> Deref for RgbInvoice<T> {
    type Target = CallRequest<T, RgbBeneficiary>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl<T: Display + FromStr> DerefMut for RgbInvoice<T> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}
