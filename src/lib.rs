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

// TODO: Activate no_std once StrictEncoding will support it
// #![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::type_complexity)]

extern crate alloc;

#[macro_use]
extern crate amplify;
extern crate rgbcore as rgb;

#[cfg(feature = "bitcoin")]
#[macro_use]
extern crate strict_encoding;
#[cfg(all(feature = "serde", feature = "bitcoin"))]
#[macro_use]
extern crate serde;

extern crate core;
pub extern crate rgb_invoice as invoice;

mod pile;
mod contract;
pub mod popls;
mod util;
mod contracts;
mod stockpile;
#[cfg(feature = "stl")]
pub mod stl;

#[cfg(feature = "bitcoin")]
pub use bp::{Outpoint, Txid};
pub use contract::{
    Assignment, ConsumeError, Contract, ContractState, CreateParams, EitherSeal, ImmutableState,
    OwnedState, CONSIGNMENT_MAGIC_NUMBER, CONSIGNMENT_VERSION,
};
pub use contracts::{Contracts, IssuerError};
pub use hypersonic::*;
#[cfg(feature = "fs")]
pub use pile::fs::PileFs;
pub use pile::{OpRels, Pile, Witness, WitnessStatus};
pub use rgb::*;
#[cfg(feature = "fs")]
pub use stockpile::dir::StockpileDir;
pub use stockpile::Stockpile;
pub use util::{ContractRef, InvalidContractRef};

// TODO: Move to amplify crate
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display(inner)]
pub enum TripleError<A: core::error::Error, B: core::error::Error, C: core::error::Error> {
    A(A),
    B(B),
    C(C),
}

impl<A: core::error::Error, B: core::error::Error, C: core::error::Error> TripleError<A, B, C> {
    pub fn from_a(a: impl Into<A>) -> Self { Self::A(a.into()) }
    pub fn from_b(a: impl Into<B>) -> Self { Self::B(a.into()) }
    pub fn from_c(c: impl Into<C>) -> Self { Self::C(c.into()) }

    pub fn from_other_a<A2: core::error::Error + Into<A>>(e: TripleError<A2, B, C>) -> Self {
        match e {
            TripleError::A(a) => Self::A(a.into()),
            TripleError::B(b) => Self::B(b),
            TripleError::C(c) => Self::C(c),
        }
    }

    pub fn from_other_b<B2: core::error::Error + Into<B>>(e: TripleError<A, B2, C>) -> Self {
        match e {
            TripleError::A(a) => Self::A(a),
            TripleError::B(b) => Self::B(b.into()),
            TripleError::C(c) => Self::C(c),
        }
    }

    pub fn from_other_c<C2: core::error::Error + Into<C>>(e: TripleError<A, B, C2>) -> Self {
        match e {
            TripleError::A(a) => Self::A(a),
            TripleError::B(b) => Self::B(b),
            TripleError::C(c) => Self::C(c.into()),
        }
    }
}

impl<A: core::error::Error, B: core::error::Error, C: core::error::Error> From<EitherError<A, B>>
    for TripleError<A, B, C>
{
    fn from(e: EitherError<A, B>) -> Self {
        match e {
            EitherError::A(a) => Self::A(a),
            EitherError::B(b) => Self::B(b),
        }
    }
}
