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

// TODO: Activate once StrictEncoding will be no_std
// #![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    // TODO: Activate once StrictEncoding removes invalid unsafe fn modifiers from the raw reader
    // unsafe_code,
    dead_code,
    // TODO: Complete documentation
    // missing_docs,
    unused_variables,
    unused_mut,
    unused_imports,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![allow(clippy::type_complexity)]
#![cfg_attr(feature = "async", allow(async_fn_in_trait))]

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
mod stockpile;
mod contract;
mod consignment;
mod contracts;
pub mod popls;
mod util;
#[cfg(feature = "stl")]
pub mod stl;

#[cfg(feature = "bitcoin")]
pub use bp::{Outpoint, Txid};
pub use consignment::{parse_consignment, Consignment, MAX_CONSIGNMENT_OPS};
pub use contract::{
    Assignment, ConsumeError, Contract, ContractState, CreateParams, EitherSeal, ImmutableState,
    OwnedState,
};
#[cfg(feature = "binfile")]
pub use contracts::CONSIGN_MAGIC_NUMBER;
pub use contracts::{
    ContractStateName, Contracts, IssuerError, SyncError, WalletState, CONSIGN_VERSION,
};
pub use hypersonic::*;
pub use pile::{OpRels, Pile, Witness, WitnessStatus};
pub use rgb::*;
pub use stockpile::Stockpile;
pub use util::{ContractRef, InvalidContractRef};
