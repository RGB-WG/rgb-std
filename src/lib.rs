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

#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    // missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

// CORE LIB:
// issue    :: Schema, Metadata, {GlobalState}, {Assignments} -> Genesis
//
// STD LIB:
// import   :: Stash, (Schema | Interface) -> Stash
// state    :: Inventory, ContractId -> ContractState
// interpret :: ContractState, Interface -> InterpretedState
//
// issue    :: Schema, State, Interface -> Consignment -- calls `core::issue`
//                                                     -- internally
// extract  :: Inventory, ContractId, Interface -> Consignment
//          -- contract transfer
//
// compose  :: Inventory, ContractId, Interface, [Outpoint] -> Consignment
//          -- base for state transfer describing existing state
// transfer :: Consignment, (...) -> StateTransition -- prepares transition
// preserve :: Stash, [Outpoint], StateTransition -> [StateTransition]
//          -- creates blank state transitions
// consign  :: Stash, StateTransition -> Consignment -- extracts history data
//
// reveal   :: Consignment, RevealInfo -> Consignment -- removes blinding from
//                                                    -- known UTXOs
// validate :: Consignment -> (Validity, ContractUpdate)
// enclose  :: Inventory, Disclosure -> Inventory !!
// consume  :: Inventory, Consignment -> Inventory !! -- for both transfers and
//                                                    -- contracts
//
// endpoints :: Consignment -> [Outpoint] -- used to construct initial PSBT

// WALLET LIB:
// embed     :: Psbt, ContractId -> Psbt -- adds contract information to PSBT
// commit    :: Psbt, ContractId, Transition -> Psbt -- adds transition
//                                                   -- information to the PSBT
// bundle    :: Psbt -> Psbt -- takes individual transitions and bundles them
// finalize  :: Psbt -> Psbt -- should be performed by BP; converts individual
//                           -- commitments into tapret

extern crate core;
#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate commit_verify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

/// Re-exporting all invoice data types (RGB and BP).
pub extern crate invoice;

pub mod stl;
pub mod interface;
pub mod containers;
pub mod persistence;
pub mod resolvers;
mod contract;
pub mod info;

pub use bp::{Outpoint, Txid};
pub use contract::{BundleExt, MergeReveal, MergeRevealError, RevealError, TypedAssignsExt};
pub use invoice::{Allocation, Amount, CoinAmount, OwnedFraction, Precision, TokenIndex};
pub use rgb::prelude::*;
pub use stl::{LIB_NAME_RGB_CONTRACT, LIB_NAME_RGB_STD};

/// BIP32 derivation index for outputs which may contain assigned RGB state.
pub const RGB_NATIVE_DERIVATION_INDEX: u32 = 9;
/// BIP32 derivation index for outputs which are tweaked with Tapret commitment
/// and may also optionally contain assigned RGB state.
pub const RGB_TAPRET_DERIVATION_INDEX: u32 = 10;
