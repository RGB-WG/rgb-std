// RGB wallet library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

//! Library provides three main procedures:
//!
//! ## 1. PSBT-based state transition construction.
//!
//! Given PSBT-originating set of outpoints the procedure creates all required
//! state transitions for all contracts, adding necessary information to PSBT
//! for constructing bundles and tapret proofs. The actual state transitions are
//! saved into the stash even before witness transactions are mined. They may be
//! also put into PSBT, if needed for the hardware signers.
//!
//! ## 2. PSBT-based finalization.
//!
//! Procedure takes PSBT with all information for constructing transition
//! bundles and taprets and
//! a) generates final tapret commitment;
//! b) creates consignment for the main transfer.
//!
//! ## 3. Descriptor-based contract state.
//!
//! Checks descriptor UTXO set and updates contract, removing outdated outputs.
//! For instance, after consignment creation, a new state transition is already
//! present in the contract state, even before the witness transaction is mined.
//! Descriptor filtering of the contract state will show a valid result, since
//! a new state without mined witness will not be displayed. Once the witness
//! gets mined, a new state appears, and previous state gets invalidated since
//! it no longer assigned to an unspent transaction output.

#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[macro_use]
extern crate amplify;

mod invoice;
mod pay;
pub mod psbt;

pub use invoice::{
    Beneficiary, InvoiceParseError, InvoiceState, RgbInvoice, RgbTransport, TransportParseError,
};
pub use pay::{InventoryWallet, PayError};

// 1. Construct main state transition with transition builder
// -- shortcut using invoice to do that construction (like .with_invoice())
// -- have a construction for the "remaining state" assigned to a seal
//    prototype.
// 2. Add that state transition to PSBT
// -- add change by checking change PSBT flag and assigning remaining state to
//    that output
// 3. Extract from PSBT all spent prevouts and construct blank state transitions
//    for each one of them; embed them into PSBT
