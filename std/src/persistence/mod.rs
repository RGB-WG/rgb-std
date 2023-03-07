// RGB standard library for working with smart contracts on Bitcoin & Lightning
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

//! Module defines API used by providers of persistent data for RGB contracts.
//!
//! These data include:
//! 1. [`Stash`]: a consensus-critical data for client-side-validation which
//!    must be preserved and backed up.
//! 2. [`ContractState`], updated with each enclosed consignment and disclosure.
//! 3. [`Index`] over stash, which simplifies construction of a new
//!    consignments.
//! 4. [`Inventory`], which abstracts stash, contract states and
//!    index for complex operations requiring participation of all of them.
//!
//! 2-4 data can be re-computed from the stash in case of loss or corruption.

mod stash;
mod stock;
mod inventory;
mod index;
