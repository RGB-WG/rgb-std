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

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

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
mod mound;
mod info;
pub mod popls;

#[cfg(feature = "bitcoin")]
pub use bp::{Outpoint, Txid};
pub use hypersonic::*;
pub use info::ContractInfo;
#[cfg(feature = "fs")]
pub use mound::file::{DirExcavator, DirMound};
pub use mound::{Excavate, IssueError, Mound, MoundConsumeError, MAGIC_BYTES_CONSIGNMENT};
#[cfg(feature = "fs")]
pub use pile::fs::FilePile;
pub use pile::{Index, Pile};
pub use rgb::*;
pub use stockpile::{Assignment, ConsumeError, CreateParams, EitherSeal, Stockpile};
