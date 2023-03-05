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

//! RGB containers are data packages which can be transferred between smart
//! contract users. There are two main types of containers:
//! 1. [`Consignments`], containing information about partial state of a *single
//!    contract*, extending from its genesis up to certain contract endpoints.
//! 2. [`Disclosures`], containing extracts from (possibly) independent state
//!    transitions and extensions under multiple contracts. Useful fro
//!    disclosing the concealed state for some other parties, and also for
//!    performing "change" operations on inventory during state transfers.

mod consignment;
mod disclosure;
mod bindle;
mod contract;
mod transfer;
mod seal;
mod util;
mod check;
mod certs;

pub use certs::{Certificate, ContentId, Identity, SignedOff};
pub use check::CheckError;
pub use consignment::{Consignment, Contract, Transfer};
pub use seal::{EndpointSeal, VoutSeal};
pub use util::{AnchoredBundle, ContainerVer, Terminal};
