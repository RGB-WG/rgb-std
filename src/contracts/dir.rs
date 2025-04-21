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

use std::collections::HashMap;
use std::path::PathBuf;

use hypersonic::Stock;

use crate::{CodexId, Consensus, Contract, ContractId, Pile, Schema};

/// Directory-based memory-efficient collection of RGB smart contracts and contract issuers.
///
/// Unlike [`crate::ContractsInmem`], which can also be read from a directory, doesn't maintain all
/// contracts in memory, and loads/unloads them from/to disk dynamically.
#[derive(Getters)]
pub struct ContractsDir<S: Stock, P: Pile> {
    #[getter(as_copy)]
    consensus: Consensus,
    #[getter(as_copy)]
    testnet: bool,
    schemata: HashMap<CodexId, Schema>,
    cache: HashMap<ContractId, Contract<S, P>>,
    path: PathBuf,
}

// TODO: Implement
