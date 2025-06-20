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

//! RGB containers are data packages which can be transferred between smart contract users.
//! The main type of container is the [`Consignment`], containing information about partial state
//! of a *single contract*, extending from its genesis up to certain contract endpoints.

mod seal;
mod anchors;
mod consignment;
mod util;
mod partials;
mod indexed;
mod file;
mod kit;

pub use anchors::{PubWitness, SealWitness, SealWitnessMergeError, ToWitnessId, WitnessBundle};
pub use consignment::{
    Consignment, ConsignmentExt, ConsignmentId, ConsignmentParseError, Contract, Transfer,
    ValidConsignment, ValidContract, ValidTransfer,
};
pub use file::{FileContent, LoadError, UniversalFile};
pub use indexed::IndexedConsignment;
pub use kit::{Kit, KitId, ValidKit};
pub use partials::{Batch, Fascia};
pub use seal::{BuilderSeal, VoutSeal};
pub use util::{ContainerVer, SecretSeals};

pub const ASCII_ARMOR_NAME: &str = "Name";
pub const ASCII_ARMOR_SCHEMA: &str = "Schema";
pub const ASCII_ARMOR_CONTRACT: &str = "Contract";
pub const ASCII_ARMOR_VERSION: &str = "Version";
pub const ASCII_ARMOR_TERMINAL: &str = "Terminal";
pub const ASCII_ARMOR_SCRIPT: &str = "Alu-Lib";
pub const ASCII_ARMOR_TYPE_SYSTEM: &str = "Type-System";
pub const ASCII_ARMOR_CONSIGNMENT_TYPE: &str = "Type";
