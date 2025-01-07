// RGB command-line toolbox utility
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

use std::path::PathBuf;

use clap::ValueHint;
use rgb::SealType;

#[derive(Parser)]
pub struct Args {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Cmd,
}

#[derive(Parser)]
pub enum Cmd {
    /// Provide information about a given file (type, used ids etc)
    Info {
        /// File to inspect
        #[clap(value_hint = ValueHint::FilePath)]
        file: PathBuf,
    },

    /// Inspect the provided binary file by converting it into YAML representation
    Inspect {
        /// File to inspect
        #[clap(value_hint = ValueHint::FilePath)]
        file: PathBuf,
    },

    /// Dump complex data into multiple debug files
    ///
    /// Works for contract consignments and stockpiles
    Dump {
        /// Remove the destination directory if it already exists
        #[clap(short, long, global = true)]
        force: bool,

        /// The seal type used by the contract
        seal: SealType,

        /// Source data to process
        #[clap(value_hint = ValueHint::FilePath)]
        src: PathBuf,

        /// Destination directory to put dump files
        ///
        /// If skipped, adds `dump` subdirectory to the `src` path.
        #[clap(value_hint = ValueHint::FilePath)]
        dst: Option<PathBuf>,
    },
}
