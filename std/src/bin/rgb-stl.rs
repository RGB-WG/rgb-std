// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2023 Dr Maxim Orlovsky. All rights reserved.
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

use std::io::stdout;
use std::{env, fs, io};

use amplify::num::u24;
use rgbstd::stl::StandardLib;
use strict_encoding::{StrictEncode, StrictWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let lib = StandardLib::new().type_lib();
    let id = lib.id();

    let ext = match args.get(1).map(String::as_str) {
        Some("--stl") => "stl",
        Some("--sty") => "sty",
        _ => "sty",
    };
    let filename = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| format!("stl/RGBContracts-v0.10.2.A.{ext}"));
    let mut file = match args.len() {
        1 => Box::new(stdout()) as Box<dyn io::Write>,
        2 | 3 => Box::new(fs::File::create(filename)?) as Box<dyn io::Write>,
        _ => panic!("invalid argument count"),
    };
    match ext {
        "stl" => {
            lib.strict_encode(StrictWriter::with(u24::MAX.into_usize(), file))?;
        }
        _ => {
            writeln!(
                file,
                "{{-
  Id: {id}
  Name: RGBCore
  Description: Consensus layer for RGB smart contracts
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}
"
            )?;
            writeln!(file, "{lib}")?;
        }
    }

    Ok(())
}
