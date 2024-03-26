// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.
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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_types;

use std::fs;
use std::io::Write;

use commit_verify::CommitmentLayout;
use rgbstd::containers::Transfer;
use rgbstd::interface::{rgb20, rgb21, rgb25, IfaceClass, Rgb21, Rgb25};
use rgbstd::stl::{
    aluvm_stl, bp_core_stl, bp_tx_stl, commit_verify_stl, rgb_contract_stl, rgb_core_stl,
    rgb_std_stl,
};
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::{parse_args, StlFormat, SystemBuilder};

fn main() {
    let (_, dir) = parse_args();
    let dir = dir.unwrap_or_else(|| "./stl".to_owned());

    let contract_stl = rgb_contract_stl();
    contract_stl
        .serialize(StlFormat::Binary, Some(&dir), "0.1.0", None)
        .expect("unable to write to the file");
    contract_stl
        .serialize(StlFormat::Armored, Some(&dir), "0.1.0", None)
        .expect("unable to write to the file");
    contract_stl
        .serialize(
            StlFormat::Source,
            Some(&dir),
            "0.1.0",
            Some(
                "
  Description: Types for writing RGB contracts and interfaces
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    let rgb21 = Rgb21::stl();
    rgb21
        .serialize(StlFormat::Binary, Some(&dir), "0.1.0", None)
        .expect("unable to write to the file");
    rgb21
        .serialize(StlFormat::Armored, Some(&dir), "0.1.0", None)
        .expect("unable to write to the file");
    rgb21
        .serialize(
            StlFormat::Source,
            Some(&dir),
            "0.1.0",
            Some(
                "
  Description: Types for RGB21 interface
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    let rgb_std = rgb_std_stl();
    rgb_std
        .serialize(StlFormat::Binary, Some(&dir), "0.1.0", None)
        .expect("unable to write to the file");
    rgb_std
        .serialize(StlFormat::Armored, Some(&dir), "0.1.0", None)
        .expect("unable to write to the file");
    rgb_std
        .serialize(
            StlFormat::Source,
            Some(&dir),
            "0.1.0",
            Some(
                "
  Description: RGB standard library
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    let std = std_stl();
    let rgb = rgb_std_stl();
    let core = rgb_core_stl();
    let tx = bp_tx_stl();
    let bp = bp_core_stl();
    let cv = commit_verify_stl();
    let st = strict_types_stl();
    let vm = aluvm_stl();

    let sys = SystemBuilder::new()
        .import(rgb)
        .unwrap()
        .import(core)
        .unwrap()
        .import(vm)
        .unwrap()
        .import(bp)
        .unwrap()
        .import(tx)
        .unwrap()
        .import(cv)
        .unwrap()
        .import(st)
        .unwrap()
        .import(std)
        .unwrap()
        .finalize()
        .expect("not all libraries present");

    let ifsys = SystemBuilder::new()
        .import(rgb21)
        .unwrap()
        .import(rgb_contract_stl())
        .unwrap()
        .import(bp_tx_stl())
        .unwrap()
        .import(std_stl())
        .unwrap()
        .finalize()
        .expect("not all libraries present");

    let mut file = fs::File::create(format!("{dir}/RGB20.con")).unwrap();
    let base_id = rgb20::fungible().iface_id();
    let inflatible_id = rgb20::inflatable().iface_id();
    writeln!(file, "{}", rgb20::fungible().display(map! { base_id => tn!("RGB20Base") }, &ifsys))
        .unwrap();
    writeln!(file, "{}", rgb20::fixed().display(map! { base_id => tn!("RGB20Fixed") }, &ifsys))
        .unwrap();
    writeln!(file, "{}", rgb20::renameable().display(map! { base_id => tn!("RGB20Base") }, &ifsys))
        .unwrap();
    writeln!(file, "{}", rgb20::burnable().display(map! { base_id => tn!("RGB20Base") }, &ifsys))
        .unwrap();
    writeln!(file, "{}", rgb20::inflatable().display(map! { base_id => tn!("RGB20Base") }, &ifsys))
        .unwrap();
    writeln!(
        file,
        "{}",
        rgb20::replaceable().display(map! { inflatible_id => tn!("RGB20Inflatible") }, &ifsys)
    )
    .unwrap();

    let rgb21 = Rgb21::iface(rgb21::Features::all());
    fs::write(format!("{dir}/RGB21.con"), format!("{}", rgb21.display(none!(), &ifsys))).unwrap();

    let rgb25 = Rgb25::iface(rgb25::Features::all());
    fs::write(format!("{dir}/RGB25.con"), format!("{}", rgb25.display(none!(), &ifsys))).unwrap();

    let mut file = fs::File::create(format!("{dir}/Transfer.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: RGB Transfer
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}

Seals vesper lexicon=types+commitments
"
    )
    .unwrap();
    let layout = Transfer::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("RGBStd.Consignmenttrue").unwrap();
    writeln!(file, "{tt}").unwrap();
}
