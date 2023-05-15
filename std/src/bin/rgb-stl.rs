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

use rgbstd::stl::rgb_contract_stl;
use strict_types::typelib::parse_args;

fn main() {
    let (format, dir) = parse_args();

    rgb_contract_stl()
        .serialize(
            format,
            dir.as_ref(),
            "0.1.0",
            Some(
                "
  Description: Types for writing RGB contracts and interfaces
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    /*
    bp::stl::bp_core_stl()
        .serialize(
            format,
            dir,
            "0.1.0",
            Some(
                "
  Description: Bitcoin client-side-validation library
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");
     */
}
