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

#![cfg_attr(coverage_nightly, feature(coverage_attribute), coverage(off))]

use rgb::stl::{rgb_seals, rgb_stl};
use strict_types::parse_args;

fn main() {
    let (format, dir) = parse_args();

    rgb_stl()
        .serialize(
            format,
            dir.as_ref(),
            "0.12.0",
            Some(
                "
  Description: RGB smart contracts library
  Author: Dr Maxim Orlovsky <orlovsky@ubideco.org>
  Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems, \
                 Switzerland.
                All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    rgb_seals()
        .serialize(
            format,
            dir.as_ref(),
            "0.12.0",
            Some(
                "
  Description: RGB smart contracts library
  Author: Dr Maxim Orlovsky <orlovsky@ubideco.org>
  Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems, \
                 Switzerland.
                All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");
}
