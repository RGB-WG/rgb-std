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

use rgb::Occurrences;

use crate::interface::{GenesisIface, Iface, OwnedIface, Req, TransitionIface};
use crate::stl::StandardTypes;

pub fn rgb20() -> Iface {
    let types = StandardTypes::new();

    Iface {
        name: tn!("RGB20"),
        global_state: tiny_bmap! {
            tn!("Nominal") => Req::require(types.get("RGBContract.Nominal")),
            tn!("ContractText") => Req::require(types.get("RGBContract.ContractText")),
        },
        assignments: tiny_bmap! {
            tn!("Assets") => OwnedIface::Amount,
        },
        valencies: none!(),
        genesis: GenesisIface {
            metadata: None,
            global: tiny_bmap! {
                tn!("Nominal") => Occurrences::Once,
                tn!("ContractText") => Occurrences::Once,
            },
            assignments: tiny_bmap! {
                tn!("Assets") => Occurrences::OnceOrMore
            },
            valencies: none!(),
        },
        transitions: tiny_bmap! {
            tn!("Transfer") => TransitionIface {
                always_include: false,
                metadata: None,
                globals: none!(),
                inputs: tiny_bmap! {
                    tn!("Assets") => Occurrences::OnceOrMore,
                },
                assignments: tiny_bmap! {
                    tn!("Assets") => Occurrences::OnceOrMore,
                },
                valencies: none!(),
            }
        },
        extensions: none!(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::containers::BindleContent;

    const RGB20: &str = include_str!("../../tests/data/rgb20.asc.rgb");

    #[test]
    fn iface_creation() { rgb20(); }

    #[test]
    fn iface_bindle() {
        assert_eq!(format!("{}", rgb20().bindle()), RGB20);
    }
}
