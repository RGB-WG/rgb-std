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

use amplify::confinement::SmallOrdSet;
use bp::bc::stl::bitcoin_stl;
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::typelib::{LibBuilder, TranslateError};
use strict_types::TypeLib;

use super::{
    AssignIface, GenesisIface, GlobalIface, Iface, OwnedIface, Req, TransitionIface, VerNo,
};
use crate::interface::ArgSpec;
use crate::stl::{rgb_contract_stl, ProofOfReserves, StandardTypes};

pub const LIB_NAME_RGB20: &str = "RGB20";
/// Strict types id for the library providing data types for RGB20 interface.
pub const LIB_ID_RGB20: &str = "escort_chamber_clone_8g3y7GatrZYywXA38YKq1vCWmtrTYSMEBNgPqDy8NBDF";

#[derive(
    Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From
)]
#[wrapper(Display, FromStr, Add, Sub, Mul, Div, Rem)]
#[wrapper_mut(AddAssign, SubAssign, MulAssign, DivAssign, RemAssign)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB20)]
struct Amount(u64);
impl StrictSerialize for Amount {}
impl StrictDeserialize for Amount {}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB20)]
struct Meta {
    pub reserves: SmallOrdSet<ProofOfReserves>,
}
impl StrictSerialize for Meta {}
impl StrictDeserialize for Meta {}

fn _rgb20_stl() -> Result<TypeLib, TranslateError> {
    LibBuilder::new(libname!(LIB_NAME_RGB20))
        .transpile::<Meta>()
        .transpile::<Amount>()
        .compile(bset! {
            bitcoin_stl().to_dependency(),
            rgb_contract_stl().to_dependency()
        })
}

/// Generates strict type library providing data types for RGB20 interface.
pub fn rgb20_stl() -> TypeLib { _rgb20_stl().expect("invalid strict type RGB20 library") }

pub fn rgb20() -> Iface {
    let types = StandardTypes::with(rgb20_stl());

    Iface {
        version: VerNo::V1,
        name: tn!("RGB20"),
        global_state: tiny_bmap! {
            fname!("spec") => GlobalIface::required(types.get("RGBContract.DivisibleAssetSpec")),
            fname!("terms") => GlobalIface::required(types.get("RGBContract.RicardianContract")),
            fname!("created") => GlobalIface::required(types.get("RGBContract.Timestamp")),
            fname!("issuedSupply") => GlobalIface::none_or_many(types.get("RGB20.Amount")),
            fname!("burnedSupply") => GlobalIface::none_or_many(types.get("RGB20.Amount")),
            fname!("replacedSupply") => GlobalIface::none_or_many(types.get("RGB20.Amount")),
        },
        assignments: tiny_bmap! {
            fname!("inflationAllowance") => AssignIface::public(OwnedIface::Amount, Req::NoneOrMore),
            fname!("updateRight") => AssignIface::public(OwnedIface::Amount, Req::Optional),
            fname!("burnRight") => AssignIface::public(OwnedIface::Amount, Req::Optional),
            fname!("assetOwner") => AssignIface::private(OwnedIface::Amount, Req::NoneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            metadata: Some(types.get("RGB20.Meta")),
            global: tiny_bmap! {
                fname!("spec") => ArgSpec::required(),
                fname!("terms") => ArgSpec::required(),
                fname!("issuedSupply") => ArgSpec::required(),
            },
            assignments: tiny_bmap! {
                fname!("assetOwner") => ArgSpec::many(),
                fname!("inflationAllowance") => ArgSpec::many(),
                fname!("updateRight") => ArgSpec::optional(),
                fname!("burnRight") => ArgSpec::optional(),
            },
            valencies: none!(),
        },
        transitions: tiny_bmap! {
            tn!("Transfer") => TransitionIface {
                optional: false,
                metadata: None,
                globals: none!(),
                inputs: tiny_bmap! {
                    fname!("previous") => ArgSpec::from_non_empty("assetOwner"),
                },
                assignments: tiny_bmap! {
                    fname!("beneficiary") => ArgSpec::from_non_empty("assetOwner"),
                },
                valencies: none!(),
                default_assignment: Some(fname!("assetOwner")),
            }
        },
        extensions: none!(),
        default_operation: Some(tn!("Transfer")),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::containers::BindleContent;

    const RGB20: &str = include_str!("../../tests/data/rgb20.rgba");

    #[test]
    fn lib_id() {
        let lib = rgb20_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB20);
    }

    #[test]
    fn iface_creation() { rgb20(); }

    #[test]
    fn iface_bindle() {
        assert_eq!(format!("{}", rgb20().bindle()), RGB20);
    }
}
