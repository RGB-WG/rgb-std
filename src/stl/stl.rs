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

use bp::bc::stl::bp_tx_stl;
use bp::stl::bp_core_stl;
use commit_verify::stl::commit_verify_stl;
use invoice::Amount;
pub use rgb::stl::{aluvm_stl, rgb_core_stl, LIB_ID_RGB};
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typesys::SystemBuilder;
use strict_types::{CompileError, LibBuilder, SemId, SymbolicSys, TypeLib, TypeSystem};

use super::{
    BurnMeta, ContractData, DivisibleAssetSpec, Error, IssueMeta, MediaType, RicardianContract,
    Timestamp, LIB_NAME_RGB_CONTRACT,
};
use crate::containers::{Contract, Transfer};
use crate::persistence::Stock;
use crate::stl::ProofOfReserves;
use crate::LIB_NAME_RGB_STD;

/// Strict types id for the library providing standard data types which may be
/// used in RGB smart contracts.
pub const LIB_ID_RGB_CONTRACT: &str =
    "urn:ubideco:stl:pGtgmYchjsHEdmKzmkc6SX8rDm4qxN472K8vQyLmNGX#polygon-antonio-violet";

/// Strict types id for the library representing of RGB StdLib data types.
pub const LIB_ID_RGB_STD: &str =
    "urn:ubideco:stl:FjdM8g7HN2S8hfKB17GuwsnKRzFM9up8bJ4uBNzWAPDL#aloha-olivia-rider";

fn _rgb_std_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_STD), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bp_tx_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency(),
        rgb_core_stl().to_dependency()
    })
    .transpile::<Transfer>()
    .transpile::<Contract>()
    .transpile::<Stock>()
    .compile()
}

fn _rgb_contract_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_CONTRACT), tiny_bset! {
        std_stl().to_dependency(),
        bp_tx_stl().to_dependency()
    })
    .transpile::<Amount>()
    .transpile::<Timestamp>()
    .transpile::<DivisibleAssetSpec>()
    .transpile::<RicardianContract>()
    .transpile::<ContractData>()
    .transpile::<MediaType>()
    .transpile::<ProofOfReserves>()
    .transpile::<BurnMeta>()
    .transpile::<IssueMeta>()
    .compile()
}

/// Generates strict type library representation of RGB StdLib data types.
pub fn rgb_std_stl() -> TypeLib { _rgb_std_stl().expect("invalid strict type RGBStd library") }

/// Generates strict type library providing standard data types which may be
/// used in RGB smart contracts.
pub fn rgb_contract_stl() -> TypeLib {
    _rgb_contract_stl().expect("invalid strict type RGBContract library")
}

#[derive(Debug)]
pub struct StandardTypes(SymbolicSys);

impl Default for StandardTypes {
    fn default() -> Self { StandardTypes::new() }
}

impl StandardTypes {
    pub fn new() -> Self {
        Self::try_with([std_stl(), bp_tx_stl(), rgb_contract_stl()])
            .expect("error in standard RGBContract type system")
    }

    pub fn with(lib: TypeLib) -> Self {
        Self::try_with([std_stl(), bp_tx_stl(), rgb_contract_stl(), lib])
            .expect("error in standard RGBContract type system")
    }

    #[allow(clippy::result_large_err)]
    fn try_with(libs: impl IntoIterator<Item = TypeLib>) -> Result<Self, Error> {
        let mut builder = SystemBuilder::new();
        for lib in libs.into_iter() {
            builder = builder.import(lib)?;
        }
        let sys = builder.finalize()?;
        Ok(Self(sys))
    }

    pub fn type_system(&self) -> TypeSystem { self.0.as_types().clone() }

    pub fn get(&self, name: &'static str) -> SemId {
        *self.0.resolve(name).unwrap_or_else(|| {
            panic!("type '{name}' is absent in standard RGBContract type library")
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn contract_lib_id() {
        let lib = rgb_contract_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_CONTRACT);
    }

    #[test]
    fn std_lib_id() {
        let lib = rgb_std_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_STD);
    }
}
