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

pub use bp::bc::stl::{bp_consensus_stl, bp_tx_stl};
pub use bp::stl::bp_core_stl;
#[allow(unused_imports)]
pub use commit_verify::stl::{commit_verify_stl, LIB_ID_COMMIT_VERIFY};
use invoice::{Allocation, Amount};
pub use rgb::stl::{aluvm_stl, rgb_commit_stl, rgb_logic_stl, LIB_ID_RGB_COMMIT, LIB_ID_RGB_LOGIC};
use rgb::Schema;
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typesys::SystemBuilder;
use strict_types::{CompileError, LibBuilder, SemId, SymbolicSys, TypeLib, TypeSystem};

use super::{
    AssetSpec, AttachmentType, BurnMeta, ContractSpec, ContractTerms, EmbeddedMedia, Error,
    IssueMeta, MediaType, OpidRejectUrl, TokenData, LIB_NAME_RGB_CONTRACT, LIB_NAME_RGB_STORAGE,
};
use crate::containers::{Contract, Kit, Transfer};
use crate::persistence::{MemIndex, MemStash, MemState};
use crate::stl::ProofOfReserves;
use crate::LIB_NAME_RGB_STD;

/// Strict types id for the library providing standard data types which may be
/// used in RGB smart contracts.
pub const LIB_ID_RGB_STORAGE: &str =
    "stl:HWQT7tdF-Lqa1hg5-irH6cgG-Ot7VIra-ZFcTzDK-NPRnpDc#chess-open-nepal";

/// Strict types id for the library providing standard data types which may be
/// used in RGB smart contracts.
pub const LIB_ID_RGB_CONTRACT: &str =
    "stl:1uyMC~lT-xPK57Lr-IgIhB0r-WxYd9io-2wZav_s-6TbR4LY#nuclear-liquid-sonic";

/// Strict types id for the library representing of RGB StdLib data types.
pub const LIB_ID_RGB_STD: &str =
    "stl:LxiMjmBl-MRIFHb1-pitHq43-IPC2~cM-SHQA3hl-mGfDECY#studio-cycle-analyze";

fn _rgb_std_stl() -> Result<TypeLib, Box<CompileError>> {
    // TODO: wait for fix in strict_types to use LibBuilder::with
    #[allow(deprecated)]
    Ok(LibBuilder::new(libname!(LIB_NAME_RGB_STD), [
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bp_consensus_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency(),
        rgb_commit_stl().to_dependency(),
        rgb_logic_stl().to_dependency(),
    ])
    .transpile::<Transfer>()
    .transpile::<Contract>()
    .transpile::<Kit>()
    .compile()?)
}

fn _rgb_contract_stl() -> Result<TypeLib, Box<CompileError>> {
    Ok(LibBuilder::with(libname!(LIB_NAME_RGB_CONTRACT), [
        std_stl().to_dependency_types(),
        bp_consensus_stl().to_dependency_types(),
    ])
    .transpile::<Amount>()
    .transpile::<Allocation>()
    .transpile::<ContractSpec>()
    .transpile::<AssetSpec>()
    .transpile::<ContractTerms>()
    .transpile::<MediaType>()
    .transpile::<ProofOfReserves>()
    .transpile::<BurnMeta>()
    .transpile::<IssueMeta>()
    .transpile::<AttachmentType>()
    .transpile::<TokenData>()
    .transpile::<EmbeddedMedia>()
    .transpile::<OpidRejectUrl>()
    .compile()?)
}

fn _rgb_storage_stl() -> Result<TypeLib, Box<CompileError>> {
    // TODO: wait for fix in strict_types to use LibBuilder::with
    #[allow(deprecated)]
    Ok(LibBuilder::new(libname!(LIB_NAME_RGB_STORAGE), [
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bp_tx_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency(),
        rgb_commit_stl().to_dependency(),
        rgb_logic_stl().to_dependency(),
        rgb_std_stl().to_dependency(),
    ])
    .transpile::<MemIndex>()
    .transpile::<MemState>()
    .transpile::<MemStash>()
    .compile()?)
}

/// Generates strict type library representation of RGB StdLib data types.
pub fn rgb_std_stl() -> TypeLib { _rgb_std_stl().expect("invalid strict type RGBStd library") }

/// Generates strict type library providing standard data types which may be
/// used in RGB smart contracts.
pub fn rgb_contract_stl() -> TypeLib {
    _rgb_contract_stl().expect("invalid strict type RGBContract library")
}

/// Generates strict type library providing standard storage for state, contract
/// state and index.
pub fn rgb_storage_stl() -> TypeLib {
    _rgb_storage_stl().expect("invalid strict type RGBStorage library")
}

#[derive(Debug)]
pub struct StandardTypes(SymbolicSys);

impl StandardTypes {
    pub fn with(lib: TypeLib) -> Self {
        Self::try_with([std_stl(), bp_consensus_stl(), rgb_contract_stl(), lib])
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

    pub fn type_system(&self, schema: Schema) -> TypeSystem {
        self.0.as_types().extract(schema.types()).unwrap()
    }

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

    #[test]
    fn storage_lib_id() {
        let lib = rgb_storage_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_STORAGE);
    }
}
