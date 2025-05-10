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

use bp::bc::stl::bp_consensus_stl;
use bp::seals::WTxoSeal;
use bp::stl::bp_core_stl;
use commit_verify::stl::commit_verify_stl;
use hypersonic::aluvm::alu::stl::aluvm_stl;
use hypersonic::aluvm::zkstl::finite_field_stl;
use hypersonic::stl::{sonic_stl, usonic_stl};
use rgb::{OperationSeals, LIB_NAME_RGB};
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::LibBuilder;
use strict_types::{CompileError, TypeLib};

use crate::popls::bp::PrefabBundle;

/// Strict types id for the library providing data types for RGB types.
pub const LIB_ID_RGB: &str =
    "stl:aAwQVXsP-iTgCThm-8gQAXF5-A8c47_D-pABre7n-mw2KeW0#wizard-farmer-mirage";

fn _rgb_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::with(libname!(LIB_NAME_RGB), [
        std_stl().to_dependency_types(),
        strict_types_stl().to_dependency_types(),
        commit_verify_stl().to_dependency_types(),
        aluvm_stl().to_dependency_types(),
        finite_field_stl().to_dependency_types(),
        usonic_stl().to_dependency_types(),
        sonic_stl().to_dependency_types(),
        bp_consensus_stl().to_dependency_types(),
        bp_core_stl().to_dependency_types(),
    ])
    .transpile::<OperationSeals<WTxoSeal>>()
    .transpile::<PrefabBundle>()
    .compile()
}

/// Generates a strict type library providing data types for RGB types.
pub fn rgb_stl() -> TypeLib { _rgb_stl().expect("invalid strict type RGB library") }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lib_id() {
        let lib = rgb_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB);
    }
}
