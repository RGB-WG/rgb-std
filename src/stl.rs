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
use bp::seals::TxoSeal;
use bp::stl::bp_core_stl;
use commit_verify::stl::commit_verify_stl;
use hypersonic::aluvm::alu::stl::aluvm_stl;
use hypersonic::aluvm::zkstl::finite_field_stl;
use hypersonic::stl::{sonic_stl, usonic_stl};
use rgb::LIB_NAME_RGB;
use single_use_seals::SealWitness;
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::LibBuilder;
use strict_types::{CompileError, TypeLib};

use crate::popls::bp::PrefabBundle;
use crate::Consignment;

/// Strict types id for the library providing data types for RGB types.
pub const LIB_ID_RGB: &str =
    "stl:wjjLvtfk-o0qv4i1-bpXiUdB-Ert02Al-GrKveWI-JgIe7nk#section-status-input";

#[allow(clippy::result_large_err)]
fn _rgb_seals() -> Result<TypeLib, CompileError> {
    LibBuilder::with(libname!("SingleUseSeals"), [
        std_stl().to_dependency_types(),
        commit_verify_stl().to_dependency_types(),
        bp_consensus_stl().to_dependency_types(),
        bp_core_stl().to_dependency_types(),
    ])
    .transpile::<SealWitness<TxoSeal>>()
    .compile()
}

#[allow(clippy::result_large_err)]
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
        rgb_seals().to_dependency_types(),
    ])
    .transpile::<Consignment<TxoSeal>>()
    .transpile::<PrefabBundle>()
    .compile()
}

/// Generates a version of SingleUseSeal strict type library specific for RGB.
pub fn rgb_seals() -> TypeLib { _rgb_seals().expect("invalid strict type SingleUseSeals library") }

/// Generates a strict type library providing data types for RGB types.
pub fn rgb_stl() -> TypeLib { _rgb_stl().expect("invalid strict type RGB library") }

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use super::*;

    #[test]
    fn lib_id() {
        let lib = rgb_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB);
    }
}
