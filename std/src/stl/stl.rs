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

use std::str::FromStr;

use bp::dbc::LIB_NAME_BPCORE;
use bp::LIB_NAME_BITCOIN;
use strict_types::typelib::LibBuilder;
use strict_types::typesys::SystemBuilder;
use strict_types::{Dependency, SemId, TypeLib, TypeLibId, TypeSystem};

use super::{
    DivisibleAssetSpec, Error, MediaType, RicardianContract, Timestamp, LIB_NAME_RGB_CONTRACT,
};

#[derive(Debug)]
pub struct StandardLib(TypeLib);

impl StandardLib {
    pub fn new() -> Self {
        fn builder() -> Result<TypeLib, Error> {
            let bitcoin_id = TypeLibId::from_str(
                "circus_report_jeep_2bj6eDer24ZBSVq6JgQW2BrARt6vx56vMWzF35J45gzY",
            )?;
            let bpcore_id = TypeLibId::from_str(
                "harlem_null_puma_DxuLX8d9UiMyEJMRJivMFviK1B8t1QWyjywXuDC13iKR",
            )?;

            let imports = bset! {
                Dependency::with(bitcoin_id, libname!(LIB_NAME_BITCOIN)),
                Dependency::with(bpcore_id, libname!(LIB_NAME_BPCORE)),
            };

            LibBuilder::new(libname!(LIB_NAME_RGB_CONTRACT))
                .process::<Timestamp>()?
                .process::<DivisibleAssetSpec>()?
                .process::<RicardianContract>()?
                .process::<MediaType>()?
                .compile(imports)
                .map_err(Error::from)
        }

        Self(builder().expect("error in standard RGBContract type library"))
    }

    pub fn type_lib(&self) -> TypeLib { self.0.clone() }
}

#[derive(Debug)]
pub struct StandardTypes(TypeSystem);

impl StandardTypes {
    pub fn new() -> Self {
        fn builder() -> Result<TypeSystem, Error> {
            let lib = StandardLib::new().type_lib();
            let sys = SystemBuilder::new().import(lib)?.finalize()?;
            Ok(sys)
        }

        Self(builder().expect("error in standard RGBContract type system"))
    }

    pub fn type_system(&self) -> TypeSystem { self.0.clone() }

    pub fn get(&self, name: &'static str) -> SemId {
        self.0
            .id_by_name(name)
            .expect("type is absent in standard RGBContract type library")
    }
}
