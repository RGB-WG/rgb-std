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

use core::str::FromStr;

use hypersonic::ContractId;
use strict_encoding::TypeName;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, From)]
#[display(inner)]
pub enum ContractRef {
    #[from]
    Id(ContractId),

    #[from]
    #[from(&'static str)]
    Name(TypeName),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, Error)]
#[display("invalid contract reference '{0}'")]
pub struct InvalidContractRef(String);

impl FromStr for ContractRef {
    type Err = InvalidContractRef;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(id) = ContractId::from_str(s) {
            Ok(ContractRef::Id(id))
        } else if let Ok(name) = TypeName::from_str(s) {
            Ok(ContractRef::Name(name))
        } else {
            Err(InvalidContractRef(s.to_owned()))
        }
    }
}
