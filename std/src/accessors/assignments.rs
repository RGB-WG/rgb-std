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

use rgb::{AssignAttach, AssignData, AssignFungible, AssignRights, ExposedSeal, TypedAssigns};

pub trait TypedAssignsExt<Seal: ExposedSeal> {
    fn filter_revealed_seals(&self) -> Vec<Seal>;
}

impl<Seal: ExposedSeal> TypedAssignsExt<Seal> for TypedAssigns<Seal> {
    fn filter_revealed_seals(&self) -> Vec<Seal> {
        match self {
            TypedAssigns::Declarative(s) => {
                s.iter().filter_map(AssignRights::revealed_seal).collect()
            }
            TypedAssigns::Fungible(s) => {
                s.iter().filter_map(AssignFungible::revealed_seal).collect()
            }
            TypedAssigns::Structured(s) => s.iter().filter_map(AssignData::revealed_seal).collect(),
            TypedAssigns::Attachment(s) => {
                s.iter().filter_map(AssignAttach::revealed_seal).collect()
            }
        }
    }
}
