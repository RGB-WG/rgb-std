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

use amplify::confinement::SmallVec;
use commit_verify::Conceal;
use rgb::{
    Assign, AssignAttach, AssignData, AssignFungible, AssignRights, ExposedSeal, ExposedState,
    TypedAssigns, Xchain,
};

pub trait TypedAssignsExt<Seal: ExposedSeal> {
    fn reveal_seal(&mut self, seal: Xchain<Seal>);

    fn filter_revealed_seals(&self) -> Vec<Xchain<Seal>>;
}

impl<Seal: ExposedSeal> TypedAssignsExt<Seal> for TypedAssigns<Seal> {
    fn reveal_seal(&mut self, seal: Xchain<Seal>) {
        fn reveal<State: ExposedState, Seal: ExposedSeal>(
            vec: &mut SmallVec<Assign<State, Seal>>,
            revealed: Xchain<Seal>,
        ) {
            for assign in vec.iter_mut() {
                match assign {
                    Assign::ConfidentialSeal { seal, state } if *seal == revealed.conceal() => {
                        *assign = Assign::Revealed {
                            seal: revealed,
                            state: state.clone(),
                        }
                    }
                    Assign::Confidential { seal, state } if *seal == revealed.conceal() => {
                        *assign = Assign::ConfidentialState {
                            seal: revealed,
                            state: *state,
                        }
                    }
                    _ => {}
                }
            }
        }

        match self {
            TypedAssigns::Declarative(v) => reveal(v, seal),
            TypedAssigns::Fungible(v) => reveal(v, seal),
            TypedAssigns::Structured(v) => reveal(v, seal),
            TypedAssigns::Attachment(v) => reveal(v, seal),
        }
    }

    fn filter_revealed_seals(&self) -> Vec<Xchain<Seal>> {
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
