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

use invoice::Amount;
use rgb::{AssetTag, BlindingFactor, DataState};

use crate::interface::AttachedState;

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub enum PersistedState {
    Void,
    Amount(Amount, BlindingFactor, AssetTag),
    Data(DataState, u128),
    Attachment(AttachedState, u64),
}

impl PersistedState {
    pub(super) fn update_blinding(&mut self, blinding: BlindingFactor) {
        match self {
            PersistedState::Void => {}
            PersistedState::Amount(_, b, _) => *b = blinding,
            PersistedState::Data(_, _) => {}
            PersistedState::Attachment(_, _) => {}
        }
    }
}
