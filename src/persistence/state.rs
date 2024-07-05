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

use std::error::Error;
use std::fmt::Debug;

use invoice::Amount;
use rgb::{AssetTag, BlindingFactor, ContractHistory, ContractId, DataState};

use crate::interface::AttachedState;
use crate::persistence::StoreTransaction;
use crate::resolvers::ResolveHeight;

#[derive(Clone, PartialEq, Eq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum StateUpdateError<E: Error> {
    /// unable to resolve witness. Details:
    ///
    /// {0}
    Resolver(String),

    /// contract state {0} is not known.
    UnknownContract(ContractId),

    #[display(inner)]
    Connectivity(E),
}

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub enum PersistedState {
    Void,
    Amount(Amount, BlindingFactor, AssetTag),
    Data(DataState, u128),
    Attachment(AttachedState, u64),
}

impl PersistedState {
    pub(crate) fn update_blinding(&mut self, blinding: BlindingFactor) {
        match self {
            PersistedState::Void => {}
            PersistedState::Amount(_, b, _) => *b = blinding,
            PersistedState::Data(_, _) => {}
            PersistedState::Attachment(_, _) => {}
        }
    }
}

pub trait StateProvider: Debug + StateReadProvider + StateWriteProvider {}

pub trait StateReadProvider {
    type Error: Clone + Eq + Error;

    fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<Option<&ContractHistory>, Self::Error>;
}

pub trait StateWriteProvider: StoreTransaction<TransactionErr = Self::Error> {
    type Error: Clone + Eq + Error;

    fn create_or_update_state<R: ResolveHeight>(
        &mut self,
        contract_id: ContractId,
        updater: impl FnOnce(Option<ContractHistory>) -> Result<ContractHistory, String>,
    ) -> Result<(), StateUpdateError<Self::Error>>;

    fn update_state<R: ResolveHeight>(
        &mut self,
        contract_id: ContractId,
        updater: impl FnMut(&mut ContractHistory) -> Result<(), String>,
    ) -> Result<(), StateUpdateError<Self::Error>>;
}
