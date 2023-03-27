// RGB wallet library for smart contracts on Bitcoin & Lightning network
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

use bitcoin::psbt::Psbt;
use bp::seals::txout::CloseMethod;

#[derive(Debug, Display, Error)]
#[display(doc_comments)]
pub enum DbcPsbtError {}

pub trait PsbtDbc {
    fn dbc_conclude(&mut self, method: CloseMethod) -> Result<(), DbcPsbtError>;
}

impl PsbtDbc for Psbt {
    fn dbc_conclude(&mut self, method: CloseMethod) -> Result<(), DbcPsbtError> {
        // 1. Produce mpc::Commitment
        // 2. Depending on the method modify output which is necessary to modify
        todo!()
    }
}
