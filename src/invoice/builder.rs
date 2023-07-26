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

use rgb::ContractId;
use rgbstd::interface::TypedState;
use rgbstd::Chain;

use super::{Beneficiary, RgbInvoice, RgbTransport};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RgbInvoiceBuilder(RgbInvoice);

impl RgbInvoiceBuilder {
    pub fn new(beneficiary: impl Into<Beneficiary>) -> Self {
        Self(RgbInvoice {
            transports: vec![RgbTransport::UnspecifiedMeans],
            contract: None,
            iface: None,
            operation: None,
            assignment: None,
            beneficiary: beneficiary.into(),
            owned_state: TypedState::Void,
            chain: None,
            expiry: None,
            unknown_query: none!(),
        })
    }

    pub fn with(contract_id: ContractId, beneficiary: impl Into<Beneficiary>) -> Self {
        Self::new(beneficiary).set_contract(contract_id)
    }

    pub fn rgb20(contract_id: ContractId, beneficiary: impl Into<Beneficiary>) -> Self {
        Self::with(contract_id, beneficiary).set_interface("RGB20")
    }

    pub fn rgb20_anything(beneficiary: impl Into<Beneficiary>) -> Self {
        Self::new(beneficiary).set_interface("RGB20")
    }

    pub fn set_contract(mut self, contract_id: ContractId) -> Self {
        self.0.contract = Some(contract_id);
        self
    }

    pub fn set_interface(mut self, name: &'static str) -> Self {
        self.0.iface = Some(tn!(name));
        self
    }

    pub fn set_operation(mut self, name: &'static str) -> Self {
        self.0.operation = Some(tn!(name));
        self
    }

    pub fn set_assignment(mut self, name: &'static str) -> Self {
        self.0.assignment = Some(fname!(name));
        self
    }

    pub fn set_base_amount(mut self, amount: u64) -> Self {
        self.0.owned_state = TypedState::Amount(amount);
        self
    }

    pub fn set_coins(self, coins: u64, cents: u64, precision: impl Into<u8>) -> Self {
        self.set_base_amount(coins.pow(precision.into() as u32) + cents)
    }

    pub fn set_amount(self, amount: f64, precision: impl Into<u8>) -> Result<Self, Self> {
        if amount <= 0.0 {
            return Err(self);
        }
        let coins = amount.floor();
        let cents = amount - coins;
        Ok(self.set_coins(coins as u64, cents as u64, precision))
    }

    pub fn set_chain(mut self, chain: impl Into<Chain>) -> Self {
        self.0.chain = Some(chain.into());
        self
    }

    pub fn set_expiry_timestamp(mut self, expiry: i64) -> Self {
        self.0.expiry = Some(expiry);
        self
    }

    pub fn finish(self) -> RgbInvoice { self.0 }
}
