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

use alloc::collections::BTreeMap;

use hypersonic::{CellAddr, ContractId, Supply};

use crate::{Pile, Stockpile};

pub struct Mound<S: Supply<CAPS>, P: Pile, const CAPS: u32>(
    BTreeMap<ContractId, Stockpile<S, P, CAPS>>,
);

impl<S: Supply<CAPS>, P: Pile, const CAPS: u32> Mound<S, P, CAPS> {
    pub fn new() -> Self { Self(BTreeMap::new()) }
    pub fn excavate(mut loader: impl Excavate<S, P, CAPS>) -> Self {
        Self(loader.excavate().collect())
    }

    pub fn contract_ids(&self) -> impl Iterator<Item = ContractId> + use<'_, S, P, CAPS> {
        self.0.keys().copied()
    }

    pub fn contracts(&self) -> impl Iterator<Item = (ContractId, &Stockpile<S, P, CAPS>)> {
        self.0.iter().map(|(id, stock)| (*id, stock))
    }

    pub fn contracts_mut(
        &mut self,
    ) -> impl Iterator<Item = (ContractId, &mut Stockpile<S, P, CAPS>)> {
        self.0.iter_mut().map(|(id, stock)| (*id, stock))
    }

    pub fn contract(&self, id: ContractId) -> &Stockpile<S, P, CAPS> {
        self.0
            .get(&id)
            .unwrap_or_else(|| panic!("unknown contract {id}"))
    }

    pub fn contract_mut(&mut self, id: ContractId) -> &mut Stockpile<S, P, CAPS> {
        self.0
            .get_mut(&id)
            .unwrap_or_else(|| panic!("unknown contract {id}"))
    }

    pub fn select<'seal>(
        &self,
        seal: &'seal P::Seal,
    ) -> impl Iterator<Item = (ContractId, CellAddr)> + use<'_, 'seal, S, P, CAPS> {
        self.0
            .iter()
            .filter_map(|(id, stockpile)| stockpile.seal(seal).map(|addr| (*id, addr)))
    }
}

pub trait Excavate<S: Supply<CAPS>, P: Pile, const CAPS: u32> {
    fn excavate(&mut self) -> impl Iterator<Item = (ContractId, Stockpile<S, P, CAPS>)>;
}
