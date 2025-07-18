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

use core::error::Error as StdError;

use amplify::MultiError;
use hypersonic::{CodexId, ContractId, Stock};
use rgb::RgbSeal;
use strict_encoding::StrictDecode;

use crate::{
    Articles, Consensus, Consignment, ConsumeError, Contract, CreateParams, Issuer, IssuerError,
    Pile,
};

/// Stockpile provides a specific persistence implementation for the use in [`crate::Contracts`].
/// It allows for it to abstract from a specific storage media, whether it is a file system,
/// database, or a network service. Its main task is to load already known contract issuers and
/// contract runtimes ([`Contract`]); or to add new ones via the [`Self::import_issuer`] and
/// [`Self::issue`] procedures.
///
/// # Reading contracts
///
/// Since there might be many thousands of contracts, loading all of them at once may not make a
/// sense performance-one. So the contracts are instantiated one-by-one, using the
/// [`Self::contract`] method.
///
/// To iterate over all known contracts, a specific [`crate::Contracts`] implementation should
/// iterate over contract ids, present in the system, and instantiate them one by one. This allows
/// the full use of Rust iterators, including instantiating contracts in "pages" of a certain size
/// (by using [`Iterator::skip`] and [`Iterator::take`]) etc.
pub trait Stockpile {
    /// Specific stock runtime used by [`Contract`]s instantiated by this stockpile.
    type Stock: Stock;
    /// Specific pile runtime used by [`Contract`]s instantiated by this stockpile.
    type Pile: Pile;
    /// Errors happening during storage procedures.
    type Error: StdError;

    fn consensus(&self) -> Consensus;
    fn is_testnet(&self) -> bool;

    fn issuers_count(&self) -> usize;
    fn contracts_count(&self) -> usize;

    fn has_issuer(&self, codex_id: CodexId) -> bool;
    fn has_contract(&self, contract_id: ContractId) -> bool;

    fn codex_ids(&self) -> impl Iterator<Item = CodexId>;
    fn contract_ids(&self) -> impl Iterator<Item = ContractId>;

    fn issuer(&self, codex_id: CodexId) -> Option<Issuer>;
    fn contract(&self, contract_id: ContractId) -> Option<Contract<Self::Stock, Self::Pile>>;

    fn import_issuer(&mut self, issuer: Issuer) -> Result<Issuer, Self::Error>;

    fn import_contract(
        &mut self,
        articles: Articles,
        consignment: Consignment<<Self::Pile as Pile>::Seal>,
    ) -> Result<
        Contract<Self::Stock, Self::Pile>,
        MultiError<
            ConsumeError<<<Self::Pile as Pile>::Seal as RgbSeal>::Definition>,
            <Self::Stock as Stock>::Error,
            <Self::Pile as Pile>::Error,
        >,
    >
    where
        <<Self::Pile as Pile>::Seal as RgbSeal>::Client: StrictDecode,
        <<Self::Pile as Pile>::Seal as RgbSeal>::Published: StrictDecode,
        <<Self::Pile as Pile>::Seal as RgbSeal>::WitnessId: StrictDecode;

    fn issue(
        &mut self,
        params: CreateParams<<<Self::Pile as Pile>::Seal as RgbSeal>::Definition>,
    ) -> Result<
        Contract<Self::Stock, Self::Pile>,
        MultiError<IssuerError, <Self::Stock as Stock>::Error, <Self::Pile as Pile>::Error>,
    >;

    fn purge(&mut self, contract_id: ContractId) -> Result<(), Self::Error>;
}
