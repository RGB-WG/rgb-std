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

mod inmem;
#[cfg(feature = "fs")]
pub mod dir;

use alloc::collections::BTreeMap;
use core::borrow::Borrow;
use std::io;

use amplify::confinement::SmallOrdMap;
use hypersonic::{AcceptError, Articles, CallParams, StateName, Stock};
use rgb::RgbSeal;
use serde::de::StdError;
use strict_encoding::{
    ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter, WriteRaw,
};
use strict_types::StrictVal;

pub use self::inmem::ContractsInmem;
use crate::{
    AuthToken, CallError, CellAddr, CodexId, ConsumeError, ContractId, ContractInfo, ContractRef,
    ContractState, CreateParams, Operation, Opid, Pile, Schema,
};

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct OpOut<Seal: RgbSeal> {
    pub addr: CellAddr,
    pub seal: Seal,
    pub name: StateName,
    pub val: StrictVal,
}

pub trait ContractsApi<S: Stock, P: Pile> {
    fn codex_ids(&self) -> impl Iterator<Item = CodexId>;
    fn schemata(&self) -> impl Iterator<Item = (CodexId, &Schema)>;
    fn schema(&self, codex_id: CodexId) -> Option<&Schema>;

    fn contract_ids(&self) -> impl Iterator<Item = ContractId>;
    fn contracts_info(&self) -> impl Iterator<Item = ContractInfo>;
    fn contracts_state(&self) -> impl Iterator<Item = (ContractId, ContractState<P::Seal>)> {
        // Some implementations, for instance doing network requests, may provide a more efficient
        // method
        self.contract_ids().map(|id| (id, self.contract_state(id)))
    }
    fn contract_state(&self, id: ContractId) -> ContractState<P::Seal>;
    fn contract_articles(&self, id: ContractId) -> &Articles;

    fn has_contract(&self, id: ContractId) -> bool;
    fn find_contract_id(&self, r: impl Into<ContractRef>) -> Option<ContractId>;

    fn issue(
        &mut self,
        params: CreateParams<<P::Seal as RgbSeal>::Definiton>,
        stock_conf: S::Conf,
        pile_conf: P::Conf,
    ) -> Result<ContractId, IssueError<S::Error>>
    where
        S::Error: From<P::Error>;

    fn contract_call(
        &mut self,
        contract_id: ContractId,
        call: CallParams,
        seals: SmallOrdMap<u16, <P::Seal as RgbSeal>::Definiton>,
    ) -> Result<Operation, AcceptError>;

    fn include(
        &mut self,
        contract_id: ContractId,
        opid: Opid,
        pub_witness: &<P::Seal as RgbSeal>::Published,
        anchor: <P::Seal as RgbSeal>::Client,
    );

    fn consign(
        &mut self,
        contract_id: ContractId,
        terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        writer: StrictWriter<impl WriteRaw>,
    ) -> io::Result<()>
    where
        <P::Seal as RgbSeal>::Client: StrictDumb + StrictEncode,
        <P::Seal as RgbSeal>::Published: StrictDumb + StrictEncode,
        <P::Seal as RgbSeal>::WitnessId: StrictEncode;

    fn consume(
        &mut self,
        contract_id: ContractId,
        reader: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(&Operation) -> BTreeMap<u16, <P::Seal as RgbSeal>::Definiton>,
    ) -> Result<(), ConsumeError<<P::Seal as RgbSeal>::Definiton>>
    where
        <P::Seal as RgbSeal>::Client: StrictDecode,
        <P::Seal as RgbSeal>::Published: StrictDecode,
        <P::Seal as RgbSeal>::WitnessId: StrictDecode;
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IssueError<E: StdError> {
    /// proof of publication layer mismatch.
    ConsensusMismatch,
    /// unable to consume a testnet contract for mainnet.
    TestnetMismatch,
    /// unable to consume a mainnet contract for testnet.
    MainnetMismatch,
    /// unknown codex for contract issue {0}.
    UnknownCodex(CodexId),

    /// invalid schema; {0}
    #[from]
    InvalidSchema(CallError),

    #[from]
    #[display(inner)]
    Inner(hypersonic::IssueError<E>),
}
