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

use alloc::collections::{BTreeMap, BTreeSet};

use bp::seals::TxoSeal;
use bp::{dbc, Outpoint, Txid, Vout};
use hypersonic::{AuthToken, CellAddr, ContractId, IssueParams, Operation, Schema, Supply};

use crate::pile::Protocol;
use crate::{Mound, Pile};

pub trait WalletDescriptor {}

impl<D: dbc::Proof> Protocol for TxoSeal<D> {
    type Id = Txid;

    fn auth_token(&self) -> AuthToken { todo!() }
}

/// Wallet contains a bunch of RGB contract stockpiles, which are held by a single owner; such that
/// when a new operation under any of the contracts happen it may affect other contracts sharing the
/// same UTXOs.
pub struct Wallet<
    W: WalletDescriptor,
    D: dbc::Proof,
    S: Supply<CAPS>,
    P: Pile<Seal = TxoSeal<D>>,
    X,
    const CAPS: u32,
> {
    pub descriptor: W,
    pub unspent: BTreeMap<Outpoint, BTreeSet<(ContractId, TxoSeal<D>)>>,
    pub mound: Mound<S, P, X, CAPS>,
}

impl<
        W: WalletDescriptor,
        D: dbc::Proof,
        S: Supply<CAPS>,
        P: Pile<Seal = TxoSeal<D>>,
        X,
        const CAPS: u32,
    > Wallet<W, D, S, P, X, CAPS>
{
    pub fn issue(&mut self, schema: Schema, params: IssueParams, supply: S, pile: P) -> ContractId {
        self.mound.issue(schema, params, supply, pile)
    }

    pub fn assignments(
        &self,
        outpoint: Outpoint,
    ) -> impl Iterator<Item = (ContractId, &TxoSeal<D>)> {
        self.unspent
            .get(&outpoint)
            .expect("unknown outpoint")
            .iter()
            .map(|(id, seal)| (*id, seal))
    }

    pub fn new_vout(&mut self, vout: Vout) -> TxoSeal<D> { todo!() }

    pub fn new_seal(&mut self) -> TxoSeal<D> { todo!() }

    pub fn resolve_seal(&self, opout: CellAddr) -> TxoSeal<D> { todo!() }

    pub fn assemble_psbt(&self, op: Operation) { todo!() }
}

pub trait WalletPersistence<Seal: Protocol> {}

pub mod file {
    use std::path::{Path, PathBuf};

    use hypersonic::{CodexId, FileSupply, IssueParams, Schema};

    use super::*;
    use crate::FilePile;

    pub type FileWallet<W, D: dbc::Proof, const CAPS: u32> =
        Wallet<W, D, FileSupply, FilePile<TxoSeal<D>>, PathBuf, CAPS>;

    impl<W: WalletDescriptor, D: dbc::Proof, const CAPS: u32> FileWallet<W, D, CAPS> {
        pub fn issue_file(&mut self, codex_id: CodexId, params: IssueParams) -> ContractId {
            let schema = self.mound.schema(codex_id).expect("unknown codex id");
            // TODO: check that if the issue belongs to the wallet add it to the unspents
            self.mound.issue_file(schema.clone(), params)
        }
    }
}
