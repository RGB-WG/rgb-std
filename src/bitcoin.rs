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

use amplify::confinement::SmallOrdSet;
use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::seals::TxoSeal;
use bp::{dbc, Outpoint, Txid, Vout};
use hypersonic::{
    AuthToken, CellAddr, ContractId, IssueParams, MethodName, NamedState, Operation, Schema,
    StateAtom, Supply,
};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::StrictVal;

use crate::pile::Protocol;
use crate::{Mound, Pile};

pub trait WalletDescriptor {}

pub const BITCOIN_OPRET: u32 = 0x0001_0001_u32;
pub const BITCOIN_TAPRET: u32 = 0x0001_0002_u32;

pub type OpretSeal = TxoSeal<OpretProof>;
pub type TapretSeal = TxoSeal<TapretProof>;

/// Parameters used by BP-based wallet for constructing operations.
///
/// Differs from [`hypersonic::CallParams`] in the fact that it uses [`TxoSeal`]s instead of
/// AuthTokens for output definitions.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConstructParams<D: dbc::Proof> {
    pub method: MethodName,
    pub global: Vec<NamedState<StateAtom>>,
    pub owned: BTreeMap<TxoSeal<D>, NamedState<StrictVal>>,
    pub using: Vec<(AuthToken, StrictVal)>,
    pub reading: Vec<CellAddr>,
}

/// Prefabricated operation, which includes information on the contract id and closed seals
/// (previous outputs).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = "RGB")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Prefab {
    pub contract_id: ContractId,
    pub closes: SmallOrdSet<Outpoint>,
    pub operation: Operation,
}

/// A pack of prefabricated operations related to the same witness transaction.
///
/// The pack should cover all contracts assigning state to the witness transaction previous outputs.
/// It is used to add seal closing commitment to the witness transaction PSBT.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = "RGB")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PrefabPack(SmallOrdSet<Prefab>);

impl StrictSerialize for Prefab {}
impl StrictDeserialize for Prefab {}

impl<D: dbc::Proof> Protocol for TxoSeal<D> {
    type Id = Txid;

    fn auth_token(&self) -> AuthToken { todo!() }
}

/// Barrow contains a bunch of RGB contract stockpiles, which are held by a single owner; such that
/// when a new operation under any of the contracts happen it may affect other contracts sharing the
/// same UTXOs.
pub struct Barrow<
    W: WalletDescriptor,
    D: dbc::Proof,
    S: Supply<CAPS>,
    P: Pile<Seal = TxoSeal<D>>,
    X,
    const CAPS: u32,
> {
    pub wallet: W,
    //pub unspent: BTreeMap<Outpoint, BTreeSet<(ContractId, TxoSeal<D>)>>,
    pub mound: Mound<S, P, X, CAPS>,
}

impl<
        W: WalletDescriptor,
        D: dbc::Proof,
        S: Supply<CAPS>,
        P: Pile<Seal = TxoSeal<D>>,
        X,
        const CAPS: u32,
    > Barrow<W, D, S, P, X, CAPS>
{
    pub fn with(wallet: W, mound: Mound<S, P, X, CAPS>) -> Self { Self { wallet, mound } }

    pub fn unbind(self) -> (W, Mound<S, P, X, CAPS>) { (self.wallet, self.mound) }

    pub fn issue(&mut self, schema: Schema, params: IssueParams, supply: S, pile: P) -> ContractId {
        self.mound.issue(schema, params, supply, pile)
    }

    /*
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
     */

    pub fn new_vout(&mut self, vout: Vout) -> TxoSeal<D> { todo!() }

    pub fn new_seal(&mut self) -> TxoSeal<D> { todo!() }

    pub fn resolve_seal(&self, opout: CellAddr) -> TxoSeal<D> { todo!() }

    /// Creates a single operation basing on the provided construction parameters.
    pub fn prefab(&self, contract_id: ContractId, params: ConstructParams<D>) -> Prefab {
        // convert ExecParams into CallParams
        todo!()
    }

    /// Completes creation of a prefabricated operation pack, adding blank operations if necessary.
    pub fn complete(&self, ops: impl IntoIterator<Item = Prefab>) -> PrefabPack {
        // add blank operations
        todo!()
    }
}

pub mod file {
    use std::path::PathBuf;

    use hypersonic::{CodexId, FileSupply, IssueParams};

    use super::*;
    use crate::FilePile;

    pub type FileWallet<W, D: dbc::Proof, const CAPS: u32> =
        Barrow<W, D, FileSupply, FilePile<TxoSeal<D>>, PathBuf, CAPS>;

    impl<W: WalletDescriptor, D: dbc::Proof, const CAPS: u32> FileWallet<W, D, CAPS> {
        pub fn issue_file(&mut self, codex_id: CodexId, params: IssueParams) -> ContractId {
            let schema = self.mound.schema(codex_id).expect("unknown codex id");
            // TODO: check that if the issue belongs to the wallet add it to the unspents
            self.mound.issue_file(schema.clone(), params)
        }
    }

    pub type DirBtcMound<D: dbc::Proof, const CAPS: u32> =
        Mound<FileSupply, FilePile<TxoSeal<D>>, PathBuf, CAPS>;
    pub type DirOpretMound = DirBtcMound<OpretProof, BITCOIN_OPRET>;
    pub type DirTapretMound = DirBtcMound<TapretProof, BITCOIN_TAPRET>;

    pub struct DirMound {
        opret: DirOpretMound,
        tapret: DirTapretMound,
    }

    pub type BpBarrow<W, D: dbc::Proof, const CAPS: u32> =
        Barrow<W, D, FileSupply, FilePile<TxoSeal<D>>, PathBuf, CAPS>;
    pub type DirOpretBarrow<W> = BpBarrow<W, OpretProof, BITCOIN_OPRET>;
    pub type DirTapretBarrow<W> = BpBarrow<W, TapretProof, BITCOIN_TAPRET>;

    pub enum DirBarrow<W: WalletDescriptor> {
        Opret(DirOpretBarrow<W>),
        Tapret(DirTapretBarrow<W>),
    }

    impl<W: WalletDescriptor> DirBarrow<W> {
        pub fn issue_file(&mut self, codex_id: CodexId, params: IssueParams) -> ContractId {
            match self {
                DirBarrow::Opret(barrow) => barrow.issue_file(codex_id, params),
                DirBarrow::Tapret(barrow) => barrow.issue_file(codex_id, params),
            }
        }
    }
}
