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

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;
use std::{fs, io, iter};

use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::seals::TxoSeal;
use bp::{dbc, Vout};
use hypersonic::{CodexId, FileSupply, Schema};
use invoice::bp::WitnessOut;
#[cfg(feature = "bitcoin")]
use rgb::{BITCOIN_OPRET, BITCOIN_TAPRET};
#[cfg(feature = "liquid")]
use rgb::{LIQUID_OPRET, LIQUID_TAPRET};
use strict_encoding::{StreamReader, StrictReader};

use super::*;
use crate::mound::file::DirExcavator;
use crate::{
    AuthToken, ContractId, ContractInfo, ContractState, CreateParams, FilePile, Mound, Outpoint,
    SealType,
};

pub type FileWallet<W, D, const CAPS: u32> =
    Barrow<W, D, FileSupply, FilePile<TxoSeal<D>>, DirExcavator<TxoSeal<D>, CAPS>, CAPS>;

impl<W: WalletProvider, D: dbc::Proof, const CAPS: u32> FileWallet<W, D, CAPS> {
    pub fn issue_to_file(&mut self, params: CreateParams<TxoSeal<D>>) -> ContractId {
        // TODO: check that if the issue belongs to the wallet add it to the unspents
        self.mound.issue_to_file(params)
    }
}

pub type DirBtcMound<D, const CAPS: u32> =
    Mound<FileSupply, FilePile<TxoSeal<D>>, DirExcavator<TxoSeal<D>, CAPS>, CAPS>;

#[cfg(feature = "bitcoin")]
pub type DirBcOpretMound = DirBtcMound<OpretProof, BITCOIN_OPRET>;
#[cfg(feature = "bitcoin")]
pub type DirBcTapretMound = DirBtcMound<TapretProof, BITCOIN_TAPRET>;
#[cfg(feature = "liquid")]
pub type DirLqOpretMound = DirBtcMound<OpretProof, LIQUID_OPRET>;
#[cfg(feature = "liquid")]
pub type DirLqTapretMound = DirBtcMound<TapretProof, LIQUID_TAPRET>;

pub struct DirMound {
    pub schemata: BTreeMap<CodexId, Schema>,
    #[cfg(feature = "bitcoin")]
    pub bc_opret: DirBcOpretMound,
    #[cfg(feature = "bitcoin")]
    pub bc_tapret: DirBcTapretMound,
    #[cfg(feature = "liquid")]
    pub lq_opret: DirLqOpretMound,
    #[cfg(feature = "liquid")]
    pub lq_tapret: DirLqTapretMound,
}

impl DirMound {
    pub fn load(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        let schemata = fs::read_dir(root)
            .expect("unable to read directory")
            .filter_map(|entry| {
                let entry = entry.expect("unable to read directory");
                let ty = entry.file_type().expect("unable to read file type");
                if ty.is_file()
                    && entry.path().extension().and_then(OsStr::to_str) == Some("issuer")
                {
                    Schema::load(entry.path())
                        .inspect_err(|err| eprintln!("Unable to load schema: {}", err))
                        .ok()
                        .map(|schema| (schema.codex.codex_id(), schema))
                } else {
                    None
                }
            })
            .collect();

        #[cfg(feature = "bitcoin")]
        let bc_opret = { DirBcOpretMound::load(root.join(SealType::BitcoinOpret.to_string())) };

        #[cfg(feature = "bitcoin")]
        let bc_tapret = { DirBcTapretMound::load(root.join(SealType::BitcoinTapret.to_string())) };

        #[cfg(feature = "liquid")]
        let lq_opret = { DirLqOpretMound::load(root.join(SealType::LiquidOpret.to_string())) };

        #[cfg(feature = "liquid")]
        let lq_tapret = { DirLqTapretMound::load(root.join(SealType::LiquidTapret.to_string())) };

        Self {
            schemata,
            #[cfg(feature = "bitcoin")]
            bc_opret,
            #[cfg(feature = "bitcoin")]
            bc_tapret,
            #[cfg(feature = "liquid")]
            lq_opret,
            #[cfg(feature = "liquid")]
            lq_tapret,
        }
    }

    pub fn codex_ids(&self) -> impl Iterator<Item = CodexId> + use<'_> {
        self.schemata.keys().copied()
    }

    pub fn schemata(&self) -> impl Iterator<Item = (CodexId, &Schema)> {
        self.schemata.iter().map(|(k, v)| (*k, v))
    }

    pub fn schema(&self, codex_id: CodexId) -> Option<&Schema> { self.schemata.get(&codex_id) }

    pub fn contract_ids(&self) -> impl Iterator<Item = ContractId> + use<'_> {
        let iter = iter::empty();
        #[cfg(feature = "bitcoin")]
        let iter = iter.chain(self.bc_opret.contract_ids());
        #[cfg(feature = "bitcoin")]
        let iter = iter.chain(self.bc_tapret.contract_ids());
        #[cfg(feature = "liquid")]
        let iter = iter.chain(self.lq_opret.contract_ids());
        #[cfg(feature = "liquid")]
        let iter = iter.chain(self.lq_tapret.contract_ids());
        iter
    }

    pub fn contracts_info(&self) -> impl Iterator<Item = ContractInfo> + use<'_> {
        let iter = iter::empty();
        #[cfg(feature = "bitcoin")]
        let iter = iter.chain(self.bc_opret.contracts_info());
        #[cfg(feature = "bitcoin")]
        let iter = iter.chain(self.bc_tapret.contracts_info());
        #[cfg(feature = "liquid")]
        let iter = iter.chain(self.lq_opret.contracts_info());
        #[cfg(feature = "liquid")]
        let iter = iter.chain(self.lq_tapret.contracts_info());
        iter
    }
}

pub type BpBarrow<W, D, const CAPS: u32> =
    Barrow<W, D, FileSupply, FilePile<TxoSeal<D>>, DirExcavator<TxoSeal<D>, CAPS>, CAPS>;

pub struct DirBpBarrow<W: WalletProvider> {
    #[cfg(feature = "bitcoin")]
    bc_opret: BpBarrow<W, OpretProof, BITCOIN_OPRET>,
    #[cfg(feature = "bitcoin")]
    bc_tapret: BpBarrow<W, TapretProof, BITCOIN_TAPRET>,
    #[cfg(feature = "liquid")]
    lq_opret: BpBarrow<W, OpretProof, LIQUID_OPRET>,
    #[cfg(feature = "liquid")]
    lq_tapret: BpBarrow<W, TapretProof, LIQUID_TAPRET>,
}

impl<W: WalletProvider> DirBpBarrow<W> {
    pub fn load_opret(ty: SealType, root: impl AsRef<Path>, wallet: O) -> Self {
        let mound = DirMound::load(root.as_ref());
        Self::with_opret(ty, mound, wallet)
    }

    pub fn load_tapret(ty: SealType, root: impl AsRef<Path>, wallet: T) -> Self {
        let mound = DirMound::load(root);
        Self::with_tapret(ty, mound, wallet)
    }

    pub fn with_opret(ty: SealType, mound: DirMound, wallet: O) -> Self {
        match ty {
            #[cfg(feature = "bitcoin")]
            SealType::BitcoinOpret => Self::BcOpret(BpBarrow::with(wallet, mound.bc_opret)),
            #[cfg(feature = "liquid")]
            SealType::LiquidOpret => Self::LqOpret(BpBarrow::with(wallet, mound.lq_opret)),
            _ => panic!("unsupported seal type"),
        }
    }

    pub fn with_tapret(ty: SealType, mound: DirMound, wallet: T) -> Self {
        match ty {
            #[cfg(feature = "bitcoin")]
            SealType::BitcoinTapret => Self::BcTapret(BpBarrow::with(wallet, mound.bc_tapret)),
            #[cfg(feature = "liquid")]
            SealType::LiquidTapret => Self::LqTapret(BpBarrow::with(wallet, mound.lq_tapret)),
            _ => panic!("unsupported seal type"),
        }
    }

    pub fn issue_to_file(&mut self, params: CreateParams<Outpoint>) -> ContractId {
        match self {
            #[cfg(feature = "bitcoin")]
            Self::BcOpret(barrow) => barrow.issue_to_file(params.transform(barrow.noise_engine())),
            #[cfg(feature = "bitcoin")]
            Self::BcTapret(barrow) => barrow.issue_to_file(params.transform(barrow.noise_engine())),
            #[cfg(feature = "liquid")]
            Self::LqOpret(barrow) => barrow.issue_to_file(params.transform(barrow.noise_engine())),
            #[cfg(feature = "liquid")]
            Self::LqTapret(barrow) => barrow.issue_to_file(params.transform(barrow.noise_engine())),
        }
    }

    pub fn auth_token(&mut self, nonce: u64) -> Option<AuthToken> {
        match self {
            #[cfg(feature = "bitcoin")]
            Self::BcOpret(barrow) => barrow.auth_token(nonce),
            #[cfg(feature = "bitcoin")]
            Self::BcTapret(barrow) => barrow.auth_token(nonce),
            #[cfg(feature = "liquid")]
            Self::LqOpret(barrow) => barrow.auth_token(nonce),
            #[cfg(feature = "liquid")]
            Self::LqTapret(barrow) => barrow.auth_token(nonce),
        }
    }

    pub fn wout(&mut self, nonce: u64) -> WitnessOut {
        match self {
            #[cfg(feature = "bitcoin")]
            Self::BcOpret(barrow) => barrow.wout(nonce),
            #[cfg(feature = "bitcoin")]
            Self::BcTapret(barrow) => barrow.wout(nonce),
            #[cfg(feature = "liquid")]
            Self::LqOpret(barrow) => barrow.wout(nonce),
            #[cfg(feature = "liquid")]
            Self::LqTapret(barrow) => barrow.wout(nonce),
        }
    }

    pub fn state(
        &mut self,
        contract_id: Option<ContractId>,
    ) -> Box<dyn Iterator<Item = (ContractId, ContractState<Outpoint>)> + '_> {
        match self {
            #[cfg(feature = "bitcoin")]
            Self::BcOpret(barrow) => Box::new(barrow.state(contract_id)),
            #[cfg(feature = "bitcoin")]
            Self::BcTapret(barrow) => Box::new(barrow.state(contract_id)),
            #[cfg(feature = "liquid")]
            Self::LqOpret(barrow) => Box::new(barrow.state(contract_id)),
            #[cfg(feature = "liquid")]
            Self::LqTapret(barrow) => Box::new(barrow.state(contract_id)),
        }
    }

    pub fn state_all(
        &mut self,
        contract_id: Option<ContractId>,
    ) -> Box<dyn Iterator<Item = (ContractId, ContractState<Outpoint>)> + '_> {
        match self {
            #[cfg(feature = "bitcoin")]
            Self::BcOpret(barrow) => Box::new(barrow.state_all(contract_id)),
            #[cfg(feature = "bitcoin")]
            Self::BcTapret(barrow) => Box::new(barrow.state_all(contract_id)),
            #[cfg(feature = "liquid")]
            Self::LqOpret(barrow) => Box::new(barrow.state_all(contract_id)),
            #[cfg(feature = "liquid")]
            Self::LqTapret(barrow) => Box::new(barrow.state_all(contract_id)),
        }
    }

    pub fn prefab(&mut self, params: PrefabParams<Vout>) -> Prefab {
        match self {
            #[cfg(feature = "bitcoin")]
            Self::BcOpret(barrow) => barrow.prefab(params),
            #[cfg(feature = "bitcoin")]
            Self::BcTapret(barrow) => barrow.prefab(params),
            #[cfg(feature = "liquid")]
            Self::LqOpret(barrow) => barrow.prefab(params),
            #[cfg(feature = "liquid")]
            Self::LqTapret(barrow) => barrow.prefab(params),
        }
    }

    pub fn bundle(
        &mut self,
        items: impl IntoIterator<Item = PrefabParams<Vout>>,
        change: Vout,
    ) -> PrefabBundle {
        match self {
            #[cfg(feature = "bitcoin")]
            Self::BcOpret(barrow) => barrow.bundle(items, change),
            #[cfg(feature = "bitcoin")]
            Self::BcTapret(barrow) => barrow.bundle(items, change),
            #[cfg(feature = "liquid")]
            Self::LqOpret(barrow) => barrow.bundle(items, change),
            #[cfg(feature = "liquid")]
            Self::LqTapret(barrow) => barrow.bundle(items, change),
        }
    }

    pub fn consume_from_file(&mut self, path: impl AsRef<Path>) -> io::Result<()> {
        let file = File::open(path)?;
        let mut reader = StrictReader::with(StreamReader::new::<{ usize::MAX }>(file));
        match self {
            #[cfg(feature = "bitcoin")]
            Self::BcOpret(barrow) => barrow
                .consume(&mut reader)
                .unwrap_or_else(|err| panic!("Unable to accept a consignment: {err}")),
            #[cfg(feature = "bitcoin")]
            Self::BcTapret(barrow) => barrow
                .consume(&mut reader)
                .unwrap_or_else(|err| panic!("Unable to accept a consignment: {err}")),
            #[cfg(feature = "liquid")]
            Self::LqOpret(barrow) => barrow
                .consume(&mut reader)
                .unwrap_or_else(|err| panic!("Unable to accept a consignment: {err}")),
            #[cfg(feature = "liquid")]
            Self::LqTapret(barrow) => barrow
                .consume(&mut reader)
                .unwrap_or_else(|err| panic!("Unable to accept a consignment: {err}")),
        }
        Ok(())
    }

    pub fn wallet_tapret(&mut self) -> &mut T {
        match self {
            #[cfg(feature = "bitcoin")]
            Self::BcTapret(barrow) => &mut barrow.wallet,
            #[cfg(feature = "liquid")]
            Self::LqTapret(barrow) => &mut barrow.wallet,
            _ => panic!("Invalid wallet type"),
        }
    }

    pub fn wallet_opret(&mut self) -> &mut O {
        match self {
            #[cfg(feature = "bitcoin")]
            Self::BcOpret(barrow) => &mut barrow.wallet,
            #[cfg(feature = "liquid")]
            Self::LqOpret(barrow) => &mut barrow.wallet,
            _ => panic!("Invalid wallet type"),
        }
    }
}
