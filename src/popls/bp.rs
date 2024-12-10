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

//! Implementation of RGB standard library types for Bitcoin protocol, covering Bitcoin and Liquid
//! proof of publication layer 1.

use alloc::collections::BTreeMap;

use amplify::confinement;
use amplify::confinement::SmallOrdSet;
use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::seals::TxoSeal;
use bp::{dbc, Outpoint, Txid, Vout};
use hypersonic::{
    AdaptedState, AuthToken, CellAddr, CodexId, ContractId, IssueParams, MethodName, NamedState,
    Operation, Schema, StateAtom, Supply,
};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::StrictVal;

use crate::pile::Protocol;
use crate::{Excavate, Mound, Pile};

pub trait WalletProvider {}
pub trait OpretProvider: WalletProvider {}
pub trait TapretProvider: WalletProvider {}

#[cfg(feature = "bitcoin")]
pub const BITCOIN_OPRET: u32 = 0x0001_0001_u32;
#[cfg(feature = "bitcoin")]
pub const BITCOIN_TAPRET: u32 = 0x0001_0002_u32;
#[cfg(feature = "liquid")]
pub const LIQUID_OPRET: u32 = 0x0002_0001_u32;
#[cfg(feature = "liquid")]
pub const LIQUID_TAPRET: u32 = 0x0002_0002_u32;

pub type OpretSeal = TxoSeal<OpretProof>;
pub type TapretSeal = TxoSeal<TapretProof>;

impl<D: dbc::Proof> Protocol for TxoSeal<D> {
    type Id = Txid;

    fn auth_token(&self) -> AuthToken { todo!() }
}

// TODO: Support failback seals
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase", untagged)
)]
pub enum BuilderSeal {
    #[display("~:{0}")]
    Oneself(Vout),

    #[display("{0}")]
    Extern(Outpoint),
}

/// Parameters used by BP-based wallet for constructing operations.
///
/// Differs from [`hypersonic::CallParams`] in the fact that it uses [`TxoSeal`]s instead of
/// AuthTokens for output definitions.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct ConstructParams {
    pub contract_id: ContractId,
    pub method: MethodName,
    pub global: Vec<NamedState<StateAtom>>,
    pub owned: BTreeMap<BuilderSeal, NamedState<StrictVal>>,
    pub using: Vec<(AuthToken, StrictVal)>,
    pub reading: Vec<CellAddr>,
}

/// Prefabricated operation, which includes information on the contract id and closed seals
/// (previous outputs).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = "RGB")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Prefab {
    pub contract_id: ContractId,
    pub closes: SmallOrdSet<Outpoint>,
    pub defines: SmallOrdSet<Vout>,
    pub operation: Operation,
}

/// A bundle of prefabricated operations related to the same witness transaction.
///
/// The pack should cover all contracts assigning state to the witness transaction previous outputs.
/// It is used to add seal closing commitment to the witness transaction PSBT.
#[derive(Wrapper, WrapperMut, Clone, Eq, PartialEq, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = "RGB")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct PrefabBundle(SmallOrdSet<Prefab>);

impl StrictSerialize for PrefabBundle {}
impl StrictDeserialize for PrefabBundle {}

impl PrefabBundle {
    pub fn new(items: impl IntoIterator<Item = Prefab>) -> Result<Self, confinement::Error> {
        let items = SmallOrdSet::try_from_iter(items.into_iter())?;
        Ok(Self(items))
    }

    pub fn closes(&self) -> impl Iterator<Item = Outpoint> + use<'_> {
        self.0.iter().flat_map(|item| item.closes.iter().copied())
    }

    pub fn defines(&self) -> impl Iterator<Item = Vout> + use<'_> {
        self.0.iter().flat_map(|item| item.defines.iter().copied())
    }
}

/// Barrow contains a bunch of RGB contract stockpiles, which are held by a single owner; such that
/// when a new operation under any of the contracts happen it may affect other contracts sharing the
/// same UTXOs.
pub struct Barrow<
    W: WalletProvider,
    D: dbc::Proof,
    S: Supply<CAPS>,
    P: Pile<Seal = TxoSeal<D>>,
    X: Excavate<S, P, CAPS>,
    const CAPS: u32,
> {
    pub wallet: W,
    //pub unspent: BTreeMap<Outpoint, BTreeSet<(ContractId, TxoSeal<D>)>>,
    pub mound: Mound<S, P, X, CAPS>,
}

impl<
        W: WalletProvider,
        D: dbc::Proof,
        S: Supply<CAPS>,
        P: Pile<Seal = TxoSeal<D>>,
        X: Excavate<S, P, CAPS>,
        const CAPS: u32,
    > Barrow<W, D, S, P, X, CAPS>
{
    pub fn with(wallet: W, mound: Mound<S, P, X, CAPS>) -> Self { Self { wallet, mound } }

    pub fn unbind(self) -> (W, Mound<S, P, X, CAPS>) { (self.wallet, self.mound) }

    pub fn issue(
        &mut self,
        codex_id: CodexId,
        params: IssueParams,
        supply: S,
        pile: P,
    ) -> ContractId {
        self.mound.issue(codex_id, params, supply, pile)
    }

    // TODO: Use bitcoin-specific state type aware of outpoints
    pub fn state(
        &self,
        contract_id: Option<ContractId>,
    ) -> impl Iterator<Item = (ContractId, &AdaptedState)> {
        self.mound
            .contracts()
            .filter(move |(id, _)| contract_id.is_none() || Some(*id) == contract_id)
            .map(|(id, stockpile)| (id, &stockpile.stock().state().main))
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
    pub fn prefab(&self, params: ConstructParams) -> Prefab {
        // convert ExecParams into CallParams
        todo!()
    }

    /// Completes creation of a prefabricated operation pack, adding blank operations if necessary.
    pub fn bundle(&self, ops: impl IntoIterator<Item = Prefab>) -> PrefabBundle {
        // add blank operations
        todo!()
    }
}

pub mod file {
    use std::iter;
    use std::path::Path;

    use hypersonic::{CodexId, FileSupply, IssueParams};

    use super::*;
    use crate::mound::file::DirExcavator;
    use crate::{FilePile, SealType};

    pub type FileWallet<W, D, const CAPS: u32> =
        Barrow<W, D, FileSupply, FilePile<TxoSeal<D>>, DirExcavator<TxoSeal<D>, CAPS>, CAPS>;

    impl<W: WalletProvider, D: dbc::Proof, const CAPS: u32> FileWallet<W, D, CAPS> {
        pub fn issue_file(&mut self, codex_id: CodexId, params: IssueParams) -> ContractId {
            // TODO: check that if the issue belongs to the wallet add it to the unspents
            self.mound.issue_file(codex_id, params)
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
            #[cfg(feature = "bitcoin")]
            let bc_opret = {
                let path = root.as_ref().join(SealType::BitcoinOpret.to_string());
                DirBcOpretMound::load(path)
            };

            #[cfg(feature = "bitcoin")]
            let bc_tapret = {
                let path = root.as_ref().join(SealType::BitcoinTapret.to_string());
                DirBcTapretMound::load(path)
            };

            #[cfg(feature = "liquid")]
            let lq_opret = {
                let path = root.as_ref().join(SealType::LiquidOpret.to_string());
                DirLqOpretMound::load(path)
            };

            #[cfg(feature = "liquid")]
            let lq_tapret = {
                let path = root.as_ref().join(SealType::LiquidTapret.to_string());
                DirLqTapretMound::load(path)
            };

            Self {
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
            let iter = iter::empty();
            #[cfg(feature = "bitcoin")]
            let iter = iter.chain(self.bc_opret.codex_ids());
            #[cfg(feature = "bitcoin")]
            let iter = iter.chain(self.bc_tapret.codex_ids());
            #[cfg(feature = "liquid")]
            let iter = iter.chain(self.lq_opret.codex_ids());
            #[cfg(feature = "liquid")]
            let iter = iter.chain(self.lq_tapret.codex_ids());
            iter
        }

        pub fn schemata(&self) -> impl Iterator<Item = (CodexId, &Schema)> {
            let iter = iter::empty();
            #[cfg(feature = "bitcoin")]
            let iter = iter.chain(self.bc_opret.schemata());
            #[cfg(feature = "bitcoin")]
            let iter = iter.chain(self.bc_tapret.schemata());
            #[cfg(feature = "liquid")]
            let iter = iter.chain(self.lq_opret.schemata());
            #[cfg(feature = "liquid")]
            let iter = iter.chain(self.lq_tapret.schemata());
            iter
        }

        pub fn schema(&self, codex_id: CodexId) -> Option<&Schema> {
            let res = None;
            #[cfg(feature = "bitcoin")]
            let res = res.or_else(|| self.bc_opret.schema(codex_id));
            #[cfg(feature = "bitcoin")]
            let res = res.or_else(|| self.bc_tapret.schema(codex_id));
            #[cfg(feature = "liquid")]
            let res = res.or_else(|| self.lq_opret.schema(codex_id));
            #[cfg(feature = "liquid")]
            let res = res.or_else(|| self.lq_tapret.schema(codex_id));
            res
        }

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
    }

    pub type BpBarrow<W, D, const CAPS: u32> =
        Barrow<W, D, FileSupply, FilePile<TxoSeal<D>>, DirExcavator<TxoSeal<D>, CAPS>, CAPS>;

    #[cfg(feature = "bitcoin")]
    pub type DirBcOpretBarrow<W> = BpBarrow<W, OpretProof, BITCOIN_OPRET>;
    #[cfg(feature = "bitcoin")]
    pub type DirBcTapretBarrow<W> = BpBarrow<W, TapretProof, BITCOIN_TAPRET>;
    #[cfg(feature = "liquid")]
    pub type DirLqOpretBarrow<W> = BpBarrow<W, OpretProof, LIQUID_OPRET>;
    #[cfg(feature = "liquid")]
    pub type DirLqTapretBarrow<W> = BpBarrow<W, TapretProof, LIQUID_TAPRET>;

    pub enum DirBarrow<O: OpretProvider, T: TapretProvider> {
        #[cfg(feature = "bitcoin")]
        BcOpret(DirBcOpretBarrow<O>),
        #[cfg(feature = "bitcoin")]
        BcTapret(DirBcTapretBarrow<T>),
        #[cfg(feature = "liquid")]
        LqOpret(DirLqOpretBarrow<O>),
        #[cfg(feature = "liquid")]
        LqTapret(DirLqTapretBarrow<T>),
    }

    impl<O: OpretProvider, T: TapretProvider> DirBarrow<O, T> {
        pub fn load_opret(ty: SealType, root: impl AsRef<Path>, wallet: O) -> Self {
            let mound = DirMound::load(root);
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

        pub fn issue_file(&mut self, codex_id: CodexId, params: IssueParams) -> ContractId {
            match self {
                #[cfg(feature = "bitcoin")]
                Self::BcOpret(barrow) => barrow.issue_file(codex_id, params),
                #[cfg(feature = "bitcoin")]
                Self::BcTapret(barrow) => barrow.issue_file(codex_id, params),
                #[cfg(feature = "liquid")]
                Self::LqOpret(barrow) => barrow.issue_file(codex_id, params),
                #[cfg(feature = "liquid")]
                Self::LqTapret(barrow) => barrow.issue_file(codex_id, params),
            }
        }

        pub fn state(
            &self,
            contract_id: Option<ContractId>,
        ) -> Box<dyn Iterator<Item = (ContractId, &AdaptedState)> + '_> {
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

        pub fn prefab(&self, params: ConstructParams) -> Prefab {
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

        pub fn bundle(&self, items: impl IntoIterator<Item = ConstructParams>) -> PrefabBundle {
            let iter = items.into_iter().map(|params| self.prefab(params));
            let items = SmallOrdSet::try_from_iter(iter).expect("too large script");
            PrefabBundle(items)
        }
    }
}
