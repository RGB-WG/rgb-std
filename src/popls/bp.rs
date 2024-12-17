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
use std::collections::BTreeSet;

use amplify::confinement::SmallOrdSet;
use amplify::{confinement, Bytes32};
use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::seals::TxoSeal;
use bp::{dbc, Outpoint, Vout};
use commit_verify::{Digest, DigestExt, Sha256};
use hypersonic::{
    AdaptedState, AuthToken, CallParams, CellAddr, ContractId, CoreParams, DataCell, MethodName,
    NamedState, Operation, Schema, StateAtom, StateCalc, StateName, Supply,
};
use rgb::SonicSeal;
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::StrictVal;

use crate::stockpile::EitherSeal;
use crate::{Assignment, CreateParams, Excavate, Mound, Pile};

pub trait WalletProvider {
    fn noise_seed(&self) -> Bytes32;
    fn utxos(&self) -> impl Iterator<Item = Outpoint>;
}
pub trait OpretProvider: WalletProvider {}
pub trait TapretProvider: WalletProvider {}

pub const BP_BLANK_METHOD: &str = "_";

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

impl EitherSeal<Outpoint> {
    pub fn transform<D: dbc::Proof>(
        self,
        noise_engine: Sha256,
        nonce: u64,
    ) -> EitherSeal<TxoSeal<D>> {
        match self {
            EitherSeal::Known(seal) => {
                EitherSeal::Known(TxoSeal::no_fallback(seal, noise_engine, nonce))
            }
            EitherSeal::External(auth) => EitherSeal::External(auth),
        }
    }
}

impl CreateParams<Outpoint> {
    pub fn transform<D: dbc::Proof>(self, mut noise_engine: Sha256) -> CreateParams<TxoSeal<D>> {
        noise_engine.input_raw(self.codex_id.as_slice());
        noise_engine.input_raw(&(self.seal_type as u32).to_le_bytes());
        noise_engine.input_raw(self.method.as_bytes());
        noise_engine.input_raw(self.name.as_bytes());
        noise_engine.input_raw(&self.timestamp.unwrap_or_default().timestamp().to_le_bytes());
        CreateParams {
            codex_id: self.codex_id,
            seal_type: self.seal_type,
            method: self.method,
            name: self.name,
            timestamp: self.timestamp,
            global: self.global,
            owned: self
                .owned
                .into_iter()
                .enumerate()
                .map(|(nonce, assignment)| NamedState {
                    name: assignment.name,
                    state: Assignment {
                        seal: assignment
                            .state
                            .seal
                            .transform(noise_engine.clone(), nonce as u64),
                        data: assignment.state.data,
                    },
                })
                .collect(),
        }
    }
}

/// Parameters used by BP-based wallet for constructing operations.
///
/// Differs from [`CallParams`] in the fact that it uses [`BuilderSeal`]s instead of
/// [`hypersonic::AuthTokens`] for output definitions.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct ConstructParams {
    pub contract_id: ContractId,
    pub method: MethodName,
    pub reading: Vec<CellAddr>,
    pub using: Vec<(CellAddr, Outpoint, StrictVal)>,
    pub global: Vec<NamedState<StateAtom>>,
    pub owned: Vec<(BuilderSeal, NamedState<StrictVal>)>,
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

    pub fn issue(&mut self, params: CreateParams<Outpoint>, supply: S, pile: P) -> ContractId {
        self.mound
            .issue(params.transform(self.noise_engine()), supply, pile)
    }

    pub fn auth_token(&mut self, nonce: u64) -> Option<AuthToken> {
        let outpoint = self.wallet.utxos().next()?;
        let seal = TxoSeal::<OpretProof>::no_fallback(outpoint, self.noise_engine(), nonce);
        Some(seal.auth_token())
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

    fn noise_engine(&self) -> Sha256 {
        let noise_seed = self.wallet.noise_seed();
        let mut noise_engine = Sha256::new();
        noise_engine.input_raw(noise_seed.as_ref());
        noise_engine
    }

    /// Creates a single operation basing on the provided construction parameters.
    pub fn prefab(&mut self, params: ConstructParams) -> Prefab {
        // convert ConstructParams into CallParams
        let (closes, using) = params
            .using
            .into_iter()
            .map(|(auth, outpoint, val)| (outpoint, (auth, val)))
            .unzip();
        let closes = SmallOrdSet::try_from(closes).expect("too many inputs");
        let mut defines = SmallOrdSet::new();

        let mut noise_engine = self.noise_engine();
        noise_engine.input_raw(params.contract_id.as_slice());
        let owned = params
            .owned
            .into_iter()
            .enumerate()
            .map(|(nonce, (seal, val))| {
                let seal = match seal {
                    BuilderSeal::Oneself(vout) => {
                        defines.push(vout).expect("too many seals");
                        // NB: We use opret type here, but this doesn't matter since we create seal
                        // only to produce the auth token, and seals do not commit to their type.
                        TxoSeal::<OpretProof>::vout_no_fallback(
                            vout,
                            noise_engine.clone(),
                            nonce as u64,
                        )
                    }
                    BuilderSeal::Extern(outpoint) => {
                        TxoSeal::no_fallback(outpoint, noise_engine.clone(), nonce as u64)
                    }
                };
                let state = DataCell {
                    data: val.state,
                    auth: seal.auth_token(),
                    lock: None,
                };
                NamedState {
                    name: val.name,
                    state,
                }
            })
            .collect();

        let call = CallParams {
            core: CoreParams {
                method: params.method,
                global: params.global,
                owned,
            },
            using,
            reading: params.reading,
        };

        let stockpile = self.mound.contract_mut(params.contract_id);
        let opid = stockpile.stock_mut().call(call);
        let operation = stockpile.stock_mut().operation(opid);

        Prefab {
            contract_id: params.contract_id,
            closes,
            defines,
            operation,
        }
    }

    /// Completes creation of a prefabricated operation pack, adding blank operations if necessary.
    pub fn bundle(
        &mut self,
        ops: impl IntoIterator<Item = Prefab>,
        seal: BuilderSeal,
    ) -> PrefabBundle {
        let mut outpoints = BTreeSet::<Outpoint>::new();
        let mut contracts = BTreeSet::new();
        let mut prefabs = BTreeSet::new();
        for prefab in ops {
            contracts.insert(prefab.contract_id);
            outpoints.extend(&prefab.closes);
            prefabs.insert(prefab);
        }

        let mut prefab_params = Vec::new();
        let root_noise_engine = self.noise_engine();
        for (contract_id, stockpile) in self.mound.contracts_mut() {
            let mut noise_engine = root_noise_engine.clone();
            noise_engine.input_raw(contract_id.as_slice());

            // TODO: Simplify the expression
            // We need to clone here not to conflict with mutable call below
            let owned = stockpile.stock().state().main.owned.clone();
            let (using, prev): (_, Vec<_>) = owned
                .iter()
                .flat_map(|(name, map)| map.iter().map(move |(addr, val)| (name, *addr, val)))
                .filter_map(|(name, addr, val)| {
                    let auth = stockpile.stock_mut().operation(addr.opid).destructible
                        [addr.pos as usize]
                        .auth;
                    outpoints
                        .iter()
                        .copied()
                        .enumerate()
                        .find(|(nonce, outpoint)| {
                            TxoSeal::<OpretProof>::no_fallback(
                                *outpoint,
                                noise_engine.clone(),
                                *nonce as u64,
                            )
                            .auth_token()
                                == auth
                        })
                        .map(|(_, outpoint)| {
                            ((addr, outpoint, StrictVal::Unit), (name.clone(), val))
                        })
                })
                .unzip();

            let api = &stockpile.stock().articles().schema.default_api;
            let mut calcs = BTreeMap::<StateName, Box<dyn StateCalc>>::new();
            for (name, val) in prev {
                let calc = calcs
                    .entry(name.clone())
                    .or_insert_with(|| api.calculate(name));
                calc.accumulate(val.clone()).expect("non-computable state");
            }

            let mut owned = Vec::new();
            for (name, calc) in calcs {
                for state in calc.diff().expect("non-computable state") {
                    let state = NamedState {
                        name: name.clone(),
                        state,
                    };
                    owned.push((seal, state));
                }
            }

            let params = ConstructParams {
                contract_id,
                method: MethodName::from(BP_BLANK_METHOD),
                global: none!(),
                reading: none!(),
                using,
                owned,
            };
            prefab_params.push(params);
        }

        prefabs.extend(prefab_params.into_iter().map(|params| self.prefab(params)));

        PrefabBundle(SmallOrdSet::try_from(prefabs).expect("too many operations"))
    }
}

pub mod file {
    use std::ffi::OsStr;
    use std::path::Path;
    use std::{fs, iter};

    use hypersonic::{CodexId, FileSupply};
    #[cfg(feature = "bitcoin")]
    use rgb::{BITCOIN_OPRET, BITCOIN_TAPRET};
    #[cfg(feature = "liquid")]
    use rgb::{LIQUID_OPRET, LIQUID_TAPRET};

    use super::*;
    use crate::mound::file::DirExcavator;
    use crate::{ContractInfo, FilePile, SealType};

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
            let bc_tapret =
                { DirBcTapretMound::load(root.join(SealType::BitcoinTapret.to_string())) };

            #[cfg(feature = "liquid")]
            let lq_opret = { DirLqOpretMound::load(root.join(SealType::LiquidOpret.to_string())) };

            #[cfg(feature = "liquid")]
            let lq_tapret =
                { DirLqTapretMound::load(root.join(SealType::LiquidTapret.to_string())) };

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
            let iter = self.schemata.keys().copied();
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
            let iter = self.schemata.iter().map(|(k, v)| (*k, v));
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
            let res = self.schemata.get(&codex_id);
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
                Self::BcOpret(barrow) => {
                    barrow.issue_to_file(params.transform(barrow.noise_engine()))
                }
                #[cfg(feature = "bitcoin")]
                Self::BcTapret(barrow) => {
                    barrow.issue_to_file(params.transform(barrow.noise_engine()))
                }
                #[cfg(feature = "liquid")]
                Self::LqOpret(barrow) => {
                    barrow.issue_to_file(params.transform(barrow.noise_engine()))
                }
                #[cfg(feature = "liquid")]
                Self::LqTapret(barrow) => {
                    barrow.issue_to_file(params.transform(barrow.noise_engine()))
                }
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

        pub fn prefab(&mut self, params: ConstructParams) -> Prefab {
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

        pub fn bundle(&mut self, items: impl IntoIterator<Item = ConstructParams>) -> PrefabBundle {
            let iter = items.into_iter().map(|params| self.prefab(params));
            let items = SmallOrdSet::try_from_iter(iter).expect("too large script");
            PrefabBundle(items)
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
}
