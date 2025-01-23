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

use alloc::collections::{btree_set, BTreeMap, BTreeSet};
use alloc::vec;

use amplify::confinement::{SmallOrdMap, SmallOrdSet, SmallVec, TinyVec};
use amplify::{confinement, ByteArray, Bytes32, Wrapper};
use bp::dbc::tapret::TapretProof;
use bp::seals::{mmb, Anchor, TxoSeal};
use bp::{Outpoint, Sats, ScriptPubkey, Tx, Vout};
use commit_verify::mpc::ProtocolId;
use commit_verify::{mpc, Digest, DigestExt, Sha256};
use hypersonic::aora::Aora;
use hypersonic::{
    AuthToken, CallParams, CellAddr, ContractId, CoreParams, DataCell, MethodName, NamedState,
    Operation, StateAtom, StateCalc, StateName, Supply, UncountableState,
};
use invoice::bp::{Address, WitnessOut};
use invoice::{RgbBeneficiary, RgbInvoice};
use rgb::SealAuthToken;
use strict_encoding::{ReadRaw, StrictDecode, StrictDeserialize, StrictReader, StrictSerialize};
use strict_types::StrictVal;

use crate::stockpile::{ContractState, EitherSeal};
use crate::{Assignment, CreateParams, Excavate, IssueError, Mound, MoundConsumeError, Pile};

/// Trait abstracting specific implementation of a bitcoin wallet.
pub trait WalletProvider {
    fn noise_seed(&self) -> Bytes32;
    fn has_utxo(&self, outpoint: Outpoint) -> bool;
    fn utxos(&self) -> impl Iterator<Item = Outpoint>;
    fn register_seal(&mut self, seal: TxoSeal);
    fn resolve_seals(
        &self,
        seals: impl Iterator<Item = AuthToken>,
    ) -> impl Iterator<Item = TxoSeal>;
    fn next_address(&mut self) -> Address;
}

pub trait Coinselect {
    fn coinselect(
        &mut self,
        invoiced_state: &StrictVal,
        calc: &mut (impl StateCalc + ?Sized),
        owned_state: &BTreeMap<CellAddr, Assignment<Outpoint>>,
    ) -> Option<Vec<CellAddr>>;
}

pub const BP_BLANK_METHOD: &str = "_";

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum WoutAmount {
    #[display(inner)]
    Fixed(Sats),
    #[display("~")]
    Change,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{wout}/{amount}")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct WoutAssignment {
    pub wout: WitnessOut,
    pub amount: WoutAmount,
}

impl Into<ScriptPubkey> for WoutAssignment {
    fn into(self) -> ScriptPubkey { self.wout.into() }
}

impl<T> EitherSeal<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> EitherSeal<U> {
        match self {
            Self::Alt(seal) => EitherSeal::Alt(f(seal)),
            Self::Token(auth) => EitherSeal::Token(auth),
        }
    }
}

impl EitherSeal<Outpoint> {
    pub fn transform(self, noise_engine: Sha256, nonce: u64) -> EitherSeal<TxoSeal> {
        match self {
            EitherSeal::Alt(seal) => {
                EitherSeal::Alt(TxoSeal::no_fallback(seal, noise_engine, nonce))
            }
            EitherSeal::Token(auth) => EitherSeal::Token(auth),
        }
    }
}

impl CreateParams<Outpoint> {
    pub fn transform(self, mut noise_engine: Sha256) -> CreateParams<TxoSeal> {
        noise_engine.input_raw(self.codex_id.as_slice());
        noise_engine.input_raw(&[self.consensus as u8]);
        noise_engine.input_raw(self.method.as_bytes());
        noise_engine.input_raw(self.name.as_bytes());
        noise_engine.input_raw(&self.timestamp.unwrap_or_default().timestamp().to_le_bytes());
        CreateParams {
            codex_id: self.codex_id,
            consensus: self.consensus,
            testnet: self.testnet,
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

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct UsedState {
    pub addr: CellAddr,
    pub outpoint: Outpoint,
    pub val: StrictVal,
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound = "T: serde::Serialize + for<'d> serde::Deserialize<'d>"
    )
)]
pub struct PrefabParamsSet<T>(TinyVec<PrefabParams<T>>);

impl<T> IntoIterator for PrefabParamsSet<T> {
    type Item = PrefabParams<T>;
    type IntoIter = vec::IntoIter<PrefabParams<T>>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

impl<T: Into<ScriptPubkey>> PrefabParamsSet<T> {
    pub fn resolve_seals(
        self,
        resolver: impl Fn(&ScriptPubkey) -> Option<Vout>,
    ) -> Result<PrefabParamsSet<Vout>, UnresolvedSeal> {
        let mut items = Vec::with_capacity(self.0.len());
        for params in self.0 {
            let mut owned = Vec::with_capacity(params.owned.len());
            for assignment in params.owned {
                let seal = match assignment.state.seal {
                    EitherSeal::Alt(seal) => {
                        let spk = seal.into();
                        let vout = resolver(&spk).ok_or(UnresolvedSeal(spk))?;
                        EitherSeal::Alt(vout)
                    }
                    EitherSeal::Token(auth) => EitherSeal::Token(auth),
                };
                owned.push(NamedState {
                    name: assignment.name,
                    state: Assignment { seal, data: assignment.state.data },
                });
            }
            items.push(PrefabParams::<Vout> {
                contract_id: params.contract_id,
                method: params.method,
                reading: params.reading,
                using: params.using,
                global: params.global,
                owned,
            });
        }
        Ok(PrefabParamsSet(TinyVec::from_iter_checked(items)))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error)]
#[display("unable to resolve seal witness output seal definition for script pubkey {0:x}")]
pub struct UnresolvedSeal(ScriptPubkey);

/// Parameters used by BP-based wallet for constructing operations.
///
/// Differs from [`CallParams`] in the fact that it uses [`BuilderSeal`]s instead of
/// [`hypersonic::AuthTokens`] for output definitions.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound = "T: serde::Serialize + for<'d> serde::Deserialize<'d>"
    )
)]
pub struct PrefabParams<T> {
    pub contract_id: ContractId,
    pub method: MethodName,
    pub reading: Vec<CellAddr>,
    pub using: Vec<UsedState>,
    pub global: Vec<NamedState<StateAtom>>,
    pub owned: Vec<NamedState<Assignment<EitherSeal<T>>>>,
}

/// Prefabricated operation, which includes information on the contract id and closed seals
/// (previous outputs).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = "RGB")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Prefab {
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

impl IntoIterator for PrefabBundle {
    type Item = Prefab;
    type IntoIter = btree_set::IntoIter<Prefab>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

impl<'a> IntoIterator for &'a PrefabBundle {
    type Item = &'a Prefab;
    type IntoIter = btree_set::Iter<'a, Prefab>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

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
pub struct Barrow<W: WalletProvider, S: Supply, P: Pile<Seal = TxoSeal>, X: Excavate<S, P>> {
    pub wallet: W,
    pub mound: Mound<S, P, X>,
}

impl<W: WalletProvider, S: Supply, P: Pile<Seal = TxoSeal>, X: Excavate<S, P>> Barrow<W, S, P, X> {
    pub fn with(wallet: W, mound: Mound<S, P, X>) -> Self { Self { wallet, mound } }

    pub fn unbind(self) -> (W, Mound<S, P, X>) { (self.wallet, self.mound) }

    pub fn issue(
        &mut self,
        params: CreateParams<Outpoint>,
        supply: S,
        pile: P,
    ) -> Result<ContractId, IssueError> {
        self.mound
            .issue(params.transform(self.noise_engine()), supply, pile)
    }

    pub fn auth_token(&mut self, nonce: u64) -> Option<AuthToken> {
        let outpoint = self.wallet.utxos().next()?;
        let seal = TxoSeal::no_fallback(outpoint, self.noise_engine(), nonce);
        let auth = seal.auth_token();
        self.wallet.register_seal(seal);
        Some(auth)
    }

    pub fn wout(&mut self, nonce: u64) -> WitnessOut {
        let address = self.wallet.next_address();
        WitnessOut::new(address.payload, nonce)
    }

    pub fn state_own(
        &mut self,
        contract_id: Option<ContractId>,
    ) -> impl Iterator<Item = (ContractId, ContractState<Outpoint>)> + use<'_, W, S, P, X> {
        self.mound
            .contracts_mut()
            .filter(move |(id, _)| contract_id.is_none() || Some(*id) == contract_id)
            .map(|(id, stockpile)| {
                let state = stockpile.state().filter_map(|seal| {
                    if self.wallet.has_utxo(seal.primary) {
                        Some(seal.primary)
                    } else {
                        None
                    }
                });
                (id, state)
            })
    }

    pub fn state_all(
        &mut self,
        contract_id: Option<ContractId>,
    ) -> impl Iterator<Item = (ContractId, ContractState<Outpoint>)> + use<'_, W, S, P, X> {
        self.mound
            .contracts_mut()
            .filter(move |(id, _)| contract_id.is_none() || Some(*id) == contract_id)
            .map(|(id, stockpile)| (id, stockpile.state().map(|seal| seal.primary)))
    }

    fn noise_engine(&self) -> Sha256 {
        let noise_seed = self.wallet.noise_seed();
        let mut noise_engine = Sha256::new();
        noise_engine.input_raw(noise_seed.as_ref());
        noise_engine
    }

    pub fn fulfill(
        &mut self,
        invoice: RgbInvoice<ContractId>,
        mut coinselect: impl Coinselect,
        // TODO: Consider adding requested amount of sats to the `RgbInvoice`
        giveaway: Option<Sats>,
    ) -> Result<PrefabParams<WoutAssignment>, FulfillError> {
        let contract_id = invoice.scope;

        // Determine method
        let stockpile = self.mound.contract(contract_id);
        let api = &stockpile.stock().articles().schema.default_api;
        let call = invoice
            .call
            .or_else(|| api.default_call().cloned())
            .ok_or(FulfillError::CallStateUnknown)?;
        let state_name = call.destructible.ok_or(FulfillError::StateNameUnknown)?;
        let mut calc = api.calculate(state_name.clone());

        // Do coinselection
        let (_, state) = self
            .state_own(Some(contract_id))
            .next()
            .ok_or(FulfillError::ContractUnavailable(contract_id))?;
        let state = state
            .owned
            .get(&state_name)
            .ok_or(FulfillError::StateUnavailable)?;
        let reading = coinselect
            .coinselect(&invoice.data, calc.as_mut(), state)
            .ok_or(FulfillError::StateInsufficient)?;

        // Add beneficiaries
        let seal = match invoice.auth {
            RgbBeneficiary::Token(auth) => EitherSeal::Token(auth),
            RgbBeneficiary::WitnessOut(wout) => {
                let wout = WoutAssignment {
                    wout,
                    amount: WoutAmount::Fixed(giveaway.ok_or(FulfillError::WoutRequiresGiveaway)?),
                };
                EitherSeal::Alt(wout)
            }
        };
        calc.lessen(invoice.data.clone())?;
        let assignment = Assignment { seal, data: invoice.data };
        let state = NamedState { name: state_name.clone(), state: assignment };
        let mut owned = vec![state];

        // Add change
        let diff = calc.diff()?;
        let change_address = self.wallet.next_address();
        let wout_assign = WoutAssignment {
            wout: WitnessOut::new(change_address.payload, 0),
            amount: WoutAmount::Change,
        };
        let seal = EitherSeal::Alt(wout_assign);
        for data in diff {
            let assignment = Assignment { seal: seal.clone(), data };
            let state = NamedState { name: state_name.clone(), state: assignment };
            owned.push(state);
        }

        // Construct PrefabParams
        Ok(PrefabParams {
            contract_id,
            method: call.method,
            using: none!(),
            global: none!(),
            reading,
            owned,
        })
    }

    /// Creates a single operation basing on the provided construction parameters.
    pub fn prefab(&mut self, params: PrefabParams<Vout>) -> Prefab {
        // convert ConstructParams into CallParams
        let (closes, using) = params
            .using
            .into_iter()
            .map(|used| (used.outpoint, (used.addr, used.val)))
            .unzip();
        let closes = SmallOrdSet::try_from(closes).expect("too many inputs");
        let mut defines = SmallOrdSet::new();

        let mut seals = SmallVec::new();
        let mut noise_engine = self.noise_engine();
        noise_engine.input_raw(params.contract_id.as_slice());
        let owned = params
            .owned
            .into_iter()
            .enumerate()
            .map(|(nonce, assignment)| {
                let auth = match assignment.state.seal {
                    EitherSeal::Alt(vout) => {
                        defines.push(vout).expect("too many seals");
                        let seal =
                            TxoSeal::vout_no_fallback(vout, noise_engine.clone(), nonce as u64);
                        seals.push(seal).expect("too many seals");
                        seal.auth_token()
                    }
                    EitherSeal::Token(auth) => auth,
                };
                let state = DataCell { data: assignment.state.data, auth, lock: None };
                NamedState { name: assignment.name, state }
            })
            .collect();

        let call = CallParams {
            core: CoreParams { method: params.method, global: params.global, owned },
            using,
            reading: params.reading,
        };

        let stockpile = self.mound.contract_mut(params.contract_id);
        let opid = stockpile.stock_mut().call(call);
        let operation = stockpile.stock_mut().operation(opid);
        stockpile.pile_mut().keep_mut().append(opid, &seals);
        debug_assert_eq!(operation.contract_id, params.contract_id);

        Prefab { closes, defines, operation }
    }

    /// Complete creation of a prefabricated operation pack, adding blank operations if necessary.
    ///
    /// # Arguments
    ///
    /// - `items`: a set of instructions to create non-blank operations (potentially under multiple
    ///   contracts);
    /// - `seal`: a single-use seal definition where all blank outputs will be assigned to.
    pub fn bundle(
        &mut self,
        items: impl IntoIterator<Item = PrefabParams<Vout>>,
        change: Vout,
    ) -> PrefabBundle {
        let ops = items.into_iter().map(|params| self.prefab(params));

        let mut outpoints = BTreeSet::<Outpoint>::new();
        let mut contracts = BTreeSet::new();
        let mut prefabs = BTreeSet::new();
        for prefab in ops {
            contracts.insert(prefab.operation.contract_id);
            outpoints.extend(&prefab.closes);
            prefabs.insert(prefab);
        }

        let mut prefab_params = Vec::new();
        let root_noise_engine = self.noise_engine();
        for (contract_id, stockpile) in self
            .mound
            .contracts_mut()
            .filter(|(id, _)| !contracts.contains(id))
        {
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
                            let seal = TxoSeal::no_fallback(
                                *outpoint,
                                noise_engine.clone(),
                                *nonce as u64,
                            );
                            seal.auth_token() == auth
                        })
                        .map(|(_, outpoint)| {
                            let prevout = UsedState { addr, outpoint, val: StrictVal::Unit };
                            (prevout, (name.clone(), val))
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
                for data in calc.diff().expect("non-computable state") {
                    let state = NamedState {
                        name: name.clone(),
                        state: Assignment { seal: EitherSeal::Alt(change), data },
                    };
                    owned.push(state);
                }
            }

            let params = PrefabParams {
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

    /// Include prefab bundle into the mound, creating necessary anchors.
    pub fn include(
        &mut self,
        bundle: &PrefabBundle,
        witness: &Tx,
        mpc: mpc::MerkleBlock,
        dbc: Option<TapretProof>,
        prevouts: &[Outpoint],
    ) -> Result<(), IncludeError> {
        for prefab in bundle {
            let protocol_id = ProtocolId::from(prefab.operation.contract_id.to_byte_array());
            let opid = prefab.operation.opid();
            let mut map = bmap! {};
            for prevout in &prefab.closes {
                let pos = prevouts
                    .iter()
                    .position(|p| p == prevout)
                    .ok_or(IncludeError::MissingPrevout(*prevout))?;
                map.insert(pos as u32, mmb::Message::from_byte_array(opid.to_byte_array()));
            }
            let anchor = Anchor {
                mmb_proof: mmb::BundleProof { map: SmallOrdMap::from_checked(map) },
                mpc_protocol: protocol_id,
                mpc_proof: mpc.to_merkle_proof(protocol_id)?,
                dbc_proof: dbc.clone(),
                fallback_proof: default!(),
            };
            self.mound
                .include(prefab.operation.contract_id, opid, witness, anchor);
        }
        Ok(())
    }

    /// Consume consignment.
    #[allow(clippy::result_large_err)]
    pub fn consume(
        &mut self,
        reader: &mut StrictReader<impl ReadRaw>,
    ) -> Result<(), MoundConsumeError<TxoSeal>> {
        self.mound.consume(reader, |cells| {
            self.wallet
                .resolve_seals(cells.iter().map(|cell| cell.auth))
                .collect()
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum FulfillError {
    /// the wallet doesn't own any state for {0} to fulfill the invoice.
    ContractUnavailable(ContractId),

    /// neither invoice nor contract API contains information about the transfer method.
    CallStateUnknown,

    /// neither invoice nor contract API contains information about the state name.
    StateNameUnknown,

    /// the wallet doesn't own any state in order to fulfill the invoice.
    StateUnavailable,

    /// the state owned by the wallet is insufficient to fulfill the invoice.
    StateInsufficient,

    #[from]
    #[display(inner)]
    StateUncountable(UncountableState),

    /// the invoice asks to create an UTXO for the receiver, but method call doesn't provide
    /// information on how much sats can be put there (`giveaway` parameter).
    WoutRequiresGiveaway,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IncludeError {
    /// prefab bundle references unknown previous output {0}.
    MissingPrevout(Outpoint),

    /// multi-protocol commitment proof is invalid; {0}
    #[from]
    Mpc(mpc::LeafNotKnown),
}

#[cfg(feature = "fs")]
pub mod file {
    use std::fs::File;
    use std::io;
    use std::path::Path;

    use hypersonic::FileSupply;
    use strict_encoding::StreamReader;

    use super::*;
    use crate::mound::file::DirExcavator;
    use crate::FilePile;

    pub type DirBarrow<W> = Barrow<W, FileSupply, FilePile<TxoSeal>, DirExcavator<TxoSeal>>;

    impl<W: WalletProvider> DirBarrow<W> {
        pub fn issue_to_file(
            &mut self,
            params: CreateParams<Outpoint>,
        ) -> Result<ContractId, IssueError> {
            // TODO: check that if the issue belongs to the wallet add it to the unspents
            self.mound
                .issue_to_file(params.transform(self.noise_engine()))
        }

        pub fn consume_from_file(&mut self, path: impl AsRef<Path>) -> io::Result<()> {
            let file = File::open(path)?;
            let mut reader = StrictReader::with(StreamReader::new::<{ usize::MAX }>(file));
            self.consume(&mut reader)
                .unwrap_or_else(|err| panic!("Unable to accept a consignment: {err}"));
            Ok(())
        }
    }

    pub type BpDirMound = Mound<FileSupply, FilePile<TxoSeal>, DirExcavator<TxoSeal>>;
}
