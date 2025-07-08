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

use alloc::collections::btree_map::Entry;
use alloc::collections::{btree_set, BTreeMap, BTreeSet};
use alloc::vec;
use std::collections::HashMap;

use amplify::confinement::{
    Collection, KeyedCollection, NonEmptyVec, SmallOrdMap, SmallOrdSet, U8 as U8MAX,
};
use amplify::{confinement, ByteArray, Bytes32, MultiError, Wrapper};
use bp::dbc::tapret::TapretProof;
pub use bp::seals;
use bp::seals::{mmb, Anchor, Noise, TxoSeal, TxoSealExt, WOutpoint, WTxoSeal};
use bp::{Outpoint, Sats, ScriptPubkey, Tx, Txid, Vout};
use commit_verify::mpc::ProtocolId;
use commit_verify::{mpc, Digest, DigestExt, Sha256, StrictHash};
use hypersonic::{
    AcceptError, AuthToken, CallParams, CellAddr, ContractId, CoreParams, DataCell, MethodName,
    NamedState, Operation, Satisfaction, StateAtom, StateCalc, StateCalcError, StateName,
    StateUnknown, Stock,
};
use invoice::bp::{Address, WitnessOut};
use invoice::{RgbBeneficiary, RgbInvoice};
use rgb::RgbSealDef;
use rgbcore::LIB_NAME_RGB;
use strict_encoding::{ReadRaw, StrictDecode, StrictReader, TypeName};
use strict_types::StrictVal;

use crate::contracts::SyncError;
use crate::{
    Assignment, CodexId, Consensus, ConsumeError, Contract, ContractState, Contracts, CreateParams,
    EitherSeal, Identity, Issuer, IssuerError, OwnedState, Pile, SigBlob, Stockpile, WitnessStatus,
};

/// Trait abstracting a specific implementation of a bitcoin wallet.
pub trait WalletProvider {
    type Error: core::error::Error;

    fn has_utxo(&self, outpoint: Outpoint) -> bool;
    fn utxos(&self) -> impl Iterator<Item = Outpoint>;

    fn update_utxos(&mut self) -> Result<(), Self::Error>;
    #[cfg(feature = "async")]
    async fn update_utxos_async(&mut self) -> Result<(), Self::Error>;

    fn register_seal(&mut self, seal: WTxoSeal);
    fn resolve_seals(
        &self,
        seals: impl Iterator<Item = AuthToken>,
    ) -> impl Iterator<Item = WTxoSeal>;

    fn noise_seed(&self) -> Bytes32;
    fn next_address(&mut self) -> Address;
    fn next_nonce(&mut self) -> u64;

    /// Returns a closure which can retrieve a witness status of an arbitrary transaction id
    /// (including the ones that are not related to the wallet).
    fn txid_resolver(&self) -> impl Fn(Txid) -> Result<WitnessStatus, Self::Error>;

    #[cfg(feature = "async")]
    /// Returns a closure which can retrieve a witness status of an arbitrary transaction id
    /// (including the ones that are not related to the wallet).
    fn txid_resolver_async(
        &self,
    ) -> impl Fn(Txid) -> Box<dyn core::future::Future<Output = Result<WitnessStatus, Self::Error>>>;

    /// Returns the height of the last known block.
    fn last_block_height(&self) -> u64;

    #[cfg(feature = "async")]
    /// Returns the height of the last known block.
    async fn last_block_height_async(&self) -> u64;

    /// Broadcasts the transaction, also updating UTXO set accordingly.
    fn broadcast(&mut self, tx: &Tx, change: Option<(Vout, u32, u32)>) -> Result<(), Self::Error>;

    #[cfg(feature = "async")]
    /// Broadcasts the transaction, also updating UTXO set accordingly.
    async fn broadcast_async(
        &mut self,
        tx: &Tx,
        change: Option<(Vout, u32, u32)>,
    ) -> Result<(), Self::Error>;
}

pub trait Coinselect {
    fn coinselect<'a>(
        &mut self,
        invoiced_state: &StrictVal,
        calc: &mut StateCalc,
        // Sorted vector by values
        owned_state: impl IntoIterator<
            Item = &'a OwnedState<Outpoint>,
            IntoIter: DoubleEndedIterator<Item = &'a OwnedState<Outpoint>>,
        >,
    ) -> Option<Vec<(CellAddr, Outpoint)>>;
}

pub const BP_BLANK_METHOD: &str = "_";

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct PrefabSeal {
    pub vout: Vout,
    pub noise: Option<Noise>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{wout}/{sats}")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct WoutAssignment {
    #[cfg_attr(feature = "serde", serde(with = "serde_with::rust::display_fromstr"))]
    pub wout: WitnessOut,
    pub sats: Sats,
}

impl From<WoutAssignment> for ScriptPubkey {
    fn from(val: WoutAssignment) -> Self { val.script_pubkey() }
}

impl WoutAssignment {
    pub fn script_pubkey(&self) -> ScriptPubkey { self.wout.script_pubkey() }
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
    pub fn transform(self, noise_engine: Sha256, nonce: u64) -> EitherSeal<WTxoSeal> {
        match self {
            EitherSeal::Alt(seal) => {
                EitherSeal::Alt(WTxoSeal::no_fallback(seal, noise_engine, nonce))
            }
            EitherSeal::Token(auth) => EitherSeal::Token(auth),
        }
    }
}

impl CreateParams<Outpoint> {
    pub fn transform(self, mut noise_engine: Sha256) -> CreateParams<WTxoSeal> {
        noise_engine.input_raw(self.issuer.codex_id().as_slice());
        noise_engine.input_raw(&[self.consensus as u8]);
        noise_engine.input_raw(self.method.as_bytes());
        noise_engine.input_raw(self.name.as_bytes());
        noise_engine.input_raw(&self.timestamp.unwrap_or_default().timestamp().to_le_bytes());
        CreateParams {
            issuer: self.issuer,
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

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct UsedState {
    pub addr: CellAddr,
    pub outpoint: Outpoint,
    pub satisfaction: Option<Satisfaction>,
}

pub type PaymentScript = OpRequestSet<Option<WoutAssignment>>;

/// A set of multiple operation requests (see [`OpRequests`]) under single or multiple contracts.
#[derive(Wrapper, WrapperMut, Clone, Debug, From)]
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
pub struct OpRequestSet<T>(NonEmptyVec<OpRequest<T>, U8MAX>);

impl<T> IntoIterator for OpRequestSet<T> {
    type Item = OpRequest<T>;
    type IntoIter = vec::IntoIter<OpRequest<T>>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

impl<T> OpRequestSet<T> {
    pub fn with(request: OpRequest<T>) -> Self { Self(NonEmptyVec::with(request)) }
}

impl OpRequestSet<Option<WoutAssignment>> {
    pub fn resolve_seals(
        self,
        resolver: impl Fn(&ScriptPubkey) -> Option<Vout>,
        change: Option<Vout>,
    ) -> Result<OpRequestSet<PrefabSeal>, UnresolvedSeal> {
        let mut items = Vec::with_capacity(self.0.len());
        for request in self.0 {
            let mut owned = Vec::with_capacity(request.owned.len());
            for assignment in request.owned {
                let seal = match assignment.state.seal {
                    EitherSeal::Alt(Some(seal)) => {
                        let spk = seal.script_pubkey();
                        let vout = resolver(&spk).ok_or(UnresolvedSeal::Spk(spk))?;
                        let seal = PrefabSeal { vout, noise: Some(seal.wout.noise()) };
                        EitherSeal::Alt(seal)
                    }
                    EitherSeal::Alt(None) => {
                        let change = change.ok_or(UnresolvedSeal::Change)?;
                        let seal = PrefabSeal { vout: change, noise: None };
                        EitherSeal::Alt(seal)
                    }
                    EitherSeal::Token(auth) => EitherSeal::Token(auth),
                };
                owned.push(NamedState {
                    name: assignment.name,
                    state: Assignment { seal, data: assignment.state.data },
                });
            }
            items.push(OpRequest {
                contract_id: request.contract_id,
                method: request.method,
                reading: request.reading,
                using: request.using,
                global: request.global,
                owned,
            });
        }
        Ok(OpRequestSet(NonEmptyVec::from_iter_checked(items)))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum UnresolvedSeal {
    /// unable to resolve seal witness output seal definition for script pubkey {0:x}.
    Spk(ScriptPubkey),

    /// seal requires assignment to a change output, but the transaction lacks change.
    Change,
}

/// Request to construct RGB operations.
///
/// NB: [`OpRequest`] must contain pre-computed information about the change; otherwise the
/// excessive state will be lost. Change information allows wallet to construct complex transactions
/// with multiple changes etc. Use [`OpRequest::check`] method to verify that request includes
/// necessary change.
///
/// Differs from [`CallParams`] in the fact that it uses [`EitherSeal`]s instead of
/// [`hypersonic::AuthTokens`] for output definitions.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound = "T: serde::Serialize + for<'d> serde::Deserialize<'d>"
    )
)]
pub struct OpRequest<T> {
    pub contract_id: ContractId,
    pub method: MethodName,
    pub reading: Vec<CellAddr>,
    pub using: Vec<UsedState>,
    pub global: Vec<NamedState<StateAtom>>,
    pub owned: Vec<NamedState<Assignment<EitherSeal<T>>>>,
}

impl OpRequest<Option<WoutAssignment>> {
    pub fn resolve_seal(
        &self,
        wout: WitnessOut,
        resolver: impl Fn(&ScriptPubkey) -> Option<Vout>,
    ) -> Option<WTxoSeal> {
        for assignment in &self.owned {
            if let EitherSeal::Alt(Some(assignment)) = &assignment.state.seal {
                if assignment.wout == wout {
                    let spk = assignment.script_pubkey();
                    let vout = resolver(&spk)?;
                    let primary = WOutpoint::Wout(vout);
                    let seal = WTxoSeal { primary, secondary: TxoSealExt::Noise(wout.noise()) };
                    return Some(seal);
                }
            }
        }
        None
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum UnmatchedState {
    /// neither invoice nor contract API contains information about the state name.
    #[from(StateUnknown)]
    StateNameUnknown,

    #[from]
    #[display(inner)]
    StateCalc(StateCalcError),

    /// the operation request doesn't re-assign all of `{0}` state, leading to the state loss.
    NotEnoughChange(StateName),
}

/// Prefabricated operation, which includes information on the contract id and closed seals
/// (previous outputs).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
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
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct PrefabBundle(SmallOrdSet<Prefab>);

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

/// RGB wallet contains a bunch of RGB contracts, which are held by a single owner (a wallet);
/// such that when a new operation under any of the contracts happens, it may affect other contracts
/// sharing the same UTXOs.
pub struct RgbWallet<
    W,
    Sp,
    // TODO: Replace with IndexMap
    S = HashMap<CodexId, Issuer>,
    C = HashMap<ContractId, Contract<<Sp as Stockpile>::Stock, <Sp as Stockpile>::Pile>>,
> where
    W: WalletProvider,
    Sp: Stockpile,
    Sp::Pile: Pile<Seal = TxoSeal>,
    S: KeyedCollection<Key = CodexId, Value = Issuer>,
    C: KeyedCollection<Key = ContractId, Value = Contract<Sp::Stock, Sp::Pile>>,
{
    pub wallet: W,
    pub contracts: Contracts<Sp, S, C>,
}

impl<W, Sp, S, C> RgbWallet<W, Sp, S, C>
where
    W: WalletProvider,
    Sp: Stockpile,
    Sp::Pile: Pile<Seal = TxoSeal>,
    S: KeyedCollection<Key = CodexId, Value = Issuer>,
    C: KeyedCollection<Key = ContractId, Value = Contract<Sp::Stock, Sp::Pile>>,
{
    pub fn with_components(wallet: W, contracts: Contracts<Sp, S, C>) -> Self {
        Self { wallet, contracts }
    }

    pub fn into_components(self) -> (W, Contracts<Sp, S, C>) { (self.wallet, self.contracts) }

    pub fn issue(
        &mut self,
        params: CreateParams<Outpoint>,
    ) -> Result<
        ContractId,
        MultiError<IssuerError, <Sp::Stock as Stock>::Error, <Sp::Pile as Pile>::Error>,
    > {
        self.contracts.issue(params.transform(self.noise_engine()))
    }

    pub fn auth_token(&mut self, nonce: Option<u64>) -> Option<AuthToken> {
        let outpoint = self.wallet.utxos().next()?;
        let nonce = nonce.unwrap_or_else(|| self.wallet.next_nonce());
        let seal = WTxoSeal::no_fallback(outpoint, self.noise_engine(), nonce);
        let auth = seal.auth_token();
        self.wallet.register_seal(seal);
        Some(auth)
    }

    pub fn wout(&mut self, nonce: Option<u64>) -> WitnessOut {
        let address = self.wallet.next_address();
        let nonce = nonce.unwrap_or_else(|| self.wallet.next_nonce());
        WitnessOut::new(address.payload, nonce)
    }

    pub fn state_own(&self, contract_id: ContractId) -> ContractState<Outpoint> {
        self.contracts
            .contract_state(contract_id)
            .clone()
            .filter_map(
                |seal| {
                    if self.wallet.has_utxo(seal.primary) {
                        Some(seal.primary)
                    } else {
                        None
                    }
                },
            )
    }

    pub fn state_all(&self, contract_id: ContractId) -> ContractState<<Sp::Pile as Pile>::Seal> {
        self.contracts.contract_state(contract_id)
    }

    fn noise_engine(&self) -> Sha256 {
        let noise_seed = self.wallet.noise_seed();
        let mut noise_engine = Sha256::new();
        noise_engine.input_raw(noise_seed.as_ref());
        noise_engine
    }

    pub fn fulfill(
        &mut self,
        invoice: &RgbInvoice<ContractId>,
        mut coinselect: impl Coinselect,
        giveaway: Option<Sats>,
    ) -> Result<OpRequest<Option<WoutAssignment>>, FulfillError> {
        let contract_id = invoice.scope;

        // Determine method
        let articles = self.contracts.contract_articles(contract_id);
        let api = articles.default_api();
        let call = invoice
            .call
            .as_ref()
            .or(api.default_call.as_ref())
            .ok_or(FulfillError::CallStateUnknown)?;
        let method = call.method.clone();
        let state_name = call.owned.clone().ok_or(FulfillError::StateNameUnknown)?;
        let mut calc = api.calculate(state_name.clone())?;

        let value = invoice.data.as_ref().ok_or(FulfillError::ValueMissed)?;

        // Do coinselection
        let state = self.state_own(contract_id);
        let state = state
            .owned
            .get(&state_name)
            .ok_or(FulfillError::StateUnavailable)?;
        // NB: we do state accumulation with `calc` inside coinselect
        let mut using = coinselect
            .coinselect(value, &mut calc, state)
            .ok_or(FulfillError::StateInsufficient)?;
        // Now we need to include all other allocations under the same contract that use the
        // selected UTXOs.
        let (addrs, outpoints) = using
            .iter()
            .copied()
            .unzip::<_, _, BTreeSet<_>, BTreeSet<_>>();
        using.extend(
            state
                .iter()
                .filter(|s| outpoints.contains(&s.assignment.seal) && !addrs.contains(&s.addr))
                .filter_map(|s| {
                    calc.accumulate(&s.assignment.data).ok()?;
                    Some((s.addr, s.assignment.seal))
                }),
        );
        let using = using
            .into_iter()
            .map(|(addr, outpoint)| UsedState { addr, outpoint, satisfaction: None })
            .collect();

        // Add beneficiaries
        let seal = match invoice.auth {
            RgbBeneficiary::Token(auth) => EitherSeal::Token(auth),
            RgbBeneficiary::WitnessOut(wout) => {
                let wout = WoutAssignment {
                    wout,
                    sats: giveaway.ok_or(FulfillError::WoutRequiresGiveaway)?,
                };
                EitherSeal::Alt(Some(wout))
            }
        };
        calc.lessen(value)?;
        let assignment = Assignment { seal, data: value.clone() };
        let state = NamedState { name: state_name.clone(), state: assignment };
        let mut owned = vec![state];

        // Add change
        let diff = calc.diff()?;
        let seal = EitherSeal::Alt(None);
        for data in diff {
            let assignment = Assignment { seal: seal.clone(), data };
            let state = NamedState { name: state_name.clone(), state: assignment };
            owned.push(state);
        }

        // Construct operation request
        Ok(OpRequest {
            contract_id,
            method,
            reading: none!(),
            global: none!(),
            using,
            owned,
        })
    }

    /// Check whether all state used in a request is properly re-distributed to new owners, and
    /// non-distributed state is used in the change.
    pub fn check_request<T>(&self, request: &OpRequest<T>) -> Result<(), UnmatchedState> {
        let contract_id = request.contract_id;
        let state = self.contracts.contract_state(contract_id);
        let articles = self.contracts.contract_articles(contract_id);
        let api = articles.default_api();
        let mut calcs = BTreeMap::new();

        for inp in &request.using {
            let (state_name, val) = state
                .owned
                .iter()
                .find_map(|(state_name, map)| {
                    map.iter()
                        .find(|owned| owned.addr == inp.addr)
                        .map(|owned| (state_name, owned))
                })
                .expect("unknown state included in the contract stock");
            let calc = match calcs.entry(state_name.clone()) {
                Entry::Vacant(entry) => {
                    let calc = api.calculate(state_name.clone())?;
                    entry.insert(calc)
                }
                Entry::Occupied(entry) => entry.into_mut(),
            };
            calc.accumulate(&val.assignment.data)?;
        }
        for out in &request.owned {
            let calc = match calcs.entry(out.name.clone()) {
                Entry::Vacant(entry) => {
                    let calc = api.calculate(out.name.clone())?;
                    entry.insert(calc)
                }
                Entry::Occupied(entry) => entry.into_mut(),
            };
            calc.lessen(&out.state.data)?;
        }
        for (state_name, calc) in calcs {
            if !calc.diff()?.is_empty() {
                return Err(UnmatchedState::NotEnoughChange(state_name.clone()));
            }
        }
        Ok(())
    }

    /// Creates a single operation basing on the provided construction parameters.
    pub fn prefab(
        &mut self,
        request: OpRequest<PrefabSeal>,
    ) -> Result<Prefab, MultiError<PrefabError, <Sp::Stock as Stock>::Error>> {
        self.check_request(&request).map_err(MultiError::from_a)?;

        // convert ConstructParams into CallParams
        let (closes, using) = request
            .using
            .into_iter()
            .map(|used| (used.outpoint, (used.addr, used.satisfaction)))
            .unzip();
        let closes =
            SmallOrdSet::try_from(closes).map_err(|_| MultiError::A(PrefabError::TooManyInputs))?;
        let mut defines = SmallOrdSet::new();

        let mut seals = SmallOrdMap::new();
        let mut noise_engine = self.noise_engine();
        noise_engine.input_raw(request.contract_id.as_slice());

        let mut owned = Vec::with_capacity(request.owned.len());
        for (opout_no, assignment) in request.owned.into_iter().enumerate() {
            let auth = match assignment.state.seal {
                EitherSeal::Alt(seal) => {
                    defines
                        .push(seal.vout)
                        .map_err(|_| MultiError::A(PrefabError::TooManyOutputs))?;
                    let primary = WOutpoint::Wout(seal.vout);
                    let noise = seal.noise.unwrap_or_else(|| {
                        Noise::with(primary, noise_engine.clone(), opout_no as u64)
                    });
                    let seal = WTxoSeal { primary, secondary: TxoSealExt::Noise(noise) };
                    seals.insert(opout_no as u16, seal).expect("checked above");
                    seal.auth_token()
                }
                EitherSeal::Token(auth) => auth,
            };
            let state = DataCell { data: assignment.state.data, auth, lock: None };
            let named_state = NamedState { name: assignment.name, state };
            owned.push(named_state);
        }

        let call = CallParams {
            core: CoreParams { method: request.method, global: request.global, owned },
            using,
            reading: request.reading,
        };

        let operation = self
            .contracts
            .contract_call(request.contract_id, call, seals)
            .map_err(MultiError::from_other_a)?;

        Ok(Prefab { closes, defines, operation })
    }

    /// Complete creation of a prefabricated operation bundle from operation requests, adding blank
    /// operations if necessary. Operation requests can be multiple.
    ///
    /// A set of operations is either a collection of them or an [`OpRequestSet`] - any structure
    /// that implements the [`IntoIterator`] trait.
    ///
    /// # Arguments
    ///
    /// - `requests`: a set of instructions to create non-blank operations (potentially under
    ///   multiple contracts);
    /// - `seal`: a single-use seal definition where all blank outputs will be assigned to.
    pub fn bundle(
        &mut self,
        requests: impl IntoIterator<Item = OpRequest<PrefabSeal>>,
        change: Option<Vout>,
    ) -> Result<PrefabBundle, MultiError<BundleError, <Sp::Stock as Stock>::Error>> {
        let ops = requests.into_iter().map(|params| self.prefab(params));

        let mut outpoints = BTreeSet::<Outpoint>::new();
        let mut contracts = BTreeSet::new();
        let mut prefabs = BTreeSet::new();
        for prefab in ops {
            let prefab = prefab.map_err(MultiError::from_other_a)?;
            contracts.insert(prefab.operation.contract_id);
            outpoints.extend(&prefab.closes);
            prefabs.insert(prefab);
        }

        // Constructing blank operation requests
        let mut blank_requests = Vec::new();
        let root_noise_engine = self.noise_engine();
        for contract_id in self.contracts.contract_ids() {
            if contracts.contains(&contract_id) {
                continue;
            }
            // We need to clone here not to conflict with mutable calls below
            let owned = self.contracts.contract_state(contract_id).owned.clone();
            let (using, prev): (Vec<_>, Vec<_>) = owned
                .iter()
                .flat_map(|(name, map)| map.iter().map(move |owned| (name, owned)))
                .filter_map(|(name, owned)| {
                    let outpoint = owned.assignment.seal.primary;
                    if !outpoints.contains(&outpoint) {
                        return None;
                    }
                    let prevout = UsedState { addr: owned.addr, outpoint, satisfaction: None };
                    Some((prevout, (name.clone(), owned)))
                })
                .unzip();

            if using.is_empty() {
                continue;
            };

            let articles = self.contracts.contract_articles(contract_id);
            let api = articles.default_api();
            let mut calcs = BTreeMap::<StateName, StateCalc>::new();
            for (name, state) in prev {
                let calc = match calcs.entry(name.clone()) {
                    Entry::Vacant(entry) => {
                        let calc = api.calculate(name).map_err(MultiError::from_a)?;
                        entry.insert(calc)
                    }
                    Entry::Occupied(entry) => entry.into_mut(),
                };
                calc.accumulate(&state.assignment.data)
                    .map_err(MultiError::from_a)?;
            }

            let mut owned = Vec::new();
            let mut nonce = 0;
            let mut noise_engine = root_noise_engine.clone();
            noise_engine.input_raw(contract_id.as_slice());
            for (name, calc) in calcs {
                for data in calc.diff().map_err(MultiError::from_a)? {
                    let vout = change.ok_or(MultiError::A(BundleError::ChangeRequired))?;
                    let noise =
                        Some(Noise::with(WOutpoint::Wout(vout), noise_engine.clone(), nonce));
                    let change = PrefabSeal { vout, noise };
                    nonce += 1;
                    let state = NamedState {
                        name: name.clone(),
                        state: Assignment { seal: EitherSeal::Alt(change), data },
                    };
                    owned.push(state);
                }
            }

            let params = OpRequest {
                contract_id,
                method: MethodName::from(BP_BLANK_METHOD),
                global: none!(),
                reading: none!(),
                using,
                owned,
            };
            blank_requests.push(params);
        }

        for request in blank_requests {
            let prefab = self.prefab(request).map_err(|err| match err {
                MultiError::A(e) => MultiError::A(BundleError::Blank(e)),
                MultiError::B(e) => MultiError::B(e),
                MultiError::C(_) => unreachable!(),
            })?;
            prefabs.push(prefab);
        }

        Ok(PrefabBundle(
            SmallOrdSet::try_from(prefabs)
                .map_err(|_| MultiError::A(BundleError::TooManyBlanks))?,
        ))
    }

    /// Include a prefab bundle, creating the necessary anchors on the fly.
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
            self.contracts
                .include(prefab.operation.contract_id, opid, witness, anchor);
        }
        Ok(())
    }

    /// Consume consignment.
    ///
    /// The method:
    /// - validates the consignment;
    /// - resolves auth tokens into seal definitions known to the current wallet (i.e., coming from
    ///   the invoices produced by the wallet);
    /// - checks the signature of the issuer over the contract articles;
    ///
    /// # Arguments
    ///
    /// - `allow_unknown`: allows importing a contract which was not known to the system;
    /// - `reader`: the input stream;
    /// - `sig_validator`: a validator for the signature of the issuer over the contract articles.
    #[allow(clippy::result_large_err)]
    pub fn consume<E>(
        &mut self,
        allow_unknown: bool,
        reader: &mut StrictReader<impl ReadRaw>,
        sig_validator: impl FnOnce(StrictHash, &Identity, &SigBlob) -> Result<(), E>,
    ) -> Result<
        (),
        MultiError<ConsumeError<WTxoSeal>, <Sp::Stock as Stock>::Error, <Sp::Pile as Pile>::Error>,
    >
    where
        <Sp::Pile as Pile>::Conf: From<<Sp::Stock as Stock>::Conf>,
    {
        let seal_resolver = |op: &Operation| {
            self.wallet
                .resolve_seals(op.destructible_out.iter().map(|cell| cell.auth))
                .map(|seal| {
                    let auth = seal.auth_token();
                    let op_out =
                        op.destructible_out
                            .iter()
                            .position(|cell| cell.auth == auth)
                            .expect("invalid wallet implementation") as u16;
                    (op_out, seal)
                })
                .collect()
        };
        self.contracts
            .consume(allow_unknown, reader, seal_resolver, sig_validator)
    }

    /// Update a wallet UTXO set and the status of all witnesses and single-use seal
    /// definitions.
    ///
    /// Applies rollbacks or forwards if required and recomputes the state of the affected
    /// contracts.
    pub fn update(
        &mut self,
        min_conformations: u32,
    ) -> Result<(), MultiError<SyncError<W::Error>, <Sp::Stock as Stock>::Error>> {
        self.wallet
            .update_utxos()
            .map_err(SyncError::Wallet)
            .map_err(MultiError::from_a)?;
        let last_height = self.wallet.last_block_height();
        self.contracts
            .update_witnesses(self.wallet.txid_resolver(), last_height, min_conformations)
            .map_err(MultiError::from_other_a)
    }

    #[cfg(feature = "async")]
    /// Update a wallet UTXO set and the status of all witnesses and single-use seal
    /// definitions.
    ///
    /// Applies rollbacks or forwards if required and recomputes the state of the affected
    /// contracts.
    pub async fn update_async(
        &mut self,
        min_conformations: u32,
    ) -> Result<(), MultiError<SyncError<W::Error>, <Sp::Stock as Stock>::Error>>
    where
        Sp::Stock: 'static,
        Sp::Pile: 'static,
    {
        self.wallet
            .update_utxos_async()
            .await
            .map_err(SyncError::Wallet)
            .map_err(MultiError::from_a)?;
        let last_height = self.wallet.last_block_height_async().await;
        // TODO: Find a way to use an async version here
        self.contracts
            .update_witnesses(self.wallet.txid_resolver(), last_height, min_conformations)
            .map_err(MultiError::from_other_a)
    }
}

impl CreateParams<Outpoint> {
    pub fn new_bitcoin_testnet(codex_id: CodexId, name: impl Into<TypeName>) -> Self {
        Self::new_testnet(codex_id, Consensus::Bitcoin, name)
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum PrefabError {
    /// operation request contains too many inputs (maximum number of inputs is 64k).
    TooManyInputs,

    /// operation request contains too many outputs (maximum number of outputs is 64k).
    TooManyOutputs,

    #[from]
    #[display(inner)]
    UnmatchedState(UnmatchedState),

    #[from]
    #[display(inner)]
    Accept(AcceptError),
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BundleError {
    #[from]
    #[display(inner)]
    Prefab(PrefabError),

    /// blank {0}
    Blank(PrefabError),

    /// the requested set of operations requires creation of blank operations for other contracts,
    /// which in turn require transaction to contain a change output.
    ChangeRequired,

    /// neither invoice nor contract API contains information about the state name.
    #[from(StateUnknown)]
    StateNameUnknown,

    #[from]
    #[display(inner)]
    StateCalc(StateCalcError),

    /// one or multiple outputs used in operation requests contain too many contracts; it is
    /// impossible to create a bundle with more than 64k of operations.
    TooManyBlanks,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum FulfillError {
    /// neither invoice nor contract API contains information about the transfer method.
    CallStateUnknown,

    /// neither invoice nor contract API contains information about the state name.
    #[from(StateUnknown)]
    StateNameUnknown,

    /// the wallet doesn't own any state to fulfill the invoice.
    StateUnavailable,

    /// the state owned by the wallet is not enough to fulfill the invoice.
    StateInsufficient,

    #[from]
    #[display(inner)]
    StateCalc(StateCalcError),

    /// the invoice asks to create an UTXO for the receiver, but method call doesn't provide
    /// information on how many sats can be put there (`giveaway` argument in `Barrow::fulfill`
    /// call must not be set to None).
    WoutRequiresGiveaway,

    /// the invoice misses the value, and the method call also doesn't provide one
    ValueMissed,
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

#[cfg(feature = "binfile")]
mod _fs {
    use std::io;
    use std::path::Path;

    use amplify::confinement::U24 as U24MAX;
    use binfile::BinFile;
    use commit_verify::StrictHash;
    use strict_encoding::{DecodeError, StreamReader, StreamWriter, StrictEncode};

    use super::*;
    use crate::{Identity, SigBlob, CONSIGN_MAGIC_NUMBER, CONSIGN_VERSION};

    /// The magic number used in storing issuer as a binary file.
    pub const PREFAB_MAGIC_NUMBER: u64 = u64::from_be_bytes(*b"PREFABND");
    /// The issuer encoding version used in storing issuer as a binary file.
    pub const PREFAB_VERSION: u16 = 0;

    impl<W, Sp, S, C> RgbWallet<W, Sp, S, C>
    where
        W: WalletProvider,
        Sp: Stockpile,
        Sp::Pile: Pile<Seal = TxoSeal>,
        S: KeyedCollection<Key = CodexId, Value = Issuer>,
        C: KeyedCollection<Key = ContractId, Value = Contract<Sp::Stock, Sp::Pile>>,
    {
        #[allow(clippy::result_large_err)]
        pub fn consume_from_file<E>(
            &mut self,
            allow_unknown: bool,
            path: impl AsRef<Path>,
            sig_validator: impl FnOnce(StrictHash, &Identity, &SigBlob) -> Result<(), E>,
        ) -> Result<
            (),
            MultiError<
                ConsumeError<WTxoSeal>,
                <Sp::Stock as Stock>::Error,
                <Sp::Pile as Pile>::Error,
            >,
        >
        where
            <Sp::Pile as Pile>::Conf: From<<Sp::Stock as Stock>::Conf>,
        {
            let file = BinFile::<CONSIGN_MAGIC_NUMBER, CONSIGN_VERSION>::open(path)
                .map_err(MultiError::from_a)?;
            let mut reader = StrictReader::with(StreamReader::new::<{ usize::MAX }>(file));
            self.consume(allow_unknown, &mut reader, sig_validator)
        }
    }

    impl PrefabBundle {
        pub fn load(path: impl AsRef<Path>) -> Result<Self, DecodeError> {
            let file = BinFile::<PREFAB_MAGIC_NUMBER, PREFAB_VERSION>::open(path)?;
            let reader = StreamReader::new::<U24MAX>(file);
            Self::strict_read(reader)
            // We do not check for the end of file to allow backwards-compatible extensions
        }

        pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
            let file = BinFile::<PREFAB_MAGIC_NUMBER, PREFAB_VERSION>::create_new(path)?;
            let writer = StreamWriter::new::<U24MAX>(file);
            self.strict_write(writer)
        }
    }
}
