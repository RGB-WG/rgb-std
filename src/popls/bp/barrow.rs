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

use amplify::confinement::{SmallOrdMap, SmallOrdSet, SmallVec};
use amplify::{ByteArray, Bytes32};
use bp::seals::{mmb, Anchor, TxoSeal, TxoSealDef};
use bp::{dbc, Tx, Vout};
use commit_verify::mpc::ProtocolId;
use commit_verify::{mpc, Digest, DigestExt, Sha256};
use hypersonic::aora::Aora;
use hypersonic::{CallParams, Supply};
use invoice::bp::{Address, WitnessOut};
use rgb::SealAuthToken;
use strict_encoding::{ReadRaw, StrictReader};
use strict_types::StrictVal;

use super::{Prefab, PrefabBundle, PrefabParams, UsedState, BP_BLANK_METHOD};
use crate::{
    Assignment, AuthToken, ConsumeError, ContractId, ContractState, CoreParams, CreateParams,
    DataCell, EitherSeal, MethodName, MoundApi, NamedState, Outpoint, Pile, StateCalc, StateName,
    StockpileApi,
};

/// Trait abstracting specific implementation of a bitcoin wallet.
pub trait WalletApi {
    fn noise_seed(&self) -> Bytes32;
    fn has_utxo(&self, outpoint: Outpoint) -> bool;
    fn utxos(&self) -> impl Iterator<Item = Outpoint>;
    fn register_seal(&mut self, seal: TxoSealDef);
    fn resolve_seals(
        &self,
        seals: impl Iterator<Item = AuthToken>,
    ) -> impl Iterator<Item = TxoSealDef>;
    fn next_address(&mut self) -> Address;
}

/// Barrow contains a bunch of RGB contract stockpiles, which are held by a single owner; such that
/// when a new operation under any of the contracts happen it may affect other contracts sharing the
/// same UTXOs.
pub struct Barrow<W: WalletApi, M: MoundApi> {
    pub wallet: W,
    pub mound: M,
}

impl<W: WalletApi, M: MoundApi> Barrow<W, M> {
    pub fn with(wallet: W, mound: M) -> Self { Self { wallet, mound } }

    pub fn unbind(self) -> (W, M) { (self.wallet, self.mound) }

    pub fn issue<D: dbc::Proof, const CAPS: u32>(
        &mut self,
        params: CreateParams<Outpoint>,
        supply: impl Supply<CAPS>,
        pile: impl Pile<Seal = TxoSeal<D>>,
    ) -> ContractId {
        self.mound
            .issue(params.transform(self.noise_engine()), supply, pile)
    }

    pub fn auth_token(&mut self, nonce: u64) -> Option<AuthToken> {
        let outpoint = self.wallet.utxos().next()?;
        let seal = TxoSealDef::no_fallback(outpoint, self.noise_engine(), nonce);
        let auth = seal.auth_token();
        self.wallet.register_seal(seal);
        Some(auth)
    }

    pub fn wout(&mut self, nonce: u64) -> WitnessOut {
        let address = self.wallet.next_address();
        WitnessOut::new(address.payload, nonce)
    }

    pub fn state(
        &mut self,
        contract_id: Option<ContractId>,
    ) -> impl Iterator<Item = (ContractId, ContractState<Outpoint>)> + use<'_, W, M> {
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
    ) -> impl Iterator<Item = (ContractId, ContractState<Outpoint>)> + use<'_, W, M> {
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
                            TxoSealDef::vout_no_fallback(vout, noise_engine.clone(), nonce as u64);
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
        let opid = stockpile.call(call);
        let operation = stockpile.operation(opid);
        stockpile.pile_mut().keep_mut().append(opid, &seals);
        debug_assert_eq!(operation.contract_id, params.contract_id);

        Prefab { closes, defines, operation }
    }

    /// Completes creation of a prefabricated operation pack, adding blank operations if necessary.
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
        for (contract_id, stockpile) in self.mound.contracts_mut() {
            let mut noise_engine = root_noise_engine.clone();
            noise_engine.input_raw(contract_id.as_slice());

            // TODO: Simplify the expression
            // We need to clone here not to conflict with mutable call below
            let owned = stockpile.state().owned.clone();
            let (using, prev): (_, Vec<_>) = owned
                .iter()
                .flat_map(|(name, map)| {
                    map.iter()
                        .map(move |(addr, assign)| (name, *addr, &assign.data))
                })
                .filter_map(|(name, addr, val)| {
                    let auth = stockpile.operation(addr.opid).destructible[addr.pos as usize].auth;
                    outpoints
                        .iter()
                        .copied()
                        .enumerate()
                        .find(|(nonce, outpoint)| {
                            TxoSealDef::no_fallback(*outpoint, noise_engine.clone(), *nonce as u64)
                                .auth_token()
                                == auth
                        })
                        .map(|(_, outpoint)| {
                            let prevout = UsedState { addr, outpoint, val: StrictVal::Unit };
                            (prevout, (name.clone(), val))
                        })
                })
                .unzip();

            let api = &stockpile.schema().default_api;
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

        PrefabBundle::from(SmallOrdSet::try_from(prefabs).expect("too many operations"))
    }

    pub fn attest<D: dbc::Proof>(
        &mut self,
        bundle: &PrefabBundle,
        witness: &Tx,
        mpc: mpc::MerkleBlock,
        dbc: D,
        prevouts: &[Outpoint],
    ) {
        let iter = bundle.iter().map(|prefab| {
            let protocol_id = ProtocolId::from(prefab.operation.contract_id.to_byte_array());
            let opid = prefab.operation.opid();
            let anchor = Anchor {
                mmb_proof: mmb::BundleProof {
                    map: SmallOrdMap::from_iter_checked(prefab.closes.iter().map(|prevout| {
                        let pos = prevouts
                            .iter()
                            .position(|p| p == prevout)
                            .expect("PSBT misses one of operation inputs");
                        (pos as u32, mmb::Message::from_byte_array(opid.to_byte_array()))
                    })),
                },
                mpc_protocol: protocol_id,
                mpc_proof: mpc.to_merkle_proof(protocol_id).expect("Invalid MPC proof"),
                dbc_proof: dbc.clone(),
                fallback_proof: default!(),
            };
            (prefab.operation.contract_id, opid, anchor)
        });
        self.mound.attest(witness, iter);
    }

    #[allow(clippy::result_large_err)]
    pub fn consume(
        &mut self,
        reader: &mut StrictReader<impl ReadRaw>,
    ) -> Result<(), ConsumeError<TxoSealDef>> {
        self.mound.consume(reader, |cells| {
            self.wallet
                .resolve_seals(cells.iter().map(|cell| cell.auth))
                //.map(TxoSeal::<D>::from_definition)
                .collect()
        })
    }
}
