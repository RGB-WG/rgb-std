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

use alloc::collections::btree_set;
use alloc::vec;

use amplify::confinement;
use amplify::confinement::{SmallOrdSet, TinyVec};
use bp::seals::TxoSeal;
use bp::{dbc, Sats, ScriptPubkey, Vout};
use commit_verify::{DigestExt, Sha256};
use invoice::bp::WitnessOut;
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::StrictVal;

use crate::{
    Assignment, CellAddr, ContractId, CreateParams, EitherSeal, MethodName, NamedState, Operation,
    Outpoint, StateAtom,
};

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{wout}/{amount}")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct WoutAssignment {
    pub wout: WitnessOut,
    pub amount: Sats,
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
    pub fn transform<D: dbc::Proof>(
        self,
        noise_engine: Sha256,
        nonce: u64,
    ) -> EitherSeal<TxoSeal<D>> {
        match self {
            EitherSeal::Alt(seal) => {
                EitherSeal::Alt(TxoSeal::no_fallback(seal, noise_engine, nonce))
            }
            EitherSeal::Token(auth) => EitherSeal::Token(auth),
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
