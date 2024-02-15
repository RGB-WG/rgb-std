// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![doc = include_str!("seals.md")]

use std::collections::{btree_set, BTreeSet};

use amplify::confinement::{Confined, U16};
use bp::seals::txout::{BlindSeal, CloseMethod, SealTxid};
use bp::secp256k1::rand::{thread_rng, RngCore};
use bp::Vout;
use commit_verify::Conceal;
use rgb::{GraphSeal, Layer1, SecretSeal, TxoSeal, XChain};
use strict_types::StrictDumb;

use crate::LIB_NAME_RGB_STD;

/// Seal definition which re-uses witness transaction id of some other seal,
/// which is not known at the moment of seal construction. Thus, the definition
/// has only information about output number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct VoutSeal {
    /// Commitment to the specific seal close method [`CloseMethod`] which must
    /// be used to close this seal.
    pub method: CloseMethod,

    /// Tx output number, which should be always known.
    pub vout: Vout,

    /// Blinding factor providing confidentiality of the seal definition.
    /// Prevents rainbow table bruteforce attack based on the existing
    /// blockchain txid set.
    pub blinding: u64,
}

impl VoutSeal {
    /// Creates new seal definition for the provided output number and seal
    /// closing method. Uses `thread_rng` to initialize blinding factor.
    #[inline]
    pub fn new(method: CloseMethod, vout: impl Into<Vout>) -> Self {
        VoutSeal::with(method, vout, thread_rng().next_u64())
    }

    /// Creates new opret-seal seal definition for the provided output number
    /// and seal closing method. Uses `thread_rng` to initialize blinding
    /// factor.
    #[inline]
    pub fn new_opret(vout: impl Into<Vout>) -> Self { VoutSeal::new(CloseMethod::OpretFirst, vout) }

    /// Creates new tapret-seal seal definition for the provided output number
    /// and seal closing method. Uses `thread_rng` to initialize blinding
    /// factor.
    #[inline]
    pub fn new_tapret(vout: impl Into<Vout>) -> Self {
        VoutSeal::new(CloseMethod::TapretFirst, vout)
    }

    /// Reconstructs previously defined opret seal given an output number and a
    /// previously generated blinding factor.
    #[inline]
    pub fn with_opret(vout: impl Into<Vout>, blinding: u64) -> Self {
        VoutSeal::with(CloseMethod::OpretFirst, vout, blinding)
    }

    /// Reconstructs previously defined tapret seal given an output number and a
    /// previously generated blinding factor.
    #[inline]
    pub fn with_tapret(vout: impl Into<Vout>, blinding: u64) -> Self {
        VoutSeal::with(CloseMethod::TapretFirst, vout, blinding)
    }

    /// Reconstructs previously defined seal given method, an output number and
    /// a previously generated blinding factor.
    #[inline]
    pub fn with(method: CloseMethod, vout: impl Into<Vout>, blinding: u64) -> Self {
        VoutSeal {
            method,
            vout: vout.into(),
            blinding,
        }
    }
}

impl From<VoutSeal> for GraphSeal {
    fn from(seal: VoutSeal) -> Self {
        Self::with_blinded_vout(seal.method, seal.vout, seal.blinding)
    }
}

/// Seal endpoint is a confidential seal which may be linked to the witness
/// transaction, but does not contain information about its id.
///
/// Seal endpoint can be either a pointer to the output in the witness
/// transaction, plus blinding factor value, or a confidential seal
/// [`SecretSeal`] value pointing some external unknown transaction
/// output
///
/// Seal endpoint is required in situations where sender assigns state to the
/// witness transaction output on behalf of receiver
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom, dumb = Self::ConcealedUtxo(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum TerminalSeal {
    /// External transaction output in concealed form (see [`SecretSeal`])
    #[from]
    #[strict_type(tag = 0)]
    ConcealedUtxo(SecretSeal),

    /// Seal contained within the witness transaction
    #[from]
    #[strict_type(tag = 1)]
    WitnessVout(VoutSeal),
}

impl TerminalSeal {
    /// Constructs [`TerminalSeal`] for the witness transaction. Uses
    /// `thread_rng` to initialize blinding factor.
    pub fn new_vout(method: CloseMethod, vout: impl Into<Vout>) -> TerminalSeal {
        TerminalSeal::WitnessVout(VoutSeal::new(method, vout))
    }

    pub fn secret_seal(&self) -> Option<SecretSeal> {
        match self {
            TerminalSeal::ConcealedUtxo(seal) => Some(*seal),
            TerminalSeal::WitnessVout(_) => None,
        }
    }
}

impl Conceal for TerminalSeal {
    type Concealed = SecretSeal;

    fn conceal(&self) -> Self::Concealed {
        match *self {
            TerminalSeal::ConcealedUtxo(hash) => hash,
            TerminalSeal::WitnessVout(seal) => GraphSeal::from(seal).conceal(),
        }
    }
}

/// Seal used by operation builder which can be either revealed or concealed.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
pub enum BuilderSeal<Seal: TxoSeal + Ord> {
    Revealed(XChain<Seal>),
    #[from]
    Concealed(XChain<SecretSeal>),
}

impl<Id: SealTxid> From<XChain<BlindSeal<Id>>> for BuilderSeal<BlindSeal<Id>> {
    fn from(seal: XChain<BlindSeal<Id>>) -> Self { BuilderSeal::Revealed(seal) }
}

impl<Seal: TxoSeal + Ord> BuilderSeal<Seal> {
    pub fn layer1(&self) -> Layer1 {
        match self {
            BuilderSeal::Revealed(x) => x.layer1(),
            BuilderSeal::Concealed(x) => x.layer1(),
        }
    }
}

/// Wrapper type for secret seals
#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SecretSealSet(Confined<BTreeSet<SecretSeal>, 1, U16>);

impl StrictDumb for SecretSealSet {
    fn strict_dumb() -> Self { Self(confined_bset!(strict_dumb!())) }
}

impl SecretSealSet {
    pub fn with(seal: SecretSeal) -> Self { SecretSealSet(Confined::with(seal)) }
}

impl IntoIterator for SecretSealSet {
    type Item = SecretSeal;
    type IntoIter = btree_set::IntoIter<SecretSeal>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}
