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

use std::cmp::Ordering;
use std::vec;

use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::dbc::Anchor;
use bp::{Tx, Txid};
use commit_verify::{mpc, CommitId, ReservedBytes};
use rgb::{
    AnchorSet, BundleDisclosure, DiscloseHash, Operation, Transition, TransitionBundle, XChain,
    XWitnessId,
};
use strict_encoding::StrictDumb;

use crate::accessors::{BundleExt, MergeReveal, MergeRevealError, RevealError};
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SealWitness {
    pub public: XPubWitness,
    pub anchor: AnchorSet<mpc::MerkleBlock>,
}

impl SealWitness {
    pub fn new(witness_id: XWitnessId, anchor: AnchorSet<mpc::MerkleBlock>) -> Self {
        SealWitness {
            public: witness_id.map(PubWitness::new),
            anchor,
        }
    }

    pub fn witness_id(&self) -> XWitnessId { self.public.to_witness_id() }
}

pub type XPubWitness = XChain<PubWitness>;

pub trait ToWitnessId {
    fn to_witness_id(&self) -> XWitnessId;
}

impl ToWitnessId for XPubWitness {
    fn to_witness_id(&self) -> XWitnessId { self.map_ref(|w| w.txid) }
}

impl MergeReveal for XPubWitness {
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        match (self, other) {
            (XChain::Bitcoin(one), XChain::Bitcoin(two)) => {
                one.merge_reveal(two).map(XChain::Bitcoin)
            }
            (XChain::Liquid(one), XChain::Liquid(two)) => one.merge_reveal(two).map(XChain::Liquid),
            (XChain::Bitcoin(bitcoin), XChain::Liquid(liquid)) |
            (XChain::Liquid(liquid), XChain::Bitcoin(bitcoin)) => {
                Err(MergeRevealError::ChainMismatch {
                    bitcoin: bitcoin.txid,
                    liquid: liquid.txid,
                })
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct PubWitness {
    pub txid: Txid,
    pub tx: Option<Tx>,
    pub spv: ReservedBytes<1>,
}

impl PartialEq for PubWitness {
    fn eq(&self, other: &Self) -> bool { self.txid == other.txid }
}

impl Ord for PubWitness {
    fn cmp(&self, other: &Self) -> Ordering { self.txid.cmp(&other.txid) }
}

impl PartialOrd for PubWitness {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl PubWitness {
    pub fn new(txid: Txid) -> Self {
        PubWitness {
            txid,
            tx: None,
            spv: none!(),
        }
    }
}

impl MergeReveal for PubWitness {
    fn merge_reveal(mut self, other: Self) -> Result<Self, MergeRevealError> {
        if self.txid != other.txid {
            return Err(MergeRevealError::TxidMismatch(self.txid, other.txid));
        }
        self.tx = self.tx.or(other.tx);
        // TODO: process SPV
        Ok(self)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = DiscloseHash)]
pub struct BundledWitnessDisclosure {
    pub pub_witness: XPubWitness,
    pub anchors: AnchorSet,
    pub bundle1: BundleDisclosure,
    pub bundle2: Option<BundleDisclosure>,
}

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct BundledWitness<P: mpc::Proof + StrictDumb = mpc::MerkleProof> {
    pub pub_witness: XPubWitness,
    pub anchored_bundles: AnchoredBundles<P>,
}

impl<P: mpc::Proof + StrictDumb> PartialEq for BundledWitness<P> {
    fn eq(&self, other: &Self) -> bool { self.pub_witness == other.pub_witness }
}

impl<P: mpc::Proof + StrictDumb> Ord for BundledWitness<P> {
    fn cmp(&self, other: &Self) -> Ordering { self.pub_witness.cmp(&other.pub_witness) }
}

impl<P: mpc::Proof + StrictDumb> PartialOrd for BundledWitness<P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<P: mpc::Proof + StrictDumb> BundledWitness<P> {
    pub fn bundles(&self) -> vec::IntoIter<&TransitionBundle> { self.anchored_bundles.bundles() }
}

impl BundledWitness<mpc::MerkleProof> {
    pub fn disclose(&self) -> BundledWitnessDisclosure {
        let mut bundles = self.anchored_bundles.bundles();
        BundledWitnessDisclosure {
            pub_witness: self.pub_witness.clone(),
            anchors: self.anchored_bundles.to_anchor_set(),
            bundle1: bundles
                .next()
                .expect("anchored bundle always has at least one bundle")
                .disclose(),
            bundle2: bundles.next().map(TransitionBundle::disclose),
        }
    }

    pub fn disclose_hash(&self) -> DiscloseHash { self.disclose().commit_id() }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AnchoredBundles<P: mpc::Proof + StrictDumb = mpc::MerkleProof> {
    #[strict_type(tag = 0x01)]
    Tapret(Anchor<P, TapretProof>, TransitionBundle),
    #[strict_type(tag = 0x02)]
    Opret(Anchor<P, OpretProof>, TransitionBundle),
    #[strict_type(tag = 0x03)]
    Dual(Anchor<P, TapretProof>, Anchor<P, OpretProof>, TransitionBundle),
    #[strict_type(tag = 0x00)]
    Double {
        tapret_anchor: Anchor<P, TapretProof>,
        tapret_bundle: TransitionBundle,
        opret_anchor: Anchor<P, OpretProof>,
        opret_bundle: TransitionBundle,
    },
}

impl<P: mpc::Proof + StrictDumb> StrictDumb for AnchoredBundles<P> {
    fn strict_dumb() -> Self { Self::Opret(strict_dumb!(), strict_dumb!()) }
}

impl<P: mpc::Proof + StrictDumb> AnchoredBundles<P> {
    pub fn with(anchor: AnchorSet<P>, bundle: TransitionBundle) -> Option<Self> {
        match anchor {
            AnchorSet::Tapret(tapret) => Some(Self::Tapret(tapret, bundle)),
            AnchorSet::Opret(opret) => Some(Self::Opret(opret, bundle)),
            AnchorSet::Dual { .. } => None,
        }
    }

    pub fn into_bundles(self) -> vec::IntoIter<TransitionBundle> {
        match self {
            AnchoredBundles::Tapret(_, bundle) |
            AnchoredBundles::Opret(_, bundle) |
            AnchoredBundles::Dual(_, _, bundle) => vec![bundle],
            AnchoredBundles::Double {
                tapret_bundle,
                opret_bundle,
                ..
            } => vec![tapret_bundle, opret_bundle],
        }
        .into_iter()
    }

    pub fn bundles(&self) -> vec::IntoIter<&TransitionBundle> {
        match self {
            AnchoredBundles::Tapret(_, bundle) |
            AnchoredBundles::Opret(_, bundle) |
            AnchoredBundles::Dual(_, _, bundle) => vec![bundle],
            AnchoredBundles::Double {
                tapret_bundle,
                opret_bundle,
                ..
            } => vec![tapret_bundle, opret_bundle],
        }
        .into_iter()
    }

    pub fn bundles_mut(&mut self) -> vec::IntoIter<&mut TransitionBundle> {
        match self {
            AnchoredBundles::Tapret(_, bundle) |
            AnchoredBundles::Opret(_, bundle) |
            AnchoredBundles::Dual(_, _, bundle) => vec![bundle],
            AnchoredBundles::Double {
                tapret_bundle,
                opret_bundle,
                ..
            } => vec![tapret_bundle, opret_bundle],
        }
        .into_iter()
    }

    pub fn to_anchor_set(&self) -> AnchorSet<P>
    where P: Clone {
        match self.clone() {
            AnchoredBundles::Tapret(tapret, _) => AnchorSet::Tapret(tapret),
            AnchoredBundles::Opret(opret, _) => AnchorSet::Opret(opret),
            AnchoredBundles::Dual(tapret, opret, _) |
            AnchoredBundles::Double {
                tapret_anchor: tapret,
                opret_anchor: opret,
                ..
            } => AnchorSet::Dual { tapret, opret },
        }
    }

    /// Ensures that the transition is revealed inside the anchored bundle.
    ///
    /// # Returns
    ///
    /// `true` if the transition was previously concealed; `false` if it was
    /// already revealed; error if the transition is unrelated to the bundle.
    pub fn reveal_transition(&mut self, mut transition: Transition) -> Result<bool, RevealError> {
        for bundle in self.bundles_mut() {
            match bundle.reveal_transition(transition) {
                Ok(known) => return Ok(known),
                Err(RevealError::UnrelatedTransition(_, t)) => transition = t,
            }
        }
        Err(RevealError::UnrelatedTransition(transition.id(), transition))
    }
}
