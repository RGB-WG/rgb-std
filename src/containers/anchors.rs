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
    AnchorSet, BundleDisclosure, BundleId, ContractId, DiscloseHash, Grip, TransitionBundle,
    XChain, XGrip, XWitnessId,
};
use strict_encoding::StrictDumb;

use crate::LIB_NAME_RGB_STD;

pub type XPubWitness = XChain<PubWitness>;

pub trait ToWitnessId {
    fn to_witness_id(&self) -> XWitnessId;
}

impl ToWitnessId for XPubWitness {
    fn to_witness_id(&self) -> XWitnessId { self.map_ref(|w| w.txid) }
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
    pub anchored_bundle: AnchoredBundle<P>,
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
    pub fn bundles(&self) -> vec::IntoIter<&TransitionBundle> { self.anchored_bundle.bundles() }
}

impl BundledWitness<mpc::MerkleProof> {
    pub fn disclose(&self) -> BundledWitnessDisclosure {
        let mut bundles = self.anchored_bundle.bundles();
        BundledWitnessDisclosure {
            pub_witness: self.pub_witness.clone(),
            anchors: self.anchored_bundle.to_anchor_set(),
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
pub enum AnchoredBundle<P: mpc::Proof + StrictDumb = mpc::MerkleProof> {
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

impl<P: mpc::Proof + StrictDumb> StrictDumb for AnchoredBundle<P> {
    fn strict_dumb() -> Self { Self::Opret(strict_dumb!(), strict_dumb!()) }
}

impl<P: mpc::Proof + StrictDumb> AnchoredBundle<P> {
    pub fn bundles(&self) -> vec::IntoIter<&TransitionBundle> {
        match self {
            AnchoredBundle::Tapret(_, bundle) |
            AnchoredBundle::Opret(_, bundle) |
            AnchoredBundle::Dual(_, _, bundle) => vec![bundle],
            AnchoredBundle::Double {
                tapret_bundle,
                opret_bundle,
                ..
            } => vec![tapret_bundle, opret_bundle],
        }
        .into_iter()
    }

    pub fn bundles_mut(&mut self) -> vec::IntoIter<&mut TransitionBundle> {
        match self {
            AnchoredBundle::Tapret(_, bundle) |
            AnchoredBundle::Opret(_, bundle) |
            AnchoredBundle::Dual(_, _, bundle) => vec![bundle],
            AnchoredBundle::Double {
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
            AnchoredBundle::Tapret(tapret, _) => AnchorSet::Tapret(tapret),
            AnchoredBundle::Opret(opret, _) => AnchorSet::Opret(opret),
            AnchoredBundle::Dual(tapret, opret, _) |
            AnchoredBundle::Double {
                tapret_anchor: tapret,
                opret_anchor: opret,
                ..
            } => AnchorSet::Dual { tapret, opret },
        }
    }
}

pub trait ToMerkleProof {
    fn known_bundle_ids(&self) -> impl Iterator<Item = (BundleId, ContractId)> + '_;
    fn split(self) -> (XWitnessId, AnchorSet<mpc::MerkleBlock>);
    fn to_merkle_proof(
        &self,
        contract_id: ContractId,
    ) -> Result<XGrip<mpc::MerkleProof>, mpc::LeafNotKnown>;
    fn into_merkle_proof(
        self,
        contract_id: ContractId,
    ) -> Result<XGrip<mpc::MerkleProof>, mpc::LeafNotKnown>;
}

impl ToMerkleProof for XGrip<mpc::MerkleBlock> {
    fn known_bundle_ids(&self) -> impl Iterator<Item = (BundleId, ContractId)> + '_ {
        match self {
            XGrip::Bitcoin(grip) | XGrip::Liquid(grip) => grip.anchors.known_bundle_ids(),
            _ => unreachable!(),
        }
    }

    fn split(self) -> (XWitnessId, AnchorSet<mpc::MerkleBlock>) {
        match self {
            XGrip::Bitcoin(grip) => (XWitnessId::Bitcoin(grip.id), grip.anchors),
            XGrip::Liquid(grip) => (XWitnessId::Liquid(grip.id), grip.anchors),
            _ => unreachable!(),
        }
    }

    fn to_merkle_proof(
        &self,
        contract_id: ContractId,
    ) -> Result<XGrip<mpc::MerkleProof>, mpc::LeafNotKnown> {
        self.clone().into_merkle_proof(contract_id)
    }

    fn into_merkle_proof(
        self,
        contract_id: ContractId,
    ) -> Result<XGrip<mpc::MerkleProof>, mpc::LeafNotKnown> {
        self.try_map(|grip| {
            let anchors = grip.anchors.into_merkle_proof(contract_id)?;
            Ok(Grip {
                id: grip.id,
                anchors,
            })
        })
    }
}

pub trait ToMerkleBlock {
    fn to_merkle_block(
        &self,
        contract_id: ContractId,
        bundle_id: BundleId,
    ) -> Result<XGrip<mpc::MerkleBlock>, mpc::InvalidProof>;
    fn into_merkle_block(
        self,
        contract_id: ContractId,
        bundle_id: BundleId,
    ) -> Result<XGrip<mpc::MerkleBlock>, mpc::InvalidProof>;
}

impl ToMerkleBlock for XGrip<mpc::MerkleProof> {
    fn to_merkle_block(
        &self,
        contract_id: ContractId,
        bundle_id: BundleId,
    ) -> Result<XGrip<mpc::MerkleBlock>, mpc::InvalidProof> {
        self.clone().into_merkle_block(contract_id, bundle_id)
    }

    fn into_merkle_block(
        self,
        contract_id: ContractId,
        bundle_id: BundleId,
    ) -> Result<XGrip<mpc::MerkleBlock>, mpc::InvalidProof> {
        self.try_map(|grip| {
            let anchors = grip.anchors.into_merkle_block(contract_id, bundle_id)?;
            Ok(Grip {
                id: grip.id,
                anchors,
            })
        })
    }
}
