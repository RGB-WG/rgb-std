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

use commit_verify::mpc;
use rgb::{AnchorSet, BundleId, ContractId, Grip, TransitionBundle, XGrip, XWitnessId};
use strict_encoding::StrictDumb;

use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AnchoredBundle {
    pub grip: XGrip,
    pub bundle: TransitionBundle,
}

impl AnchoredBundle {
    #[inline]
    pub fn bundle_id(&self) -> BundleId { self.bundle.bundle_id() }
}

impl PartialEq for AnchoredBundle {
    fn eq(&self, other: &Self) -> bool { self.bundle_id() == other.bundle_id() }
}

impl Ord for AnchoredBundle {
    fn cmp(&self, other: &Self) -> Ordering { self.bundle_id().cmp(&other.bundle_id()) }
}

impl PartialOrd for AnchoredBundle {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
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
