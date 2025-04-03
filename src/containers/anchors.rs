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

use amplify::ByteArray;
use bp::dbc::Anchor;
use bp::{dbc, Tx, Txid};
use commit_verify::mpc;
use rgb::validation::{DbcProof, EAnchor};
use rgb::{BundleId, DiscloseHash, TransitionBundle};
use strict_encoding::StrictDumb;

use crate::{MergeReveal, MergeRevealError, LIB_NAME_RGB_STD};

/// Error merging two [`SealWitness`]es.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum SealWitnessMergeError {
    /// Error merging two MPC proofs, which are unrelated.
    #[display(inner)]
    #[from]
    MpcMismatch(mpc::MergeError),

    /// Error merging two witness proofs, which are unrelated.
    #[display(inner)]
    #[from]
    WitnessMergeError(MergeRevealError),

    /// seal witnesses can't be merged since they have different DBC proofs.
    DbcMismatch,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SealWitness {
    pub public: PubWitness,
    pub merkle_block: mpc::MerkleBlock,
    pub dbc_proof: DbcProof,
}

impl SealWitness {
    pub fn new(witness: PubWitness, merkle_block: mpc::MerkleBlock, dbc_proof: DbcProof) -> Self {
        SealWitness {
            public: witness,
            merkle_block,
            dbc_proof,
        }
    }

    pub fn witness_id(&self) -> Txid { self.public.to_witness_id() }

    /// Merges two [`SealWitness`]es keeping revealed data.
    pub fn merge_reveal(mut self, other: Self) -> Result<Self, SealWitnessMergeError> {
        if self.dbc_proof != other.dbc_proof {
            return Err(SealWitnessMergeError::DbcMismatch);
        }
        self.public = self.public.clone().merge_reveal(other.public)?;
        self.merkle_block.merge_reveal(other.merkle_block)?;
        Ok(self)
    }

    pub fn known_bundle_ids(&self) -> impl Iterator<Item = BundleId> {
        let map = self.merkle_block.to_known_message_map().release();
        map.into_values()
            .map(|msg| BundleId::from_byte_array(msg.to_byte_array()))
    }
}

pub trait ToWitnessId {
    fn to_witness_id(&self) -> Txid;
}

impl ToWitnessId for PubWitness {
    fn to_witness_id(&self) -> Txid { self.txid() }
}

impl MergeReveal for PubWitness {
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        self.merge_reveal(other)
    }
}

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom, dumb = Self::Txid(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum PubWitness {
    #[strict_type(tag = 0x00)]
    Txid(Txid),
    #[strict_type(tag = 0x01)]
    Tx(Tx), /* TODO: Consider using `UnsignedTx` here
             * TODO: Add SPV as an option here */
}

impl PartialEq for PubWitness {
    fn eq(&self, other: &Self) -> bool { self.txid() == other.txid() }
}

impl Ord for PubWitness {
    fn cmp(&self, other: &Self) -> Ordering { self.txid().cmp(&other.txid()) }
}

impl PartialOrd for PubWitness {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl PubWitness {
    pub fn new(txid: Txid) -> Self { Self::Txid(txid) }

    pub fn with(tx: Tx) -> Self { Self::Tx(tx) }

    pub fn txid(&self) -> Txid {
        match self {
            PubWitness::Txid(txid) => *txid,
            PubWitness::Tx(tx) => tx.txid(),
        }
    }

    pub fn tx(&self) -> Option<&Tx> {
        match self {
            PubWitness::Txid(_) => None,
            PubWitness::Tx(tx) => Some(tx),
        }
    }

    pub fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        match (self, other) {
            (Self::Txid(txid1), Self::Txid(txid2)) if txid1 == txid2 => Ok(Self::Txid(txid1)),
            (Self::Txid(txid), Self::Tx(tx)) | (Self::Txid(txid), Self::Tx(tx))
                if txid == tx.txid() =>
            {
                Ok(Self::Tx(tx))
            }
            // TODO: tx1 and tx2 may differ on their witness data; take the one having most of the
            // witness
            (Self::Tx(tx1), Self::Tx(tx2)) if tx1.txid() == tx2.txid() => Ok(Self::Tx(tx1)),
            (a, b) => Err(MergeRevealError::TxidMismatch(a.txid(), b.txid())),
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
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = DiscloseHash)]
pub struct WitnessBundle<D: dbc::Proof = DbcProof> {
    pub pub_witness: PubWitness,
    pub anchor: Anchor<D>,
    pub bundle: TransitionBundle,
}

impl<D: dbc::Proof> PartialEq for WitnessBundle<D> {
    fn eq(&self, other: &Self) -> bool { self.pub_witness == other.pub_witness }
}

impl<D: dbc::Proof> Ord for WitnessBundle<D> {
    fn cmp(&self, other: &Self) -> Ordering { self.pub_witness.cmp(&other.pub_witness) }
}

impl<D: dbc::Proof> PartialOrd for WitnessBundle<D> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<D: dbc::Proof> WitnessBundle<D>
where DbcProof: From<D>
{
    #[inline]
    pub fn with(pub_witness: PubWitness, anchor: Anchor<D>, bundle: TransitionBundle) -> Self {
        Self {
            pub_witness,
            anchor,
            bundle,
        }
    }

    pub fn witness_id(&self) -> Txid { self.pub_witness.to_witness_id() }

    pub fn bundle(&self) -> &TransitionBundle { &self.bundle }

    pub fn bundle_mut(&mut self) -> &mut TransitionBundle { &mut self.bundle }

    pub fn eanchor(&self) -> EAnchor {
        EAnchor::new(self.anchor.mpc_proof.clone(), self.anchor.dbc_proof.clone().into())
    }
}
