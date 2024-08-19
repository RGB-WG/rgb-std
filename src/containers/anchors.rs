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

use amplify::ByteArray;
use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::dbc::{anchor, Anchor};
use bp::{Tx, Txid};
use commit_verify::{mpc, CommitId};
use rgb::validation::{DbcProof, EAnchor};
use rgb::{
    BundleDisclosure, BundleId, ContractId, DiscloseHash, Operation, Transition, TransitionBundle,
    XChain, XWitnessId,
};
use strict_encoding::StrictDumb;

use crate::{BundleExt, MergeReveal, MergeRevealError, RevealError, LIB_NAME_RGB_STD};

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
    pub anchors: AnchorSet,
}

impl SealWitness {
    pub fn new(witness: XPubWitness, anchors: AnchorSet) -> Self {
        SealWitness {
            public: witness,
            anchors,
        }
    }

    pub fn witness_id(&self) -> XWitnessId { self.public.to_witness_id() }
}

pub type XPubWitness = XChain<PubWitness>;

pub trait ToWitnessId {
    fn to_witness_id(&self) -> XWitnessId;
}

impl ToWitnessId for XPubWitness {
    fn to_witness_id(&self) -> XWitnessId { self.map_ref(|w| w.txid()) }
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
                    bitcoin: bitcoin.txid(),
                    liquid: liquid.txid(),
                })
            }
            _ => unreachable!(),
        }
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

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub(crate) struct AnchoredBundleDisclosure {
    pub anchor: EAnchor,
    pub bundle: BundleDisclosure,
}

impl AnchoredBundleDisclosure {
    pub fn new(anchor: EAnchor, bundle: &TransitionBundle) -> Self {
        Self {
            anchor,
            bundle: bundle.disclose(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = DiscloseHash)]
pub(crate) struct BundledWitnessDisclosure {
    pub pub_witness: XPubWitness,
    pub first: AnchoredBundleDisclosure,
    pub second: Option<AnchoredBundleDisclosure>,
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
    pub fn witness_id(&self) -> XWitnessId { self.pub_witness.to_witness_id() }

    pub(crate) fn disclose(&self) -> BundledWitnessDisclosure {
        let mut pairs = self.anchored_bundles.pairs();
        let (a1, b1) = pairs.next().expect("there always at least one bundle");
        let second = pairs
            .next()
            .map(|(a, b)| AnchoredBundleDisclosure::new(a, b));
        BundledWitnessDisclosure {
            pub_witness: self.pub_witness.clone(),
            first: AnchoredBundleDisclosure::new(a1, b1),
            second,
        }
    }

    pub fn disclose_hash(&self) -> DiscloseHash { self.disclose().commit_id() }
}

impl BundledWitness {
    pub fn merge_reveal(mut self, other: Self) -> Result<Self, MergeRevealError> {
        self.pub_witness = self.pub_witness.merge_reveal(other.pub_witness)?;
        self.anchored_bundles = self.anchored_bundles.merge_reveal(other.anchored_bundles)?;
        Ok(self)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AnchorSet {
    #[strict_type(tag = 0x01)]
    Tapret(Anchor<mpc::MerkleBlock, TapretProof>),
    #[strict_type(tag = 0x02)]
    Opret(Anchor<mpc::MerkleBlock, OpretProof>),
    #[strict_type(tag = 0x03)]
    Double {
        tapret: Anchor<mpc::MerkleBlock, TapretProof>,
        opret: Anchor<mpc::MerkleBlock, OpretProof>,
    },
}

impl StrictDumb for AnchorSet {
    fn strict_dumb() -> Self { Self::Opret(strict_dumb!()) }
}

impl AnchorSet {
    pub fn known_bundle_ids(&self) -> impl Iterator<Item = BundleId> {
        let map = match self {
            AnchorSet::Tapret(tapret) => tapret.mpc_proof.to_known_message_map().release(),
            AnchorSet::Opret(opret) => opret.mpc_proof.to_known_message_map().release(),
            AnchorSet::Double { tapret, opret } => {
                let mut map = tapret.mpc_proof.to_known_message_map().release();
                map.extend(opret.mpc_proof.to_known_message_map().release());
                map
            }
        };
        map.into_values()
            .map(|msg| BundleId::from_byte_array(msg.to_byte_array()))
    }

    pub fn has_tapret(&self) -> bool { matches!(self, Self::Tapret(_) | Self::Double { .. }) }

    pub fn has_opret(&self) -> bool { matches!(self, Self::Opret(_) | Self::Double { .. }) }

    pub fn merge_reveal(self, other: Self) -> Result<Self, anchor::MergeError> {
        match (self, other) {
            (Self::Tapret(anchor), Self::Tapret(a)) => Ok(Self::Tapret(anchor.merge_reveal(a)?)),
            (Self::Opret(anchor), Self::Opret(a)) => Ok(Self::Opret(anchor.merge_reveal(a)?)),
            (Self::Tapret(tapret), Self::Opret(opret)) |
            (Self::Opret(opret), Self::Tapret(tapret)) => Ok(Self::Double { tapret, opret }),

            (Self::Double { tapret, opret }, Self::Tapret(t)) |
            (Self::Tapret(t), Self::Double { tapret, opret }) => Ok(Self::Double {
                tapret: tapret.merge_reveal(t)?,
                opret,
            }),

            (Self::Double { tapret, opret }, Self::Opret(o)) |
            (Self::Opret(o), Self::Double { tapret, opret }) => Ok(Self::Double {
                tapret,
                opret: opret.merge_reveal(o)?,
            }),
            (
                Self::Double { tapret, opret },
                Self::Double {
                    tapret: t,
                    opret: o,
                },
            ) => Ok(Self::Double {
                tapret: tapret.merge_reveal(t)?,
                opret: opret.merge_reveal(o)?,
            }),
        }
    }
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
    pub fn with(anchor: EAnchor<P>, bundle: TransitionBundle) -> Self {
        match anchor.dbc_proof {
            DbcProof::Tapret(tapret) => Self::Tapret(Anchor::new(anchor.mpc_proof, tapret), bundle),
            DbcProof::Opret(opret) => Self::Opret(Anchor::new(anchor.mpc_proof, opret), bundle),
        }
    }

    pub fn has_tapret(&self) -> bool { matches!(self, Self::Tapret(..) | Self::Double { .. }) }

    pub fn has_opret(&self) -> bool { matches!(self, Self::Opret(..) | Self::Double { .. }) }

    pub fn pairs(&self) -> vec::IntoIter<(EAnchor<P>, &TransitionBundle)>
    where P: Clone {
        match self {
            AnchoredBundles::Tapret(anchor, bundle) => {
                let anchor = anchor.clone();
                vec![(EAnchor::new(anchor.mpc_proof, anchor.dbc_proof.into()), bundle)]
            }
            AnchoredBundles::Opret(anchor, bundle) => {
                let anchor = anchor.clone();
                vec![(EAnchor::new(anchor.mpc_proof, anchor.dbc_proof.into()), bundle)]
            }
            AnchoredBundles::Double {
                tapret_anchor,
                tapret_bundle,
                opret_anchor,
                opret_bundle,
            } => {
                let tapret_anchor = tapret_anchor.clone();
                let opret_anchor = opret_anchor.clone();
                vec![
                    (
                        EAnchor::new(tapret_anchor.mpc_proof, tapret_anchor.dbc_proof.into()),
                        tapret_bundle,
                    ),
                    (
                        EAnchor::new(opret_anchor.mpc_proof, opret_anchor.dbc_proof.into()),
                        opret_bundle,
                    ),
                ]
            }
        }
        .into_iter()
    }

    pub fn bundles(&self) -> vec::IntoIter<&TransitionBundle> {
        match self {
            AnchoredBundles::Tapret(_, bundle) | AnchoredBundles::Opret(_, bundle) => vec![bundle],
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
            AnchoredBundles::Tapret(_, bundle) | AnchoredBundles::Opret(_, bundle) => vec![bundle],
            AnchoredBundles::Double {
                tapret_bundle,
                opret_bundle,
                ..
            } => vec![tapret_bundle, opret_bundle],
        }
        .into_iter()
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

impl AnchoredBundles {
    pub fn to_anchor_set(
        &self,
        contract_id: ContractId,
        bundle_id: BundleId,
    ) -> Result<AnchorSet, mpc::InvalidProof> {
        let proto = mpc::ProtocolId::from_byte_array(contract_id.to_byte_array());
        let msg = mpc::Message::from_byte_array(bundle_id.to_byte_array());
        match self.clone() {
            Self::Tapret(anchor, _) => anchor.to_merkle_block(proto, msg).map(AnchorSet::Tapret),
            Self::Opret(anchor, _) => anchor.to_merkle_block(proto, msg).map(AnchorSet::Opret),
            Self::Double {
                tapret_anchor,
                opret_anchor,
                ..
            } => Ok(AnchorSet::Double {
                tapret: tapret_anchor.to_merkle_block(proto, msg)?,
                opret: opret_anchor.to_merkle_block(proto, msg)?,
            }),
        }
    }
}

impl AnchoredBundles {
    pub fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        match (self, other) {
            (AnchoredBundles::Tapret(anchor, bundle1), AnchoredBundles::Tapret(a, bundle2))
                if a == anchor =>
            {
                Ok(AnchoredBundles::Tapret(anchor, bundle1.merge_reveal(bundle2)?))
            }

            (AnchoredBundles::Opret(anchor, bundle1), AnchoredBundles::Opret(a, bundle2))
                if a == anchor =>
            {
                Ok(AnchoredBundles::Opret(anchor, bundle1.merge_reveal(bundle2)?))
            }

            (
                AnchoredBundles::Tapret(tapret_anchor, tapret_bundle),
                AnchoredBundles::Opret(opret_anchor, opret_bundle),
            ) |
            (
                AnchoredBundles::Opret(opret_anchor, opret_bundle),
                AnchoredBundles::Tapret(tapret_anchor, tapret_bundle),
            ) => Ok(AnchoredBundles::Double {
                tapret_anchor,
                tapret_bundle,
                opret_anchor,
                opret_bundle,
            }),

            (
                AnchoredBundles::Double {
                    tapret_anchor,
                    tapret_bundle,
                    opret_anchor,
                    opret_bundle,
                },
                AnchoredBundles::Tapret(t, bundle),
            ) |
            (
                AnchoredBundles::Tapret(t, bundle),
                AnchoredBundles::Double {
                    tapret_anchor,
                    tapret_bundle,
                    opret_anchor,
                    opret_bundle,
                },
            ) if tapret_anchor == t => Ok(AnchoredBundles::Double {
                tapret_anchor,
                opret_anchor,
                tapret_bundle: tapret_bundle.merge_reveal(bundle)?,
                opret_bundle,
            }),

            (
                AnchoredBundles::Double {
                    tapret_anchor,
                    tapret_bundle,
                    opret_anchor,
                    opret_bundle,
                },
                AnchoredBundles::Opret(o, bundle),
            ) |
            (
                AnchoredBundles::Opret(o, bundle),
                AnchoredBundles::Double {
                    tapret_anchor,
                    tapret_bundle,
                    opret_anchor,
                    opret_bundle,
                },
            ) if opret_anchor == o => Ok(AnchoredBundles::Double {
                tapret_anchor,
                opret_anchor,
                tapret_bundle: tapret_bundle.merge_reveal(bundle)?,
                opret_bundle,
            }),

            (
                AnchoredBundles::Double {
                    tapret_anchor,
                    tapret_bundle: tapret1,
                    opret_anchor,
                    opret_bundle: opret1,
                },
                AnchoredBundles::Double {
                    tapret_anchor: t,
                    opret_anchor: o,
                    tapret_bundle: tapret2,
                    opret_bundle: opret2,
                    ..
                },
            ) if tapret_anchor == t && opret_anchor == o => Ok(AnchoredBundles::Double {
                tapret_anchor,
                opret_anchor,
                tapret_bundle: tapret1.merge_reveal(tapret2)?,
                opret_bundle: opret1.merge_reveal(opret2)?,
            }),

            (me, _) => Err(MergeRevealError::AnchorsNonEqual(
                me.bundles()
                    .next()
                    .expect("at least one bundle")
                    .bundle_id(),
            )),
        }
    }
}
