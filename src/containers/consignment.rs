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

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::{fmt, iter};

use amplify::confinement::{
    LargeOrdSet, MediumBlob, SmallOrdMap, SmallOrdSet, TinyOrdMap, TinyOrdSet,
};
use amplify::{ByteArray, Bytes32};
use armor::{AsciiArmor, StrictArmorError};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use bp::Tx;
use commit_verify::{CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256};
use rgb::validation::{self};
use rgb::{
    AnchoredBundle, AssetTag, AssignmentType, AttachId, BundleId, ContractHistory, ContractId,
    Extension, Genesis, GraphSeal, OpId, Operation, Schema, SchemaId, SubSchema, Transition,
    XChain,
};
use strict_encoding::{StrictDeserialize, StrictDumb, StrictSerialize};

use super::{ContainerVer, ContentId, ContentSigs, Terminal, TerminalDisclose};
use crate::accessors::BundleExt;
use crate::interface::{ContractSuppl, IfaceId, IfacePair};
use crate::resolvers::ResolveHeight;
use crate::LIB_NAME_RGB_STD;

pub type Transfer = Consignment<true>;
pub type Contract = Consignment<false>;

/// Interface identifier.
///
/// Interface identifier commits to all the interface data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ConsignmentId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for ConsignmentId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for ConsignmentId {
    const TAG: &'static str = "urn:lnp-bp:rgb:consignment#2024-03-11";
}

impl ToBaid58<32> for ConsignmentId {
    const HRI: &'static str = "con";
    const CHUNKING: Option<Chunking> = CHUNKING_32;
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_byte_array() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for ConsignmentId {}
impl Display for ConsignmentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            f.write_str("urn:lnp-bp:con:")?;
        }
        if f.sign_minus() {
            write!(f, "{:.2}", self.to_baid58())
        } else {
            write!(f, "{:#.2}", self.to_baid58())
        }
    }
}
impl FromStr for ConsignmentId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_baid58_maybe_chunked_str(s.trim_start_matches("urn:lnp-bp:"), ':', '#')
    }
}
impl ConsignmentId {
    pub const fn from_array(id: [u8; 32]) -> Self { Self(Bytes32::from_array(id)) }
    pub fn to_mnemonic(&self) -> String { self.to_baid58().mnemonic() }
}

/// Consignment represents contract-specific data, always starting with genesis,
/// which must be valid under client-side-validation rules (i.e. internally
/// consistent and properly committed into the commitment layer, like bitcoin
/// blockchain or current state of the lightning channel).
///
/// All consignments-related procedures, including validation or merging
/// consignments data into stash or schema-specific data storage, must start
/// with `endpoints` and process up to the genesis.
#[derive(Clone, Debug, Display)]
#[display(AsciiArmor::to_ascii_armored_string)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Consignment<const TYPE: bool> {
    /// Status of the latest validation.
    ///
    /// The value is not saved and when the structure is read from a disk or
    /// network is left uninitialized. Thus, only locally-run verification by
    /// this library is trusted.
    #[strict_type(skip, dumb = None)]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(super) validation_status: Option<validation::Status>,

    /// Version.
    pub version: ContainerVer,

    /// Specifies whether the consignment contains information about state
    /// transfer (true), or it is just a consignment with an information about a
    /// contract.
    pub transfer: bool,

    /// Confidential asset tags.
    pub asset_tags: TinyOrdMap<AssignmentType, AssetTag>,

    /// Set of seals which are history terminals.
    pub terminals: SmallOrdMap<BundleId, Terminal>,

    /// Genesis data.
    pub genesis: Genesis,

    /// Data on all anchored state transitions contained in the consignments.
    pub bundles: LargeOrdSet<AnchoredBundle>,

    /// Data on all state extensions contained in the consignments.
    pub extensions: LargeOrdSet<Extension>,

    /// Schema (plus root schema, if any) under which contract is issued.
    pub schema: SubSchema,

    /// Interfaces supported by the contract.
    pub ifaces: TinyOrdMap<IfaceId, IfacePair>,

    /// Known supplements.
    pub supplements: TinyOrdSet<ContractSuppl>,

    /// Data containers coming with this consignment. For the purposes of
    /// in-memory consignments we are restricting the size of the containers to
    /// 24 bit value (RGB allows containers up to 32-bit values in size).
    pub attachments: SmallOrdMap<AttachId, MediumBlob>,

    /// Signatures on the pieces of content which are the part of the
    /// consignment.
    pub signatures: TinyOrdMap<ContentId, ContentSigs>,
}

impl<const TYPE: bool> StrictSerialize for Consignment<TYPE> {}
impl<const TYPE: bool> StrictDeserialize for Consignment<TYPE> {}

impl<const TYPE: bool> CommitEncode for Consignment<TYPE> {
    type CommitmentId = ConsignmentId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.version);
        e.commit_to_serialized(&self.transfer);

        e.commit_to_serialized(&self.contract_id());
        e.commit_to_serialized(&self.genesis.disclose_hash());
        e.commit_to_set(&TinyOrdSet::from_iter_unsafe(
            self.ifaces.values().map(|pair| pair.iimpl.impl_id()),
        ));

        e.commit_to_set(&LargeOrdSet::from_iter_unsafe(
            self.bundles.iter().map(|ab| ab.bundle.disclose_hash()),
        ));
        e.commit_to_set(&LargeOrdSet::from_iter_unsafe(
            self.extensions.iter().map(Extension::disclose_hash),
        ));
        e.commit_to_set(&SmallOrdSet::from_iter_unsafe(self.terminals_disclose()));

        e.commit_to_set(&SmallOrdSet::from_iter_unsafe(self.attachments.keys().copied()));
        e.commit_to_set(&self.supplements);
        e.commit_to_map(&self.asset_tags);
        e.commit_to_map(&self.signatures);
    }
}

impl<const TYPE: bool> Consignment<TYPE> {
    /// # Panics
    ///
    /// If the provided schema is not the one which is used by genesis.
    pub fn new(
        schema: SubSchema,
        genesis: Genesis,
        asset_tags: TinyOrdMap<AssignmentType, AssetTag>,
    ) -> Self {
        assert_eq!(schema.schema_id(), genesis.schema_id);
        Consignment {
            validation_status: None,
            version: ContainerVer::V2,
            transfer: TYPE,
            schema,
            ifaces: none!(),
            supplements: none!(),
            asset_tags,
            genesis,
            terminals: none!(),
            bundles: none!(),
            extensions: none!(),
            attachments: none!(),
            signatures: none!(),
        }
    }

    #[inline]
    pub fn consignment_id(&self) -> ConsignmentId { self.commit_id() }

    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.schema.schema_id() }

    #[inline]
    pub fn root_schema_id(&self) -> Option<SchemaId> {
        self.schema.subset_of.as_ref().map(Schema::schema_id)
    }

    #[inline]
    pub fn contract_id(&self) -> ContractId { self.genesis.contract_id() }

    pub fn anchored_bundle(&self, bundle_id: BundleId) -> Option<&AnchoredBundle> {
        self.bundles
            .iter()
            .find(|anchored_bundle| anchored_bundle.bundle.bundle_id() == bundle_id)
    }

    pub(super) fn transition(&self, opid: OpId) -> Option<&Transition> {
        self.bundles
            .iter()
            .find_map(|ab| ab.bundle.known_transitions.get(&opid))
    }

    pub(super) fn extension(&self, opid: OpId) -> Option<&Extension> {
        self.extensions
            .iter()
            .find(|&extension| extension.id() == opid)
    }

    pub fn terminals_disclose(&self) -> impl Iterator<Item = TerminalDisclose> + '_ {
        self.terminals.iter().flat_map(|(id, term)| {
            term.seals.iter().map(|seal| TerminalDisclose {
                bundle_id: *id,
                seal: *seal,
                witness_id: term
                    .witness_tx
                    .as_ref()
                    .map(|witness| witness.map_ref(Tx::txid)),
            })
        })
    }

    pub fn validation_status(&self) -> Option<&validation::Status> {
        self.validation_status.as_ref()
    }

    pub fn into_validation_status(self) -> Option<validation::Status> { self.validation_status }

    pub fn update_history<R: ResolveHeight>(
        &self,
        history: Option<&ContractHistory>,
        resolver: &mut R,
    ) -> Result<ContractHistory, R::Error> {
        let mut history = history.cloned().unwrap_or_else(|| {
            ContractHistory::with(
                self.schema_id(),
                self.root_schema_id(),
                self.contract_id(),
                &self.genesis,
            )
        });

        let mut extension_idx = self
            .extensions
            .iter()
            .map(Extension::id)
            .zip(iter::repeat(false))
            .collect::<BTreeMap<_, _>>();
        let mut ordered_extensions = BTreeMap::new();
        for anchored_bundle in &self.bundles {
            for transition in anchored_bundle.bundle.known_transitions.values() {
                let witness_anchor = resolver.resolve_anchor(&anchored_bundle.anchor)?;

                history.add_transition(transition, witness_anchor);
                for (id, used) in &mut extension_idx {
                    if *used {
                        continue;
                    }
                    for input in &transition.inputs {
                        if input.prev_out.op == *id {
                            *used = true;
                            if let Some(ord) = ordered_extensions.get_mut(id) {
                                if *ord > witness_anchor {
                                    *ord = witness_anchor;
                                }
                            } else {
                                ordered_extensions.insert(*id, witness_anchor);
                            }
                        }
                    }
                }
            }
        }
        for extension in &self.extensions {
            if let Some(witness_anchor) = ordered_extensions.get(&extension.id()) {
                history.add_extension(extension, *witness_anchor);
            }
        }

        Ok(history)
    }

    #[must_use]
    pub fn reveal_bundle_seal(mut self, bundle_id: BundleId, revealed: XChain<GraphSeal>) -> Self {
        let mut bundles = LargeOrdSet::with_capacity(self.bundles.len());
        for mut anchored_bundle in self.bundles {
            if anchored_bundle.bundle.bundle_id() == bundle_id {
                anchored_bundle.bundle.reveal_seal(revealed);
            }
            bundles.push(anchored_bundle).ok();
        }
        self.bundles = bundles;
        self
    }

    pub fn into_contract(self) -> Contract {
        Contract {
            validation_status: self.validation_status,
            version: self.version,
            transfer: false,
            schema: self.schema,
            ifaces: self.ifaces,
            supplements: self.supplements,
            asset_tags: self.asset_tags,
            genesis: self.genesis,
            terminals: self.terminals,
            bundles: self.bundles,
            extensions: self.extensions,
            attachments: self.attachments,
            signatures: self.signatures,
        }
    }
}

impl<const TYPE: bool> FromStr for Consignment<TYPE> {
    type Err = StrictArmorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_ascii_armored_str(s) }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn contract_str_parse() {
        let contract = Contract::strict_dumb();
        let contract_str = contract.to_string();
        Contract::from_str(&contract_str).expect("valid contract string");
    }

    #[test]
    fn transfer_str_parse() {
        let transfer = Transfer::strict_dumb();
        let transfer_str = transfer.to_string();
        Transfer::from_str(&transfer_str).expect("valid transfer string");
    }
}
