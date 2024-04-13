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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use std::{fmt, iter};

use aluvm::library::Lib;
use amplify::confinement::{
    Confined, LargeOrdSet, MediumBlob, SmallOrdMap, SmallOrdSet, TinyOrdMap, TinyOrdSet,
};
use amplify::{ByteArray, Bytes32};
use armor::{ArmorHeader, AsciiArmor, StrictArmor};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use commit_verify::{CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256};
use rgb::validation::{ResolveWitness, Validator, Validity, Warning, CONSIGNMENT_MAX_LIBS};
use rgb::{
    validation, AttachId, BundleId, ContractHistory, ContractId, Extension, Genesis, GraphSeal,
    Operation, Schema, SchemaId, XChain,
};
use strict_encoding::{StrictDeserialize, StrictDumb, StrictSerialize};
use strict_types::TypeSystem;

use super::{
    BundledWitness, ContainerVer, ContentId, ContentSigs, IndexedConsignment, Terminal,
    TerminalDisclose, ASCII_ARMOR_CONSIGNMENT_TYPE, ASCII_ARMOR_CONTRACT_, ASCII_ARMOR_TERMINAL,
    ASCII_ARMOR_VERSION,
};
use crate::accessors::BundleExt;
use crate::containers::anchors::ToWitnessId;
use crate::interface::{ContractSuppl, Iface, IfaceImpl};
use crate::resolvers::ResolveHeight;
use crate::{SecretSeal, LIB_NAME_RGB_STD};

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

pub type ValidContract = ValidConsignment<false>;
pub type ValidTransfer = ValidConsignment<true>;

#[derive(Clone, Debug)]
pub struct ValidConsignment<const TRANSFER: bool> {
    /// Status of the latest validation.
    validation_status: validation::Status,
    consignment: Consignment<TRANSFER>,
}

impl<const TRANSFER: bool> ValidConsignment<TRANSFER> {
    pub fn validation_status(&self) -> &validation::Status { &self.validation_status }

    pub fn into_validation_status(self) -> validation::Status { self.validation_status }

    pub fn split(self) -> (Consignment<TRANSFER>, validation::Status) {
        (self.consignment, self.validation_status)
    }
}

impl<const TRANSFER: bool> Deref for ValidConsignment<TRANSFER> {
    type Target = Consignment<TRANSFER>;

    fn deref(&self) -> &Self::Target { &self.consignment }
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
pub struct Consignment<const TRANSFER: bool> {
    /// Version.
    pub version: ContainerVer,

    /// Specifies whether the consignment contains information about state
    /// transfer (true), or it is just a consignment with an information about a
    /// contract.
    pub transfer: bool,

    /// Set of seals which are history terminals.
    pub terminals: SmallOrdMap<BundleId, Terminal>,

    /// Genesis data.
    pub genesis: Genesis,

    /// All state extensions contained in the consignment.
    pub extensions: LargeOrdSet<Extension>,

    /// All bundled state transitions contained in the consignment, together
    /// with their witness data.
    pub bundles: LargeOrdSet<BundledWitness>,

    /// Schema (plus root schema, if any) under which contract is issued.
    pub schema: Schema,

    /// Interfaces supported by the contract.
    pub ifaces: TinyOrdMap<Iface, IfaceImpl>,

    /// Known supplements.
    pub supplements: TinyOrdSet<ContractSuppl>,

    /// Type system covering all types used in schema, interfaces and
    /// implementations.
    pub types: TypeSystem,

    /// Collection of scripts used across consignment.
    pub scripts: Confined<BTreeSet<Lib>, 0, CONSIGNMENT_MAX_LIBS>,

    /// Data containers coming with this consignment. For the purposes of
    /// in-memory consignments we are restricting the size of the containers to
    /// 24 bit value (RGB allows containers up to 32-bit values in size).
    pub attachments: SmallOrdMap<AttachId, MediumBlob>,

    /// Signatures on the pieces of content which are the part of the
    /// consignment.
    pub signatures: TinyOrdMap<ContentId, ContentSigs>,
}

impl<const TRANSFER: bool> StrictSerialize for Consignment<TRANSFER> {}
impl<const TRANSFER: bool> StrictDeserialize for Consignment<TRANSFER> {}

impl<const TRANSFER: bool> CommitEncode for Consignment<TRANSFER> {
    type CommitmentId = ConsignmentId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.version);
        e.commit_to_serialized(&self.transfer);

        e.commit_to_serialized(&self.contract_id());
        e.commit_to_serialized(&self.genesis.disclose_hash());
        e.commit_to_set(&TinyOrdSet::from_iter_unsafe(
            self.ifaces.values().map(|iimpl| iimpl.impl_id()),
        ));

        e.commit_to_set(&LargeOrdSet::from_iter_unsafe(
            self.bundles.iter().map(BundledWitness::disclose_hash),
        ));
        e.commit_to_set(&LargeOrdSet::from_iter_unsafe(
            self.extensions.iter().map(Extension::disclose_hash),
        ));
        e.commit_to_set(&SmallOrdSet::from_iter_unsafe(self.terminals_disclose()));

        e.commit_to_set(&SmallOrdSet::from_iter_unsafe(self.attachments.keys().copied()));
        e.commit_to_set(&TinyOrdSet::from_iter_unsafe(
            self.supplements.iter().map(|suppl| suppl.suppl_id()),
        ));

        e.commit_to_serialized(&self.types.id());
        e.commit_to_set(&SmallOrdSet::from_iter_unsafe(self.scripts.iter().map(|lib| lib.id())));

        e.commit_to_map(&self.signatures);
    }
}

impl<const TRANSFER: bool> Consignment<TRANSFER> {
    #[inline]
    pub fn consignment_id(&self) -> ConsignmentId { self.commit_id() }

    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.schema.schema_id() }

    #[inline]
    pub fn contract_id(&self) -> ContractId { self.genesis.contract_id() }

    pub fn terminal_secrets(&self) -> impl Iterator<Item = (BundleId, XChain<SecretSeal>)> {
        self.terminals
            .clone()
            .into_iter()
            .flat_map(|(id, term)| term.secrets().map(move |secret| (id, secret)))
    }

    pub fn terminals_disclose(&self) -> impl Iterator<Item = TerminalDisclose> + '_ {
        self.terminals.iter().flat_map(|(id, term)| {
            term.seals.iter().map(|seal| TerminalDisclose {
                bundle_id: *id,
                seal: *seal,
            })
        })
    }

    pub fn update_history<R: ResolveHeight>(
        &self,
        history: Option<ContractHistory>,
        resolver: &mut R,
    ) -> Result<ContractHistory, R::Error> {
        let mut history = history.unwrap_or_else(|| {
            ContractHistory::with(self.schema_id(), self.contract_id(), &self.genesis)
        });

        let mut extension_idx = self
            .extensions
            .iter()
            .map(Extension::id)
            .zip(iter::repeat(false))
            .collect::<BTreeMap<_, _>>();
        let mut ordered_extensions = BTreeMap::new();
        for bundled_witness in &self.bundles {
            for bundle in bundled_witness.anchored_bundles.bundles() {
                for transition in bundle.known_transitions.values() {
                    let witness_anchor =
                        resolver.resolve_height(bundled_witness.pub_witness.to_witness_id())?;

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
        // We need to clone since ordered set does not allow us to mutate members.
        let mut bundles = LargeOrdSet::with_capacity(self.bundles.len());
        for mut bundled_witness in self.bundles {
            for bundle in bundled_witness.anchored_bundles.bundles_mut() {
                if bundle.bundle_id() == bundle_id {
                    bundle.reveal_seal(revealed);
                }
            }
            bundles.push(bundled_witness).ok();
        }
        self.bundles = bundles;
        self
    }

    pub fn into_contract(self) -> Contract {
        Contract {
            version: self.version,
            transfer: false,
            schema: self.schema,
            ifaces: self.ifaces,
            supplements: self.supplements,
            types: self.types,
            genesis: self.genesis,
            terminals: self.terminals,
            bundles: self.bundles,
            extensions: self.extensions,
            attachments: self.attachments,
            signatures: self.signatures,
            scripts: self.scripts,
        }
    }

    pub fn validate<R: ResolveWitness>(
        self,
        resolver: &mut R,
        testnet: bool,
    ) -> Result<ValidConsignment<TRANSFER>, (validation::Status, Consignment<TRANSFER>)> {
        let index = IndexedConsignment::new(&self);
        let mut status = Validator::validate(&index, resolver, testnet);

        let validity = status.validity();

        if self.transfer != TRANSFER {
            status.add_warning(Warning::Custom(s!("invalid consignment type")));
        }
        // TODO: check that interface ids match implementations
        // TODO: check bundle ids listed in terminals are present in the consignment
        // TODO: check attach ids from data containers are present in operations

        if validity != Validity::Valid {
            Err((status, self))
        } else {
            Ok(ValidConsignment {
                validation_status: status,
                consignment: self,
            })
        }
    }
}

impl<const TRANSFER: bool> StrictArmor for Consignment<TRANSFER> {
    type Id = ConsignmentId;
    const PLATE_TITLE: &'static str = "RGB CONSIGNMENT";

    fn armor_id(&self) -> Self::Id { self.commit_id() }
    fn armor_headers(&self) -> Vec<ArmorHeader> {
        let mut headers = vec![
            ArmorHeader::new(ASCII_ARMOR_VERSION, self.version.to_string()),
            ArmorHeader::new(
                ASCII_ARMOR_CONSIGNMENT_TYPE,
                if self.transfer {
                    s!("transfer")
                } else {
                    s!("contract")
                },
            ),
            ArmorHeader::new(ASCII_ARMOR_CONTRACT_, self.contract_id().to_string()),
        ];
        for bundle_id in self.terminals.keys() {
            headers.push(ArmorHeader::new(ASCII_ARMOR_TERMINAL, bundle_id.to_string()));
        }
        headers
    }
}
