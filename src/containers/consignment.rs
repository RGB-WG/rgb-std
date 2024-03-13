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
use std::iter;

use amplify::confinement::{LargeOrdSet, MediumBlob, SmallOrdMap, TinyOrdMap, TinyOrdSet};
use bp::Tx;
use rgb::validation::{self};
use rgb::{
    AnchoredBundle, AssetTag, AssignmentType, AttachId, BundleId, ContractHistory, ContractId,
    Extension, Genesis, GraphSeal, OpId, Operation, Schema, SchemaId, SubSchema, Transition,
    XChain,
};
use strict_encoding::{StrictDeserialize, StrictDumb, StrictSerialize};

use super::{
    Bindle, BindleContent, ContainerVer, ContentId, ContentSigs, Terminal, TerminalDisclose,
};
use crate::accessors::BundleExt;
use crate::interface::{ContractSuppl, IfaceId, IfacePair};
use crate::resolvers::ResolveHeight;
use crate::LIB_NAME_RGB_STD;

pub type Transfer = Consignment<true>;
pub type Contract = Consignment<false>;

/// Consignment represents contract-specific data, always starting with genesis,
/// which must be valid under client-side-validation rules (i.e. internally
/// consistent and properly committed into the commitment layer, like bitcoin
/// blockchain or current state of the lightning channel).
///
/// All consignments-related procedures, including validation or merging
/// consignments data into stash or schema-specific data storage, must start
/// with `endpoints` and process up to the genesis.
#[derive(Clone, Debug)]
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

    #[inline]
    pub fn unsigned_bindle(self) -> Bindle<Self>
    where Self: BindleContent {
        Bindle::new(self)
    }
}
