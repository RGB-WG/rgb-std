// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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
use std::ops::{Deref, DerefMut};

use amplify::confinement::{LargeVec, MediumBlob, SmallOrdMap, SmallVec, TinyOrdMap};
use rgb::{
    AttachId, ContractHistory, ContractId, Extension, Genesis, Operation, OrderedTxid, Schema,
    SchemaId, SubSchema,
};
use strict_encoding::{StrictDeserialize, StrictDumb, StrictSerialize};

use super::{AnchoredBundle, ContainerVer, ContentId, ContentSigs, Terminal};
use crate::interface::{IfaceId, IfacePair};
use crate::resolvers::HeightResolver;
use crate::LIB_NAME_RGB_STD;

pub type VerifiedTransfer = VerifiedConsignment<true>;
pub type VerifiedContract = VerifiedConsignment<false>;

/// Wrapper around consignments providing type safety.
///
/// The type is an in-memory only, such that consignments read from a disk or a
/// network are always treated as non-verified.
// TODO: Instead of a dedicated type use a verification status field in Consignment which will not
//       be serialized/deserialized. Requires support for skipped fields in strict encoding derives.
#[derive(Clone, PartialEq, Eq, Debug, From)]
pub struct VerifiedConsignment<const TYPE: bool>(Consignment<TYPE>);

impl<const TYPE: bool> VerifiedConsignment<TYPE> {
    pub fn unbox(self) -> Consignment<TYPE> { self.0 }
}
impl<const TYPE: bool> Deref for VerifiedConsignment<TYPE> {
    type Target = Consignment<TYPE>;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl<const TYPE: bool> DerefMut for VerifiedConsignment<TYPE> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

pub type Transfer = Consignment<true>;
pub type Contract = Consignment<false>;

/// Consignment represents contract-specific data, always starting with genesis,
/// which must be valid under client-side-validation rules (i.e. internally
/// consistent and properly committed into the commitment layer, like bitcoin
/// blockchain or current state of the lightning channel).
///
/// All consignments-related procedures, including validation or merging
/// consignments data into stash or schema-specific data storage, must start
/// with `endpoints` and process up to the genesis. If any of the nodes within
/// the consignments are not part of the paths connecting endpoints with the
/// genesis, consignments validation will return
/// [`crate::validation::Warning::ExcessiveNode`] warning.
#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Consignment<const TYPE: bool> {
    /// Version.
    pub version: ContainerVer,

    /// Specifies whether the consignment contains information about state
    /// transfer (true), or it is just a consignment with an information about a
    /// contract.
    pub transfer: bool,

    /// Schema (plus root schema, if any) under which contract is issued.
    pub schema: SubSchema,

    /// Interfaces supported by the contract.
    pub ifaces: TinyOrdMap<IfaceId, IfacePair>,

    /// Genesis data.
    pub genesis: Genesis,

    /// Set of seals which are history terminals.
    pub terminals: SmallVec<Terminal>,

    /// Data on all anchored state transitions contained in the consignments.
    pub bundles: LargeVec<AnchoredBundle>,

    /// Data on all state extensions contained in the consignments.
    pub extensions: LargeVec<Extension>,

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
    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.schema.schema_id() }

    #[inline]
    pub fn root_schema_id(&self) -> Option<SchemaId> {
        self.schema.subset_of.as_ref().map(Schema::schema_id)
    }

    #[inline]
    pub fn contract_id(&self) -> ContractId { self.genesis.contract_id() }

    pub fn build_history<R: HeightResolver>(
        &self,
        resolver: &mut R,
    ) -> Result<ContractHistory, R::Error> {
        let mut history = ContractHistory::with(
            self.schema_id(),
            self.root_schema_id(),
            self.contract_id(),
            &self.genesis,
        );

        let mut extension_idx = self
            .extensions
            .iter()
            .map(Extension::id)
            .zip(iter::repeat(false))
            .collect::<BTreeMap<_, _>>();
        let mut ordered_extensions = BTreeMap::new();
        for anchored_bundle in &self.bundles {
            for item in anchored_bundle.bundle.values() {
                if let Some(transition) = &item.transition {
                    let txid = anchored_bundle.anchor.txid;
                    let height = resolver.resolve_height(txid)?;
                    let ord_txid = OrderedTxid::new(height, txid);
                    history.add_transition(transition, ord_txid);
                    for (id, used) in &mut extension_idx {
                        if *used {
                            continue;
                        }
                        for inp_id in transition.inputs.keys() {
                            if inp_id == id {
                                *used = true;
                                if let Some(ord) = ordered_extensions.get_mut(id) {
                                    if *ord > ord_txid {
                                        *ord = ord_txid;
                                    }
                                } else {
                                    ordered_extensions.insert(*id, ord_txid);
                                }
                            }
                        }
                    }
                }
            }
        }
        for extension in &self.extensions {
            if let Some(ord_txid) = ordered_extensions.get(&extension.id()) {
                history.add_extension(extension, *ord_txid);
            }
        }

        Ok(history)
    }
}
