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

use amplify::confinement::{LargeVec, MediumBlob, SmallOrdMap, SmallVec, TinyOrdMap};
use rgb::{AttachId, ContractId, Extension, Genesis, Schema, SchemaId};
use strict_encoding::StrictDumb;

use super::{AnchoredBundle, ContainerVer, SignedBy, Terminal};
use crate::interface::{IfaceId, IfacePair};
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
    pub schema: Schema,

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
    pub signatures: SignedBy,
}

impl<const TYPE: bool> Consignment<TYPE> {
    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.schema.schema_id() }

    #[inline]
    pub fn root_schema_id(&self) -> Option<SchemaId> {
        self.schema.subset_of.as_deref().map(Schema::schema_id)
    }

    #[inline]
    pub fn contract_id(&self) -> ContractId { self.genesis.contract_id() }
}
