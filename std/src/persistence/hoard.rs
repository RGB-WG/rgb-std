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

use std::convert::Infallible;

use amplify::confinement::{SmallOrdMap, TinyOrdMap};
use rgb::{ContractId, Genesis, SchemaId};

use crate::containers::{ContentId, ContentSigs, Contract};
use crate::interface::{rgb20, Iface, IfaceId, SchemaIfaces};
use crate::persistence::{Stash, StashError, StashInconsistency};
use crate::LIB_NAME_RGB_STD;

/// Hoard is an in-memory stash useful for WASM implementations.
#[derive(Clone, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, dumb = Hoard::preset())]
pub struct Hoard {
    pub(super) schemata: TinyOrdMap<SchemaId, SchemaIfaces>,
    pub(super) ifaces: TinyOrdMap<IfaceId, Iface>,
    pub(super) contracts: TinyOrdMap<ContractId, Contract>,
    pub(super) sigs: SmallOrdMap<ContentId, ContentSigs>,
}

impl Hoard {
    pub fn preset() -> Self {
        let rgb20 = rgb20();
        let rgb20_id = rgb20.iface_id();
        Hoard {
            schemata: Default::default(),
            ifaces: tiny_bmap! {
                rgb20_id => rgb20,
            },
            contracts: Default::default(),
            sigs: Default::default(),
        }
    }

    pub fn contract(&self, id: ContractId) -> Result<&Contract, StashInconsistency> {
        self.contracts
            .get(&id)
            .ok_or(StashInconsistency::ContractAbsent(id))
    }
}

impl Stash for Hoard {
    // With in-memory data we have no connectivity or I/O errors
    type Error = Infallible;

    fn iface_by_name(&self, name: &str) -> Result<&Iface, StashError<Self::Error>> {
        self.ifaces
            .values()
            .find(|iface| iface.name.as_str() == name)
            .ok_or_else(|| StashInconsistency::IfaceNameAbsent(name.to_owned()).into())
    }
    fn iface_by_id(&self, id: IfaceId) -> Result<&Iface, StashError<Self::Error>> {
        self.ifaces
            .get(&id)
            .ok_or_else(|| StashInconsistency::IfaceAbsent(id).into())
    }

    fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, StashError<Self::Error>> {
        self.schemata
            .get(&schema_id)
            .ok_or_else(|| StashInconsistency::SchemaAbsent(schema_id).into())
    }

    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, StashError<Self::Error>> {
        Ok(&self.contract(contract_id)?.genesis)
    }

    /*
    fn anchor_by_bundle(
        &self,
        contract_id: ContractId,
        bundle_id: BundleId,
    ) -> Result<&Anchor<MerkleProof>, StashError<Self::Error>> {
        Ok(&self
            .contract(contract_id)?
            .anchored_bundle(bundle_id)
            .ok_or(StashInconsistency::BundleAbsent(contract_id, bundle_id))?
            .anchor)
    }

    fn bundle_by_id(
        &self,
        contract_id: ContractId,
        bundle_id: BundleId,
    ) -> Result<&TransitionBundle, StashError<Self::Error>> {
        self.contract(contract_id)?
            .bundle_by_id(bundle_id)
            .ok_or_else(|| StashInconsistency::BundleAbsent(contract_id, bundle_id).into())
    }
     */
}
