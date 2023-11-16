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

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use amplify::confinement;
use amplify::confinement::{Confined, LargeOrdMap, SmallOrdMap, TinyOrdMap, TinyOrdSet};
use bp::dbc::anchor::MergeError;
use commit_verify::mpc;
use rgb::{
    Anchor, AnchorId, AnchoredBundle, AssetTag, AssignmentType, BundleId, ContractId, Extension,
    Genesis, OpId, Operation, SchemaId, TransitionBundle,
};
use strict_encoding::TypeName;

use crate::accessors::{MergeReveal, MergeRevealError};
use crate::containers::{Cert, Consignment, ContentId, ContentSigs};
use crate::interface::{rgb20, ContractSuppl, Iface, IfaceId, IfacePair, SchemaIfaces};
use crate::persistence::{InventoryError, Stash, StashError, StashInconsistency};
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum ConsumeError {
    #[from]
    Confinement(confinement::Error),

    #[from]
    Anchor(mpc::InvalidProof),

    #[from]
    Merge(MergeError),

    #[from]
    MergeReveal(MergeRevealError),
}

impl From<Infallible> for InventoryError<Infallible> {
    fn from(_: Infallible) -> Self { unreachable!() }
}

/// Hoard is an in-memory stash useful for WASM implementations.
#[derive(Clone, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, dumb = Hoard::preset())]
pub struct Hoard {
    pub(super) schemata: TinyOrdMap<SchemaId, SchemaIfaces>,
    pub(super) ifaces: TinyOrdMap<IfaceId, Iface>,
    pub(super) geneses: TinyOrdMap<ContractId, Genesis>,
    pub(super) suppl: TinyOrdMap<ContractId, TinyOrdSet<ContractSuppl>>,
    pub(super) asset_tags: TinyOrdMap<ContractId, TinyOrdMap<AssignmentType, AssetTag>>,
    pub(super) bundles: LargeOrdMap<BundleId, TransitionBundle>,
    pub(super) extensions: LargeOrdMap<OpId, Extension>,
    pub(super) anchors: LargeOrdMap<AnchorId, Anchor<mpc::MerkleBlock>>,
    pub(super) sigs: SmallOrdMap<ContentId, ContentSigs>,
}

impl Hoard {
    pub fn preset() -> Self {
        let rgb20 = rgb20();
        let rgb20_id = rgb20.iface_id();
        Hoard {
            schemata: none!(),
            ifaces: tiny_bmap! {
                rgb20_id => rgb20,
            },
            geneses: none!(),
            suppl: none!(),
            asset_tags: none!(),
            bundles: none!(),
            extensions: none!(),
            anchors: none!(),
            sigs: none!(),
        }
    }

    pub(super) fn import_sigs_internal<I>(
        &mut self,
        content_id: ContentId,
        sigs: I,
    ) -> Result<(), confinement::Error>
    where
        I: IntoIterator<Item = Cert>,
        I::IntoIter: ExactSizeIterator<Item = Cert>,
    {
        let sigs = sigs.into_iter();
        if sigs.len() > 0 {
            if let Some(prev_sigs) = self.sigs.get_mut(&content_id) {
                prev_sigs.extend(sigs)?;
            } else {
                let sigs = Confined::try_from_iter(sigs)?;
                self.sigs.insert(content_id, ContentSigs::from(sigs)).ok();
            }
        }
        Ok(())
    }

    // TODO: Move into Stash trait and re-implement using trait accessor methods
    pub fn consume_consignment<const TYPE: bool>(
        &mut self,
        consignment: Consignment<TYPE>,
    ) -> Result<(), ConsumeError> {
        let contract_id = consignment.contract_id();
        let schema_id = consignment.schema_id();

        let iimpls = match self.schemata.get_mut(&schema_id) {
            Some(si) => &mut si.iimpls,
            None => {
                self.schemata
                    .insert(schema_id, SchemaIfaces::new(consignment.schema))?;
                &mut self
                    .schemata
                    .get_mut(&schema_id)
                    .expect("just inserted")
                    .iimpls
            }
        };

        for (iface_id, IfacePair { iface, iimpl }) in consignment.ifaces {
            if !self.ifaces.contains_key(&iface_id) {
                self.ifaces.insert(iface_id, iface)?;
            };
            // TODO: Update for newer implementations
            if !iimpls.contains_key(&iface_id) {
                iimpls.insert(iface_id, iimpl)?;
            };
        }

        // TODO: filter most trusted signers
        match self.suppl.get_mut(&contract_id) {
            Some(entry) => {
                entry.extend(consignment.supplements).ok();
            }
            None => {
                self.suppl.insert(contract_id, consignment.supplements).ok();
            }
        }

        match self.geneses.get_mut(&contract_id) {
            Some(genesis) => *genesis = genesis.clone().merge_reveal(consignment.genesis)?,
            None => {
                self.geneses.insert(contract_id, consignment.genesis)?;
            }
        }

        for extension in consignment.extensions {
            let opid = extension.id();
            match self.extensions.get_mut(&opid) {
                Some(e) => *e = e.clone().merge_reveal(extension)?,
                None => {
                    self.extensions.insert(opid, extension)?;
                }
            }
        }

        for AnchoredBundle { anchor, bundle } in consignment.bundles {
            let bundle_id = bundle.bundle_id();
            let anchor = anchor.map(|a| a.into_merkle_block(contract_id, bundle_id.into()))?;
            self.consume_anchor(anchor)?;
            self.consume_bundle(bundle)?;
        }

        for (content_id, sigs) in consignment.signatures {
            // Do not bother if we can't import all the sigs
            self.import_sigs_internal(content_id, sigs).ok();
        }

        // Update asset tags
        self.asset_tags
            .insert(contract_id, consignment.asset_tags.clone())?;

        Ok(())
    }

    // TODO: Move into Stash trait and re-implement using trait accessor methods
    pub fn consume_bundle(&mut self, bundle: TransitionBundle) -> Result<(), ConsumeError> {
        let bundle_id = bundle.bundle_id();
        match self.bundles.get_mut(&bundle_id) {
            Some(b) => *b = b.clone().merge_reveal(bundle)?,
            None => {
                self.bundles.insert(bundle_id, bundle)?;
            }
        }
        Ok(())
    }

    // TODO: Move into Stash trait and re-implement using trait accessor methods
    pub fn consume_anchor(&mut self, anchor: Anchor<mpc::MerkleBlock>) -> Result<(), ConsumeError> {
        let anchor_id = anchor.anchor_id();
        match self.anchors.get_mut(&anchor_id) {
            Some(a) => *a = a.clone().merge_reveal(anchor)?,
            None => {
                self.anchors.insert(anchor_id, anchor)?;
            }
        }
        Ok(())
    }
}

impl Stash for Hoard {
    // With in-memory data we have no connectivity or I/O errors
    type Error = Infallible;

    fn ifaces(&self) -> Result<BTreeMap<IfaceId, TypeName>, Self::Error> {
        Ok(self
            .ifaces
            .iter()
            .map(|(id, iface)| (*id, iface.name.clone()))
            .collect())
    }

    fn iface_by_name(&self, name: &TypeName) -> Result<&Iface, StashError<Self::Error>> {
        self.ifaces
            .values()
            .find(|iface| &iface.name == name)
            .ok_or_else(|| StashInconsistency::IfaceNameAbsent(name.clone()).into())
    }
    fn iface_by_id(&self, id: IfaceId) -> Result<&Iface, StashError<Self::Error>> {
        self.ifaces
            .get(&id)
            .ok_or_else(|| StashInconsistency::IfaceAbsent(id).into())
    }

    fn schema_ids(&self) -> Result<BTreeSet<SchemaId>, Self::Error> {
        Ok(self.schemata.keys().copied().collect())
    }

    fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, StashError<Self::Error>> {
        self.schemata
            .get(&schema_id)
            .ok_or_else(|| StashInconsistency::SchemaAbsent(schema_id).into())
    }

    fn contract_ids_by_iface(&self, name: &TypeName) -> Result<BTreeSet<ContractId>, Self::Error> {
        let iface = self.iface_by_name(name).unwrap();
        let iface_id = iface.iface_id();
        let schemata = self
            .schemata
            .iter()
            .filter(|(_, iface)| iface.iimpls.contains_key(&iface_id))
            .map(|(schema_id, _)| schema_id)
            .collect::<BTreeSet<_>>();
        Ok(self
            .geneses
            .iter()
            .filter(|(_, genesis)| schemata.contains(&genesis.schema_id))
            .map(|(contract_id, _)| contract_id)
            .copied()
            .collect())
    }

    fn contract_ids(&self) -> Result<BTreeSet<ContractId>, Self::Error> {
        Ok(self.geneses.keys().copied().collect())
    }

    fn contract_suppl(&self, contract_id: ContractId) -> Option<&TinyOrdSet<ContractSuppl>> {
        self.suppl.get(&contract_id)
    }

    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, StashError<Self::Error>> {
        self.geneses
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id).into())
    }

    fn bundle_ids(&self) -> Result<BTreeSet<BundleId>, Self::Error> {
        Ok(self.bundles.keys().copied().collect())
    }

    fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, StashError<Self::Error>> {
        self.bundles
            .get(&bundle_id)
            .ok_or(StashInconsistency::BundleAbsent(bundle_id).into())
    }

    fn extension_ids(&self) -> Result<BTreeSet<OpId>, Self::Error> {
        Ok(self.extensions.keys().copied().collect())
    }

    fn extension(&self, op_id: OpId) -> Result<&Extension, StashError<Self::Error>> {
        self.extensions
            .get(&op_id)
            .ok_or(StashInconsistency::OperationAbsent(op_id).into())
    }

    fn anchor_ids(&self) -> Result<BTreeSet<AnchorId>, Self::Error> {
        Ok(self.anchors.keys().copied().collect())
    }

    fn anchor(
        &self,
        anchor_id: AnchorId,
    ) -> Result<&Anchor<mpc::MerkleBlock>, StashError<Self::Error>> {
        self.anchors
            .get(&anchor_id)
            .ok_or(StashInconsistency::AnchorAbsent(anchor_id).into())
    }

    fn contract_asset_tags(
        &self,
        contract_id: ContractId,
    ) -> Result<&TinyOrdMap<AssignmentType, AssetTag>, StashError<Self::Error>> {
        self.asset_tags
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id))
            .map_err(StashError::from)
    }
}
