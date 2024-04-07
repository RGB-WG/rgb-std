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
use std::convert::Infallible;

use amplify::confinement;
use amplify::confinement::{Confined, LargeOrdMap, SmallOrdMap, TinyOrdMap, TinyOrdSet};
use bp::dbc::anchor::MergeError;
use bp::dbc::tapret::TapretCommitment;
use commit_verify::{mpc, CommitId};
use rgb::{
    AnchorSet, AssetTag, AssignmentType, BundleId, ContractId, Extension, Genesis, OpId, Operation,
    SchemaId, TransitionBundle, XWitnessId,
};
use strict_encoding::TypeName;

use crate::accessors::{MergeReveal, MergeRevealError};
use crate::containers::{BundledWitness, Cert, Consignment, ContentId, ContentSigs, SealWitness};
use crate::interface::{
    rgb20, rgb21, rgb25, ContractSuppl, Iface, IfaceClass, IfaceId, IfacePair, Rgb20, Rgb21, Rgb25,
    SchemaIfaces,
};
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

    /// bundle {1} for contract {0} contains invalid transitioon input map
    #[display(doc_comments)]
    InvalidBundle(ContractId, BundleId),
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
    pub(super) witnesses: LargeOrdMap<XWitnessId, SealWitness>,
    pub(super) sigs: SmallOrdMap<ContentId, ContentSigs>,
}

impl Hoard {
    pub fn preset() -> Self {
        let rgb20 = Rgb20::iface(rgb20::Features::all());
        let rgb20_id = rgb20.iface_id();
        let rgb21 = Rgb21::iface(rgb21::Features::all());
        let rgb21_id = rgb21.iface_id();
        let rgb25 = Rgb25::iface(rgb25::Features::all());
        let rgb25_id = rgb25.iface_id();
        Hoard {
            schemata: none!(),
            ifaces: tiny_bmap! {
                rgb20_id => rgb20,
                rgb21_id => rgb21,
                rgb25_id => rgb25,
            },
            geneses: none!(),
            suppl: none!(),
            asset_tags: none!(),
            bundles: none!(),
            extensions: none!(),
            witnesses: none!(),
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

        for BundledWitness {
            pub_witness,
            anchored_bundles,
        } in consignment.bundles
        {
            // TODO: Save pub witness transaction and SPVs
            let anchor_set = anchored_bundles.to_anchor_set();
            for bundle in anchored_bundles.into_bundles() {
                let bundle_id = bundle.bundle_id();
                self.consume_bundle(bundle)?;
                let anchor = anchor_set.to_merkle_block(contract_id, bundle_id)?;
                self.consume_witness(SealWitness {
                    public: pub_witness.clone(),
                    anchor,
                })?;
            }
        }

        for (content_id, sigs) in consignment.signatures {
            // Do not bother if we can't import all the sigs
            self.import_sigs_internal(content_id, sigs).ok();
        }

        // Update asset tags
        self.asset_tags
            .insert(contract_id, consignment.asset_tags)?;

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
    pub fn consume_witness(&mut self, witness: SealWitness) -> Result<(), ConsumeError> {
        let witness_id = witness.witness_id();
        match self.witnesses.get_mut(&witness_id) {
            Some(w) => {
                w.public = w.public.clone().merge_reveal(witness.public)?;
                w.anchor = w.anchor.clone().merge_reveal(witness.anchor)?;
            }
            None => {
                self.witnesses.insert(witness_id, witness)?;
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

    fn contract_suppl(&self, contract_id: ContractId) -> Option<&ContractSuppl> {
        // TODO: select supplement basing on the signer trust level
        self.contract_suppl_all(contract_id)
            .and_then(|set| set.first())
    }

    fn contract_suppl_all(&self, contract_id: ContractId) -> Option<&TinyOrdSet<ContractSuppl>> {
        self.suppl.get(&contract_id)
    }

    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, StashError<Self::Error>> {
        self.geneses
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id).into())
    }

    fn witness_ids(&self) -> Result<BTreeSet<XWitnessId>, Self::Error> {
        Ok(self.witnesses.keys().copied().collect())
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

    fn anchor(
        &self,
        witness_id: XWitnessId,
    ) -> Result<AnchorSet<mpc::MerkleBlock>, StashError<Self::Error>> {
        let witness = self
            .witnesses
            .get(&witness_id)
            .ok_or(StashInconsistency::AnchorAbsent(witness_id))?
            .clone();
        Ok(witness.anchor)
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

    fn taprets(&self) -> Result<BTreeMap<XWitnessId, TapretCommitment>, StashError<Self::Error>> {
        Ok(self
            .witnesses
            .iter()
            .filter_map(|(witness_id, witness)| match &witness.anchor {
                AnchorSet::Tapret(tapret) | AnchorSet::Dual { tapret, .. } => {
                    Some((*witness_id, tapret))
                }
                AnchorSet::Opret(_) => None,
            })
            .map(|(witness_id, tapret)| {
                (witness_id, TapretCommitment {
                    mpc: tapret.mpc_proof.commit_id(),
                    nonce: tapret.dbc_proof.path_proof.nonce(),
                })
            })
            .collect())
    }
}
