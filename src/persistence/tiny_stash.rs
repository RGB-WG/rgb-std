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

use std::collections::BTreeSet;
use std::convert::Infallible;

use aluvm::library::{Lib, LibId};
use amplify::confinement;
use amplify::confinement::{
    Confined, LargeOrdMap, MediumBlob, SmallOrdMap, TinyOrdMap, TinyOrdSet,
};
use bp::dbc::tapret::TapretCommitment;
use commit_verify::CommitId;
use rgb::{
    AttachId, BundleId, ContractId, Extension, Genesis, OpId, Operation, Schema, SchemaId,
    TransitionBundle, XWitnessId,
};
use strict_encoding::TypeName;
use strict_types::TypeSystem;

use crate::containers::{AnchorSet, Cert, ContentId, ContentSigs, SealWitness};
use crate::interface::{ContractSuppl, Iface, IfaceId, IfaceImpl, IfaceRef};
use crate::persistence::{
    SchemaIfaces, StashInconsistency, StashProvider, StashProviderError as ProviderError,
    StashReadProvider, StashWriteProvider,
};
use crate::LIB_NAME_RGB_STD;

/// Hoard is an in-memory stash useful for WASM implementations.
#[derive(Clone, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct TinyStash {
    schemata: TinyOrdMap<SchemaId, SchemaIfaces>,
    ifaces: TinyOrdMap<IfaceId, Iface>,
    geneses: TinyOrdMap<ContractId, Genesis>,
    suppl: TinyOrdMap<ContractId, TinyOrdSet<ContractSuppl>>,
    bundles: LargeOrdMap<BundleId, TransitionBundle>,
    extensions: LargeOrdMap<OpId, Extension>,
    witnesses: LargeOrdMap<XWitnessId, SealWitness>,
    attachments: SmallOrdMap<AttachId, MediumBlob>,
    type_system: TypeSystem,
    libs: SmallOrdMap<LibId, Lib>,
    sigs: SmallOrdMap<ContentId, ContentSigs>,
}

impl TinyStash {
    pub fn new() -> Self { TinyStash::default() }
}

impl StashProvider for TinyStash {}

impl StashReadProvider for TinyStash {
    // With in-memory data we have no connectivity or I/O errors
    type Error = Infallible;

    fn type_system(&self) -> Result<&TypeSystem, Self::Error> { Ok(&self.type_system) }

    fn lib(&self, id: LibId) -> Result<&Lib, ProviderError<Self::Error>> {
        self.libs
            .get(&id)
            .ok_or_else(|| StashInconsistency::LibAbsent(id).into())
    }

    fn ifaces(&self) -> Result<impl Iterator<Item = (IfaceId, TypeName)>, Self::Error> {
        Ok(self
            .ifaces
            .iter()
            .map(|(id, iface)| (*id, iface.name.clone())))
    }

    fn iface(&self, iface: impl Into<IfaceRef>) -> Result<&Iface, ProviderError<Self::Error>> {
        let iref = iface.into();
        match iref {
            IfaceRef::Name(ref name) => self.ifaces.values().find(|iface| &iface.name == name),
            IfaceRef::Id(ref id) => self.ifaces.get(id),
        }
        .ok_or_else(|| StashInconsistency::IfaceAbsent(iref).into())
    }

    fn schema_ids(&self) -> Result<impl Iterator<Item = SchemaId>, Self::Error> {
        Ok(self.schemata.keys().copied())
    }

    fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, ProviderError<Self::Error>> {
        self.schemata
            .get(&schema_id)
            .ok_or_else(|| StashInconsistency::SchemaAbsent(schema_id).into())
    }

    fn contract_ids(&self) -> Result<impl Iterator<Item = ContractId>, Self::Error> {
        Ok(self.geneses.keys().copied())
    }

    fn contract_ids_by_iface(
        &self,
        iface: impl Into<IfaceRef>,
    ) -> Result<impl Iterator<Item = ContractId>, ProviderError<Self::Error>> {
        let iface = self.iface(iface)?;
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
            .filter(move |(_, genesis)| schemata.contains(&genesis.schema_id))
            .map(|(contract_id, _)| contract_id)
            .copied())
    }

    fn contract_supplements(
        &self,
        contract_id: ContractId,
    ) -> Result<impl Iterator<Item = ContractSuppl>, Self::Error> {
        Ok(self
            .suppl
            .get(&contract_id)
            .cloned()
            .unwrap_or_default()
            .into_iter())
    }

    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, ProviderError<Self::Error>> {
        self.geneses
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id).into())
    }

    fn witness_ids(&self) -> Result<impl Iterator<Item = XWitnessId>, Self::Error> {
        Ok(self.witnesses.keys().copied())
    }

    fn bundle_ids(&self) -> Result<impl Iterator<Item = BundleId>, Self::Error> {
        Ok(self.bundles.keys().copied())
    }

    fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, ProviderError<Self::Error>> {
        self.bundles
            .get(&bundle_id)
            .ok_or(StashInconsistency::BundleAbsent(bundle_id).into())
    }

    fn extension_ids(&self) -> Result<impl Iterator<Item = OpId>, Self::Error> {
        Ok(self.extensions.keys().copied())
    }

    fn extension(&self, op_id: OpId) -> Result<&Extension, ProviderError<Self::Error>> {
        self.extensions
            .get(&op_id)
            .ok_or(StashInconsistency::OperationAbsent(op_id).into())
    }

    fn witness(&self, witness_id: XWitnessId) -> Result<&SealWitness, ProviderError<Self::Error>> {
        self.witnesses
            .get(&witness_id)
            .ok_or(StashInconsistency::WitnessAbsent(witness_id).into())
    }

    fn taprets(&self) -> Result<impl Iterator<Item = (XWitnessId, TapretCommitment)>, Self::Error> {
        Ok(self
            .witnesses
            .iter()
            .filter_map(|(witness_id, witness)| match &witness.anchors {
                AnchorSet::Tapret(anchor) |
                AnchorSet::Double {
                    tapret: anchor,
                    opret: _,
                } => Some((*witness_id, TapretCommitment {
                    mpc: anchor.mpc_proof.commit_id(),
                    nonce: anchor.dbc_proof.path_proof.nonce(),
                })),
                _ => None,
            }))
    }
}

impl StashWriteProvider for TinyStash {
    type Error = confinement::Error;

    fn replace_schema(&mut self, schema: Schema) -> Result<bool, confinement::Error> {
        let schema_id = schema.schema_id();
        if !self.schemata.contains_key(&schema_id) {
            self.schemata.insert(schema_id, SchemaIfaces::new(schema))?;
            return Ok(true);
        }
        Ok(false)
    }

    fn replace_iface(&mut self, iface: Iface) -> Result<bool, confinement::Error> {
        let iface_id = iface.iface_id();
        if !self.ifaces.contains_key(&iface_id) {
            self.ifaces.insert(iface_id, iface)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn replace_iimpl(&mut self, iimpl: IfaceImpl) -> Result<bool, confinement::Error> {
        let schema_ifaces = self
            .schemata
            .get_mut(&iimpl.schema_id)
            .expect("unknown schema");
        let present = schema_ifaces.iimpls.contains_key(&iimpl.iface_id);
        schema_ifaces.iimpls.insert(iimpl.iface_id, iimpl)?;
        Ok(!present)
    }

    fn add_suppl(&mut self, suppl: ContractSuppl) -> Result<(), confinement::Error> {
        match self.suppl.get_mut(&suppl.contract_id) {
            None => {
                self.suppl
                    .insert(suppl.contract_id, confined_bset![suppl])?;
            }
            Some(suppls) => suppls.push(suppl)?,
        }
        Ok(())
    }

    fn replace_genesis(&mut self, genesis: Genesis) -> Result<bool, confinement::Error> {
        let contract_id = genesis.contract_id();
        let present = self.geneses.insert(contract_id, genesis)?.is_some();
        Ok(!present)
    }

    fn replace_extension(&mut self, extension: Extension) -> Result<bool, confinement::Error> {
        let opid = extension.id();
        let present = self.extensions.insert(opid, extension)?.is_some();
        Ok(!present)
    }

    fn replace_bundle(&mut self, bundle: TransitionBundle) -> Result<bool, confinement::Error> {
        let bundle_id = bundle.bundle_id();
        let present = self.bundles.insert(bundle_id, bundle)?.is_some();
        Ok(!present)
    }

    fn replace_witness(&mut self, witness: SealWitness) -> Result<bool, confinement::Error> {
        let witness_id = witness.witness_id();
        let present = self.witnesses.insert(witness_id, witness)?.is_some();
        Ok(!present)
    }

    fn replace_attachment(
        &mut self,
        id: AttachId,
        attach: MediumBlob,
    ) -> Result<bool, confinement::Error> {
        let present = self.attachments.insert(id, attach)?.is_some();
        Ok(!present)
    }

    fn consume_types(&mut self, types: TypeSystem) -> Result<(), confinement::Error> {
        self.type_system.extend(types)
    }

    fn replace_lib(&mut self, lib: Lib) -> Result<bool, confinement::Error> {
        let present = self.libs.insert(lib.id(), lib)?.is_some();
        Ok(!present)
    }

    fn import_sigs<I>(&mut self, content_id: ContentId, sigs: I) -> Result<(), confinement::Error>
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
}
