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

//use crate::containers::{Consignment, Contract, Transfer};

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Debug;

use aluvm::library::{Lib, LibId};
use amplify::confinement::{Confined, MediumBlob, TinyOrdMap};
use bp::dbc::anchor::MergeError;
use bp::dbc::tapret::TapretCommitment;
use commit_verify::mpc;
use rgb::validation::Scripts;
use rgb::{
    AssetTag, AssignmentType, AttachId, BundleId, ContractId, Extension, Genesis, OpId, Operation,
    Schema, SchemaId, TransitionBundle, XWitnessId,
};
use strict_encoding::{FieldName, TypeName};
use strict_types::typesys::UnknownType;
use strict_types::TypeSystem;

use crate::accessors::{MergeReveal, MergeRevealError};
use crate::containers::{
    BundledWitness, Cert, Consignment, ContentId, Kit, SealWitness, ToWitnessId,
};
use crate::interface::{
    ContractBuilder, ContractSuppl, Iface, IfaceId, IfaceImpl, IfaceRef, TransitionBuilder,
};
use crate::LIB_NAME_RGB_STD;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum StashError<P: StashProvider> {
    /// Connectivity errors which may be recoverable and temporary.
    ReadProvider(<P as StashReadProvider>::Error),

    /// Connectivity errors which may be recoverable and temporary.
    WriteProvider(<P as StashWriteProvider>::Error),

    /// Errors caused by invalid input arguments.
    #[from]
    #[from(UnknownType)]
    #[from(MergeError)]
    #[from(MergeRevealError)]
    #[from(mpc::InvalidProof)]
    Data(StashDataError),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StashDataError {
    /// schema {0} and related interfaces use too many AluVM libraries.
    TooManyLibs(SchemaId),

    #[from]
    #[display(inner)]
    UnknownType(UnknownType),

    #[from]
    #[display(inner)]
    Anchor(mpc::InvalidProof),

    #[from]
    #[display(inner)]
    Merge(MergeError),

    #[from]
    #[display(inner)]
    MergeReveal(MergeRevealError),

    /// schema {0} doesn't implement interface {1}.
    NoIfaceImpl(SchemaId, IfaceId),
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SchemaIfaces {
    pub schema: Schema,
    pub iimpls: TinyOrdMap<IfaceId, IfaceImpl>,
}

impl SchemaIfaces {
    pub fn new(schema: Schema) -> Self {
        SchemaIfaces {
            schema,
            iimpls: none!(),
        }
    }
}

#[derive(Debug)]
pub struct Stash<P: StashProvider> {
    provider: P,
}

impl<P: StashProvider> Stash<P> {
    pub fn new(provider: P) -> Self { Self { provider } }

    pub fn iface(&self, iface: impl Into<IfaceRef>) -> Result<&Iface, StashError<P>> {
        self.provider.iface(iface).map_err(StashError::ReadProvider)
    }
    pub fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, StashError<P>> {
        self.provider
            .schema(schema_id)
            .map_err(StashError::ReadProvider)
    }
    pub fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, StashError<P>> {
        self.provider
            .genesis(contract_id)
            .map_err(StashError::ReadProvider)
    }
    pub fn contract_ids_by_iface(
        &self,
        iface: impl Into<IfaceRef>,
    ) -> Result<impl Iterator<Item = ContractId> + '_, StashError<P>> {
        self.provider
            .contract_ids_by_iface(iface.into())
            .map_err(StashError::ReadProvider)
    }
    pub fn contract_suppl(&self, contract_id: ContractId) -> Option<&ContractSuppl> {
        self.provider.contract_suppl(contract_id)
    }

    pub(crate) fn extract<'a>(
        &self,
        schema: &Schema,
        ifaces: impl IntoIterator<Item = &'a Iface>,
    ) -> Result<(TypeSystem, Scripts), StashError<P>> {
        let type_iter = schema
            .types()
            .chain(ifaces.into_iter().flat_map(Iface::types));
        let types = self
            .provider
            .type_system()
            .map_err(StashError::ReadProvider)?
            .extract(type_iter)?;

        let mut scripts = BTreeMap::new();
        for id in schema.libs() {
            let lib = self.provider.lib(id).map_err(StashError::ReadProvider)?;
            scripts.insert(id, lib.clone());
        }
        let scripts = Scripts::try_from(scripts)
            .map_err(|_| StashDataError::TooManyLibs(schema.schema_id()))?;

        Ok((types, scripts))
    }

    pub fn contract_builder(
        &self,
        schema_id: SchemaId,
        iface: impl Into<IfaceRef>,
    ) -> Result<ContractBuilder, StashError<P>> {
        let schema_ifaces = self.schema(schema_id)?;
        let iface = self.iface(iface)?;
        let iface_id = iface.iface_id();
        let iimpl = schema_ifaces
            .iimpls
            .get(&iface_id)
            .ok_or(StashDataError::NoIfaceImpl(schema_id, iface_id))?;

        let (types, scripts) = self.extract(&schema_ifaces.schema, [iface])?;

        let builder = ContractBuilder::with(
            iface.clone(),
            schema_ifaces.schema.clone(),
            iimpl.clone(),
            types,
            scripts,
        );
        Ok(builder)
    }

    pub fn transition_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
        transition_name: Option<impl Into<FieldName>>,
    ) -> Result<TransitionBuilder, StashError<P>> {
        let schema_ifaces = self
            .provider
            .contract_schema(contract_id)
            .map_err(StashError::ReadProvider)?;
        let iface = self.iface(iface)?;
        let schema = &schema_ifaces.schema;
        let iimpl = schema_ifaces
            .iimpls
            .get(&iface.iface_id())
            .ok_or(StashDataError::NoIfaceImpl(schema.schema_id(), iface.iface_id()))?;

        let (types, _) = self.extract(&schema_ifaces.schema, [iface])?;

        let mut builder = if let Some(transition_name) = transition_name {
            TransitionBuilder::named_transition(
                contract_id,
                iface.clone(),
                schema.clone(),
                iimpl.clone(),
                transition_name.into(),
                types,
            )
        } else {
            TransitionBuilder::default_transition(
                contract_id,
                iface.clone(),
                schema.clone(),
                iimpl.clone(),
                types,
            )
        }
        .expect("internal inconsistency");
        let tags = self
            .provider
            .contract_asset_tags(contract_id)
            .map_err(StashError::ReadProvider)?;
        for (assignment_type, asset_tag) in tags {
            builder = builder
                .add_asset_tag_raw(assignment_type, asset_tag)
                .expect("tags are in bset and must not repeat");
        }
        Ok(builder)
    }

    pub fn blank_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
    ) -> Result<TransitionBuilder, StashError<P>> {
        let schema_ifaces = self
            .provider
            .contract_schema(contract_id)
            .map_err(StashError::ReadProvider)?;
        let iface = self.iface(iface)?;
        let schema = &schema_ifaces.schema;
        if schema_ifaces.iimpls.is_empty() {
            return Err(StashDataError::NoIfaceImpl(schema.schema_id(), iface.iface_id()).into());
        }

        let (types, _) = self.extract(&schema_ifaces.schema, [iface])?;

        let mut builder = if let Some(iimpl) = schema_ifaces.iimpls.get(&iface.iface_id()) {
            TransitionBuilder::blank_transition(
                contract_id,
                iface.clone(),
                schema.clone(),
                iimpl.clone(),
                types,
            )
        } else {
            let (default_iface_id, default_iimpl) = schema_ifaces.iimpls.first_key_value().unwrap();
            let default_iface = self.iface(*default_iface_id)?;

            TransitionBuilder::blank_transition(
                contract_id,
                default_iface.clone(),
                schema.clone(),
                default_iimpl.clone(),
                types,
            )
        };
        let tags = self
            .provider
            .contract_asset_tags(contract_id)
            .map_err(StashError::ReadProvider)?;
        for (assignment_type, asset_tag) in tags {
            builder = builder
                .add_asset_tag_raw(assignment_type, asset_tag)
                .expect("tags are in bset and must not repeat");
        }

        Ok(builder)
    }

    pub fn consume_kit(&mut self, kit: Kit) -> Result<(), StashError<P>> {
        self.provider
            .consume_types(kit.types)
            .map_err(StashError::WriteProvider)?;
        for lib in kit.scripts {
            self.provider
                .consume_lib(lib)
                .map_err(StashError::WriteProvider)?;
        }

        // TODO: filter most trusted signers
        for schema in kit.schemata {
            self.provider
                .consume_schema(schema)
                .map_err(StashError::WriteProvider)?;
        }
        for iface in kit.ifaces {
            self.provider
                .consume_iface(iface)
                .map_err(StashError::WriteProvider)?;
        }
        for iimpl in kit.iimpls {
            self.provider
                .consume_iimpl(iimpl)
                .map_err(StashError::WriteProvider)?;
        }

        // TODO: filter out non-trusted signers
        for suppl in kit.supplements {
            self.provider
                .consume_suppl(suppl)
                .map_err(StashError::WriteProvider)?;
        }

        for (content_id, sigs) in kit.signatures {
            // TODO: Filter sigs by trust level
            // Do not bother if we can't import all the sigs
            self.provider.import_sigs(content_id, sigs).ok();
        }

        Ok(())
    }

    pub fn consume_consignment<const TYPE: bool>(
        &mut self,
        consignment: Consignment<TYPE>,
    ) -> Result<(), StashError<P>> {
        let contract_id = consignment.contract_id();

        let genesis = match self.genesis(contract_id) {
            Ok(g) => g.clone().merge_reveal(consignment.genesis)?,
            Err(_) => consignment.genesis,
        };
        self.provider
            .consume_genesis(genesis, consignment.asset_tags)
            .map_err(StashError::WriteProvider)?;

        for extension in consignment.extensions {
            let opid = extension.id();
            let extension = match self.provider.extension(opid) {
                Ok(e) => e.clone().merge_reveal(extension)?,
                Err(_) => extension,
            };
            self.provider
                .consume_extension(extension)
                .map_err(StashError::WriteProvider)?;
        }

        for bw in consignment.bundles {
            self.consume_bundled_witness(contract_id, bw)?;
        }

        for (id, attach) in consignment.attachments {
            self.provider
                .consume_attachment(id, attach)
                .map_err(StashError::WriteProvider)?;
        }

        let (ifaces, iimpls): (BTreeSet<_>, BTreeSet<_>) = consignment
            .ifaces
            .into_inner()
            .into_iter()
            .fold((bset!(), bset!()), |(mut keys, mut values), (k, v)| {
                keys.insert(k);
                values.insert(v);
                (keys, values)
            });
        self.consume_kit(Kit {
            version: consignment.version,
            ifaces: Confined::from_collection_unsafe(ifaces),
            schemata: tiny_bset![consignment.schema],
            iimpls: Confined::from_collection_unsafe(iimpls),
            supplements: consignment.supplements,
            types: consignment.types,
            scripts: Confined::from_collection_unsafe(consignment.scripts.into_inner()),
            signatures: consignment.signatures,
        })
    }

    fn consume_bundled_witness(
        &mut self,
        contract_id: ContractId,
        bundled_witness: BundledWitness,
    ) -> Result<(), StashError<P>> {
        let BundledWitness {
            mut pub_witness,
            anchored_bundles,
        } = bundled_witness;

        // TODO: Save pub witness transaction and SPVs

        let witness_id = pub_witness.to_witness_id();
        let anchor_set = anchored_bundles.to_anchor_set();

        let mut bundles = anchored_bundles.into_bundles();
        let mut bundle = bundles.next().expect("there always at least one bundle");
        let mut bundle_id = bundle.bundle_id();

        let mut anchor = anchor_set.to_merkle_block(contract_id, bundle_id)?;
        if let Ok(witness) = self.provider.witness(witness_id) {
            anchor = witness.anchor.clone().merge_reveal(anchor)?;
            pub_witness = witness.public.clone().merge_reveal(pub_witness)?;
        }

        loop {
            bundle = match self.provider.bundle(bundle_id) {
                Ok(b) => b.clone().merge_reveal(bundle)?,
                Err(_) => bundle,
            };
            self.provider
                .consume_bundle(bundle)
                .map_err(StashError::WriteProvider)?;
            match bundles.next() {
                Some(b) => {
                    bundle_id = b.bundle_id();
                    bundle = b;
                }
                None => break,
            };
        }

        self.provider
            .consume_witness(SealWitness {
                public: pub_witness,
                anchor,
            })
            .map_err(StashError::WriteProvider)?;

        Ok(())
    }
}

pub trait StashProvider: Debug + StashReadProvider + StashWriteProvider {}

pub trait StashReadProvider {
    /// Error type which must indicate problems on data retrieval.
    type Error: Error;

    fn type_system(&self) -> Result<&TypeSystem, Self::Error>;
    fn lib(&self, id: LibId) -> Result<&Lib, Self::Error>;
    fn schema_ids(&self) -> Result<impl Iterator<Item = SchemaId>, Self::Error>;
    fn ifaces(&self) -> Result<impl Iterator<Item = (IfaceId, TypeName)>, Self::Error>;
    fn iface(&self, iface: impl Into<IfaceRef>) -> Result<&Iface, Self::Error>;
    fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, Self::Error>;
    fn contract_ids(&self) -> Result<impl Iterator<Item = ContractId>, Self::Error>;
    fn contract_ids_by_iface(
        &self,
        iface: impl Into<IfaceRef>,
    ) -> Result<impl Iterator<Item = ContractId>, Self::Error>;
    fn contract_schema(&self, contract_id: ContractId) -> Result<&SchemaIfaces, Self::Error> {
        let genesis = self.genesis(contract_id)?;
        self.schema(genesis.schema_id)
    }
    fn contract_suppl(&self, contract_id: ContractId) -> Option<&ContractSuppl>;
    fn contract_suppl_all(
        &self,
        contract_id: ContractId,
    ) -> Option<impl Iterator<Item = &ContractSuppl>>;
    fn contract_asset_tags(
        &self,
        contract_id: ContractId,
    ) -> Result<impl Iterator<Item = (AssignmentType, AssetTag)>, Self::Error>;
    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, Self::Error>;
    fn witness_ids(&self) -> Result<impl Iterator<Item = XWitnessId>, Self::Error>;
    fn bundle_ids(&self) -> Result<impl Iterator<Item = BundleId>, Self::Error>;
    fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, Self::Error>;
    fn extension_ids(&self) -> Result<impl Iterator<Item = OpId>, Self::Error>;
    fn extension(&self, op_id: OpId) -> Result<&Extension, Self::Error>;
    fn witness(&self, witness_id: XWitnessId) -> Result<&SealWitness, Self::Error>;
    fn taprets(&self) -> Result<impl Iterator<Item = (XWitnessId, TapretCommitment)>, Self::Error>;
}

pub trait StashWriteProvider {
    type Error: Error;

    fn consume_schema(&mut self, schema: Schema) -> Result<bool, Self::Error>;
    fn consume_iface(&mut self, iface: Iface) -> Result<bool, Self::Error>;
    fn consume_iimpl(&mut self, iimpl: IfaceImpl) -> Result<bool, Self::Error>;
    fn consume_suppl(&mut self, suppl: ContractSuppl) -> Result<bool, Self::Error>;
    fn consume_genesis(
        &mut self,
        genesis: Genesis,
        asset_tags: TinyOrdMap<AssignmentType, AssetTag>,
    ) -> Result<bool, Self::Error>;
    fn consume_extension(&mut self, extension: Extension) -> Result<bool, Self::Error>;
    fn consume_bundle(&mut self, bundle: TransitionBundle) -> Result<bool, Self::Error>;
    fn consume_witness(&mut self, witness: SealWitness) -> Result<bool, Self::Error>;
    fn consume_attachment(&mut self, id: AttachId, attach: MediumBlob)
    -> Result<bool, Self::Error>;
    fn consume_types(&mut self, types: TypeSystem) -> Result<(), Self::Error>;
    fn consume_lib(&mut self, lib: Lib) -> Result<bool, Self::Error>;
    fn import_sigs<I>(&mut self, content_id: ContentId, sigs: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Cert>,
        I::IntoIter: ExactSizeIterator<Item = Cert>;
}
