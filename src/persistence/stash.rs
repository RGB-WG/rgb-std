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
use std::error::Error;
use std::fmt::Debug;

use aluvm::library::{Lib, LibId};
use amplify::confinement::{Confined, MediumBlob, TinyOrdMap};
use bp::dbc::anchor::MergeError;
use bp::dbc::tapret::TapretCommitment;
use commit_verify::mpc;
use rgb::validation::Scripts;
use rgb::{
    AttachId, BundleId, ContractId, Extension, Genesis, GraphSeal, Identity, OpId, Operation,
    Schema, SchemaId, TransitionBundle, XChain, XWitnessId,
};
use strict_encoding::{FieldName, TypeName};
use strict_types::typesys::UnknownType;
use strict_types::TypeSystem;

use crate::containers::{
    BundledWitness, Consignment, ContentId, ContentRef, Kit, SealWitness, SigBlob, Supplement,
};
use crate::interface::{
    ContractBuilder, Iface, IfaceClass, IfaceId, IfaceImpl, IfaceRef, TransitionBuilder,
};
use crate::persistence::ContractIfaceError;
use crate::{MergeReveal, MergeRevealError, SecretSeal, LIB_NAME_RGB_STD};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum StashError<P: StashProvider> {
    /// Connectivity errors which may be recoverable and temporary.
    ReadProvider(<P as StashReadProvider>::Error),

    /// Connectivity errors which may be recoverable and temporary.
    WriteProvider(<P as StashWriteProvider>::Error),

    /// {0}
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    Inconsistency(StashInconsistency),

    /// Errors caused by invalid input arguments.
    #[from]
    #[from(UnknownType)]
    #[from(MergeError)]
    #[from(MergeRevealError)]
    #[from(mpc::InvalidProof)]
    Data(StashDataError),
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum ProviderError<E: Error> {
    #[from]
    Inconsistency(StashInconsistency),
    #[from]
    Iface(ContractIfaceError),
    Connectivity(E),
}

impl<P: StashProvider> From<ProviderError<<P as StashReadProvider>::Error>> for StashError<P> {
    fn from(err: ProviderError<<P as StashReadProvider>::Error>) -> Self {
        match err {
            ProviderError::Inconsistency(e) => StashError::Inconsistency(e),
            ProviderError::Connectivity(e) => StashError::ReadProvider(e),
            ProviderError::Iface(e) => StashError::Data(StashDataError::NoAbstractIface(e)),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StashInconsistency {
    /// library {0} is unknown; perhaps you need to import it first.
    LibAbsent(LibId),

    /// interface {0} is unknown; perhaps you need to import it first.
    IfaceAbsent(IfaceRef),

    /// contract {0} is unknown. Probably you haven't imported the contract yet.
    ContractAbsent(ContractId),

    /// schema {0} is unknown.
    SchemaAbsent(SchemaId),

    /// interface {0::<0} is not implemented for the schema {1::<0}.
    IfaceImplAbsent(IfaceId, SchemaId),

    /// transition {0} is absent.
    OperationAbsent(OpId),

    /// information about witness {0} is absent.
    WitnessAbsent(XWitnessId),

    /// bundle {0} is absent.
    BundleAbsent(BundleId),

    /// none of known anchors contain information on bundle {0} under contract
    /// {1}.
    BundleMissedInAnchors(BundleId, ContractId),
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

    #[from]
    #[display(inner)]
    NoAbstractIface(ContractIfaceError),
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
    pub iimpls: TinyOrdMap<TypeName, IfaceImpl>,
}

impl SchemaIfaces {
    pub fn new(schema: Schema) -> Self {
        SchemaIfaces {
            schema,
            iimpls: none!(),
        }
    }

    pub fn get(&self, id: IfaceId) -> Option<&IfaceImpl> {
        self.iimpls.values().find(|iimpl| iimpl.iface_id == id)
    }

    pub fn contains(&self, id: IfaceId) -> bool {
        self.iimpls.values().any(|iimpl| iimpl.iface_id == id)
    }
}

#[derive(Debug)]
pub struct Stash<P: StashProvider> {
    provider: P,
}

impl<P: StashProvider> Default for Stash<P>
where P: Default
{
    fn default() -> Self {
        Self {
            provider: default!(),
        }
    }
}

impl<P: StashProvider> Stash<P> {
    pub(super) fn new(provider: P) -> Self { Self { provider } }

    #[doc(hidden)]
    pub fn as_provider(&self) -> &P { &self.provider }

    pub(super) fn ifaces(&self) -> Result<impl Iterator<Item = &Iface> + '_, StashError<P>> {
        self.provider.ifaces().map_err(StashError::ReadProvider)
    }
    pub(super) fn iface(&self, iface: impl Into<IfaceRef>) -> Result<&Iface, StashError<P>> {
        Ok(self.provider.iface(iface)?)
    }
    pub(super) fn schemata(
        &self,
    ) -> Result<impl Iterator<Item = &SchemaIfaces> + '_, StashError<P>> {
        self.provider.schemata().map_err(StashError::ReadProvider)
    }
    pub(super) fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, StashError<P>> {
        Ok(self.provider.schema(schema_id)?)
    }
    pub(super) fn impl_for<'a, C: IfaceClass + 'a>(
        &'a self,
        schema_ifaces: &'a SchemaIfaces,
    ) -> Result<&'a IfaceImpl, StashError<P>> {
        Ok(self.provider.impl_for::<C>(schema_ifaces)?)
    }

    pub(super) fn geneses(&self) -> Result<impl Iterator<Item = &Genesis> + '_, StashError<P>> {
        self.provider.geneses().map_err(StashError::ReadProvider)
    }
    pub(super) fn geneses_by<'a, C: IfaceClass + 'a>(
        &'a self,
    ) -> Result<impl Iterator<Item = &'a Genesis> + 'a, StashError<P>> {
        self.provider
            .geneses_by::<C>()
            .map_err(StashError::ReadProvider)
    }
    pub(super) fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, StashError<P>> {
        Ok(self.provider.genesis(contract_id)?)
    }
    pub(super) fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, StashError<P>> {
        Ok(self.provider.bundle(bundle_id)?)
    }
    pub(super) fn witness(&self, witness_id: XWitnessId) -> Result<&SealWitness, StashError<P>> {
        Ok(self.provider.witness(witness_id)?)
    }

    pub(super) fn supplements(
        &self,
        content_ref: ContentRef,
    ) -> Result<impl Iterator<Item = Supplement> + '_, StashError<P>> {
        self.provider
            .supplements(content_ref)
            .map_err(StashError::ReadProvider)
    }

    pub(super) fn extract<'a>(
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
            let lib = self.provider.lib(id)?;
            scripts.insert(id, lib.clone());
        }
        let scripts = Scripts::try_from(scripts)
            .map_err(|_| StashDataError::TooManyLibs(schema.schema_id()))?;

        Ok((types, scripts))
    }

    pub(super) fn contract_builder(
        &self,
        issuer: Identity,
        schema_id: SchemaId,
        iface: impl Into<IfaceRef>,
    ) -> Result<ContractBuilder, StashError<P>> {
        let schema_ifaces = self.schema(schema_id)?;
        let iface = self.iface(iface)?;
        let iface_id = iface.iface_id();
        let iimpl = schema_ifaces
            .get(iface_id)
            .ok_or(StashDataError::NoIfaceImpl(schema_id, iface_id))?;

        let (types, scripts) = self.extract(&schema_ifaces.schema, [iface])?;

        let builder = ContractBuilder::with(
            issuer,
            iface.clone(),
            schema_ifaces.schema.clone(),
            iimpl.clone(),
            types,
            scripts,
        );
        Ok(builder)
    }

    pub(super) fn transition_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
        transition_name: Option<impl Into<FieldName>>,
    ) -> Result<TransitionBuilder, StashError<P>> {
        let schema_ifaces = self.provider.contract_schema(contract_id)?;
        let iface = self.iface(iface)?;
        let schema = &schema_ifaces.schema;
        let iimpl = schema_ifaces
            .get(iface.iface_id())
            .ok_or(StashDataError::NoIfaceImpl(schema.schema_id(), iface.iface_id()))?;
        let genesis = self.provider.genesis(contract_id)?;

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

        for (assignment_type, asset_tag) in genesis.asset_tags.iter() {
            builder = builder
                .add_asset_tag_raw(*assignment_type, *asset_tag)
                .expect("tags are in bset and must not repeat");
        }

        Ok(builder)
    }

    pub(super) fn blank_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
    ) -> Result<TransitionBuilder, StashError<P>> {
        let schema_ifaces = self.provider.contract_schema(contract_id)?;
        let iface = self.iface(iface)?;
        let schema = &schema_ifaces.schema;
        if schema_ifaces.iimpls.is_empty() {
            return Err(StashDataError::NoIfaceImpl(schema.schema_id(), iface.iface_id()).into());
        }
        let genesis = self.provider.genesis(contract_id)?;

        let (types, _) = self.extract(&schema_ifaces.schema, [iface])?;

        let mut builder = if let Some(iimpl) = schema_ifaces.get(iface.iface_id()) {
            TransitionBuilder::blank_transition(
                contract_id,
                iface.clone(),
                schema.clone(),
                iimpl.clone(),
                types,
            )
        } else {
            let (default_iface_name, default_iimpl) =
                schema_ifaces.iimpls.first_key_value().unwrap();
            let default_iface = self.iface(default_iface_name.clone())?;

            TransitionBuilder::blank_transition(
                contract_id,
                default_iface.clone(),
                schema.clone(),
                default_iimpl.clone(),
                types,
            )
        };
        for (assignment_type, asset_tag) in genesis.asset_tags.iter() {
            builder = builder
                .add_asset_tag_raw(*assignment_type, *asset_tag)
                .expect("tags are in bset and must not repeat");
        }

        Ok(builder)
    }

    pub(super) fn consume_kit(&mut self, kit: Kit) -> Result<(), StashError<P>> {
        self.provider
            .consume_types(kit.types)
            .map_err(StashError::WriteProvider)?;
        for lib in kit.scripts {
            self.provider
                .replace_lib(lib)
                .map_err(StashError::WriteProvider)?;
        }

        // TODO: filter most trusted signers
        for schema in kit.schemata {
            self.provider
                .replace_schema(schema)
                .map_err(StashError::WriteProvider)?;
        }
        for iface in kit.ifaces {
            self.provider
                .replace_iface(iface)
                .map_err(StashError::WriteProvider)?;
        }
        for iimpl in kit.iimpls {
            self.provider
                .replace_iimpl(iimpl)
                .map_err(StashError::WriteProvider)?;
        }

        // TODO: filter out non-trusted signers
        for suppl in kit.supplements {
            self.provider
                .add_suppl(suppl)
                .map_err(StashError::WriteProvider)?;
        }

        for (content_id, sigs) in kit.signatures {
            // TODO: Filter sigs by trust level
            // Do not bother if we can't import all the sigs
            self.provider.import_sigs(content_id, sigs).ok();
        }

        Ok(())
    }

    pub(super) fn resolve_secrets<const TRANSFER: bool>(
        &self,
        mut consignment: Consignment<TRANSFER>,
    ) -> Result<Consignment<TRANSFER>, StashError<P>> {
        for (bundle_id, secret) in consignment.terminal_secrets() {
            if let Some(seal) = self
                .provider
                .seal_secret(secret)
                .map_err(StashError::ReadProvider)?
            {
                consignment = consignment.reveal_bundle_seal(bundle_id, seal);
            }
        }
        Ok(consignment)
    }

    pub(super) fn consume_consignment<const TRANSFER: bool>(
        &mut self,
        consignment: Consignment<TRANSFER>,
    ) -> Result<(), StashError<P>> {
        let contract_id = consignment.contract_id();

        let genesis = match self.genesis(contract_id) {
            Ok(g) => g.clone().merge_reveal(consignment.genesis)?,
            Err(_) => consignment.genesis,
        };
        self.provider
            .replace_genesis(genesis)
            .map_err(StashError::WriteProvider)?;

        for extension in consignment.extensions {
            let opid = extension.id();
            let extension = match self.provider.extension(opid) {
                Ok(e) => e.clone().merge_reveal(extension)?,
                Err(_) => extension,
            };
            self.provider
                .replace_extension(extension)
                .map_err(StashError::WriteProvider)?;
        }

        for bw in consignment.bundles {
            self.consume_bundled_witness(contract_id, bw)?;
        }

        for (id, attach) in consignment.attachments {
            self.provider
                .replace_attachment(id, attach)
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
            pub_witness,
            anchored_bundles,
        } = bundled_witness;

        // TODO: Save pub witness transaction and SPVs

        for bundle in anchored_bundles.bundles().cloned() {
            let bundle_id = bundle.bundle_id();
            self.consume_bundle(bundle)?;

            let anchors = anchored_bundles.to_anchor_set(contract_id, bundle_id)?;
            let witness = SealWitness {
                public: pub_witness.clone(),
                anchors,
            };
            self.consume_witness(witness)?;
        }

        Ok(())
    }

    pub(crate) fn consume_witness(&mut self, witness: SealWitness) -> Result<bool, StashError<P>> {
        let witness = match self.provider.witness(witness.witness_id()).cloned() {
            Ok(mut w) => {
                w.public = w.public.clone().merge_reveal(witness.public)?;
                w.anchors = w.anchors.clone().merge_reveal(witness.anchors)?;
                w
            }
            Err(_) => witness,
        };

        self.provider
            .replace_witness(witness)
            .map_err(StashError::WriteProvider)
    }

    pub(crate) fn consume_bundle(
        &mut self,
        bundle: TransitionBundle,
    ) -> Result<bool, StashError<P>> {
        let bundle = match self.provider.bundle(bundle.bundle_id()).cloned() {
            Ok(b) => b.merge_reveal(bundle)?,
            Err(_) => bundle,
        };
        self.provider
            .replace_bundle(bundle)
            .map_err(StashError::WriteProvider)
    }

    pub(crate) fn store_secret_seal(
        &mut self,
        seal: XChain<GraphSeal>,
    ) -> Result<bool, StashError<P>> {
        self.provider
            .add_secret_seal(seal)
            .map_err(StashError::WriteProvider)
    }
}

pub trait StashProvider: Debug + StashReadProvider + StashWriteProvider {}

pub trait StashReadProvider {
    /// Error type which must indicate problems on data retrieval.
    type Error: Clone + Eq + Error;

    fn type_system(&self) -> Result<&TypeSystem, Self::Error>;
    fn lib(&self, id: LibId) -> Result<&Lib, ProviderError<Self::Error>>;

    fn ifaces(&self) -> Result<impl Iterator<Item = &Iface>, Self::Error>;
    fn iface(&self, iface: impl Into<IfaceRef>) -> Result<&Iface, ProviderError<Self::Error>>;
    fn schemata(&self) -> Result<impl Iterator<Item = &SchemaIfaces>, Self::Error>;
    fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, ProviderError<Self::Error>>;
    fn schemata_by<C: IfaceClass>(
        &self,
    ) -> Result<impl Iterator<Item = &SchemaIfaces>, Self::Error>;
    fn impl_for<'a, C: IfaceClass + 'a>(
        &'a self,
        schema_ifaces: &'a SchemaIfaces,
    ) -> Result<&'a IfaceImpl, ProviderError<Self::Error>>;
    fn geneses(&self) -> Result<impl Iterator<Item = &Genesis>, Self::Error>;
    fn geneses_by<C: IfaceClass>(&self) -> Result<impl Iterator<Item = &Genesis>, Self::Error>;
    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, ProviderError<Self::Error>>;

    fn contract_schema(
        &self,
        contract_id: ContractId,
    ) -> Result<&SchemaIfaces, ProviderError<Self::Error>> {
        let genesis = self.genesis(contract_id)?;
        self.schema(genesis.schema_id)
    }
    fn supplements(
        &self,
        content_ref: ContentRef,
    ) -> Result<impl Iterator<Item = Supplement>, Self::Error>;

    fn witness_ids(&self) -> Result<impl Iterator<Item = XWitnessId>, Self::Error>;
    fn bundle_ids(&self) -> Result<impl Iterator<Item = BundleId>, Self::Error>;
    fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, ProviderError<Self::Error>>;
    fn extension_ids(&self) -> Result<impl Iterator<Item = OpId>, Self::Error>;
    fn extension(&self, op_id: OpId) -> Result<&Extension, ProviderError<Self::Error>>;
    fn witness(&self, witness_id: XWitnessId) -> Result<&SealWitness, ProviderError<Self::Error>>;

    fn taprets(&self) -> Result<impl Iterator<Item = (XWitnessId, TapretCommitment)>, Self::Error>;
    fn seal_secret(
        &self,
        secret: XChain<SecretSeal>,
    ) -> Result<Option<XChain<GraphSeal>>, Self::Error>;
    fn secret_seals(&self) -> Result<impl Iterator<Item = XChain<GraphSeal>>, Self::Error>;
}

pub trait StashWriteProvider {
    type Error: Clone + Eq + Error;

    fn replace_schema(&mut self, schema: Schema) -> Result<bool, Self::Error>;
    fn replace_iface(&mut self, iface: Iface) -> Result<bool, Self::Error>;
    fn replace_iimpl(&mut self, iimpl: IfaceImpl) -> Result<bool, Self::Error>;
    fn replace_genesis(&mut self, genesis: Genesis) -> Result<bool, Self::Error>;
    fn replace_extension(&mut self, extension: Extension) -> Result<bool, Self::Error>;
    fn replace_bundle(&mut self, bundle: TransitionBundle) -> Result<bool, Self::Error>;
    fn replace_witness(&mut self, witness: SealWitness) -> Result<bool, Self::Error>;
    fn replace_attachment(&mut self, id: AttachId, attach: MediumBlob)
    -> Result<bool, Self::Error>;

    fn replace_lib(&mut self, lib: Lib) -> Result<bool, Self::Error>;
    fn consume_types(&mut self, types: TypeSystem) -> Result<(), Self::Error>;
    fn add_suppl(&mut self, suppl: Supplement) -> Result<(), Self::Error>;
    fn import_sigs<I>(&mut self, content_id: ContentId, sigs: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = (Identity, SigBlob)>,
        I::IntoIter: ExactSizeIterator<Item = (Identity, SigBlob)>;

    fn add_secret_seal(&mut self, seal: XChain<GraphSeal>) -> Result<bool, Self::Error>;
}
