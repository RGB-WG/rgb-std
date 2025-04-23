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
use std::error::Error;
use std::fmt::Debug;

use aluvm::library::{Lib, LibId};
use amplify::confinement::Confined;
use amplify::ByteArray;
use bp::dbc::tapret::TapretCommitment;
use bp::seals::txout::CloseMethod;
use commit_verify::mpc::{self, MerkleBlock};
use nonasync::persistence::{CloneNoPersistence, Persisting};
use rgb::validation::Scripts;
use rgb::{
    BundleId, ChainNet, ContractId, Genesis, GraphSeal, Identity, OpId, Schema, SchemaId,
    TransitionBundle, TransitionType, Txid,
};
use strict_types::typesys::UnknownType;
use strict_types::{FieldName, TypeSystem};

use crate::containers::{
    Consignment, ConsignmentExt, Kit, SealWitness, SealWitnessMergeError, WitnessBundle,
};
use crate::contract::{ContractBuilder, TransitionBuilder};
use crate::persistence::StoreTransaction;
use crate::{MergeReveal, MergeRevealError, SecretSeal};

#[derive(Debug, Display, Error, From)]
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
    #[display(doc_comments)]
    Inconsistency(StashInconsistency),

    /// Errors caused by invalid input arguments.
    #[from]
    #[from(UnknownType)]
    #[from(SealWitnessMergeError)]
    #[from(MergeRevealError)]
    #[from(mpc::InvalidProof)]
    Data(StashDataError),
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum ProviderError<E: Error> {
    #[from]
    Inconsistency(StashInconsistency),
    Connectivity(E),
}

impl<P: StashProvider> From<ProviderError<<P as StashReadProvider>::Error>> for StashError<P> {
    fn from(err: ProviderError<<P as StashReadProvider>::Error>) -> Self {
        match err {
            ProviderError::Inconsistency(e) => StashError::Inconsistency(e),
            ProviderError::Connectivity(e) => StashError::ReadProvider(e),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StashInconsistency {
    /// library {0} is unknown; perhaps you need to import it first.
    LibAbsent(LibId),

    /// contract {0} is unknown. Probably you haven't imported the contract yet.
    ContractAbsent(ContractId),

    /// schema {0} is unknown.
    SchemaAbsent(SchemaId),

    /// transition {0} is absent.
    OperationAbsent(OpId),

    /// information about witness {0} is absent.
    WitnessAbsent(Txid),

    /// witness {0} for the bundle {1} misses contract {2} information in {3} anchor.
    WitnessMissesContract(Txid, BundleId, ContractId, CloseMethod),

    /// bundle {0} is absent.
    BundleAbsent(BundleId),

    /// none of known anchors contain information on bundle {0} under contract
    /// {1}.
    BundleMissedInAnchors(BundleId, ContractId),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StashDataError {
    /// schema {0} uses too many AluVM libraries.
    TooManyLibs(SchemaId),

    #[from]
    #[display(inner)]
    UnknownType(UnknownType),

    #[from]
    #[display(inner)]
    Anchor(mpc::InvalidProof),

    #[from]
    #[display(inner)]
    Merge(SealWitnessMergeError),

    #[from]
    #[display(inner)]
    MergeReveal(MergeRevealError),
}

#[derive(Debug)]
pub struct Stash<P: StashProvider> {
    provider: P,
}

impl<P: StashProvider> CloneNoPersistence for Stash<P> {
    fn clone_no_persistence(&self) -> Self {
        Self {
            provider: self.provider.clone_no_persistence(),
        }
    }
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

    #[doc(hidden)]
    pub(super) fn as_provider_mut(&mut self) -> &mut P { &mut self.provider }

    pub(super) fn schemata(&self) -> Result<impl Iterator<Item = &Schema> + '_, StashError<P>> {
        self.provider.schemata().map_err(StashError::ReadProvider)
    }
    pub(super) fn schema(&self, schema_id: SchemaId) -> Result<&Schema, StashError<P>> {
        Ok(self.provider.schema(schema_id)?)
    }

    pub(super) fn geneses(&self) -> Result<impl Iterator<Item = &Genesis> + '_, StashError<P>> {
        self.provider.geneses().map_err(StashError::ReadProvider)
    }
    pub(super) fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, StashError<P>> {
        Ok(self.provider.genesis(contract_id)?)
    }
    pub(super) fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, StashError<P>> {
        Ok(self.provider.bundle(bundle_id)?)
    }
    pub(super) fn witness(&self, witness_id: Txid) -> Result<&SealWitness, StashError<P>> {
        Ok(self.provider.witness(witness_id)?)
    }

    pub(super) fn extract(&self, schema: &Schema) -> Result<(TypeSystem, Scripts), StashError<P>> {
        let type_iter = schema.types();
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
        chain_net: ChainNet,
    ) -> Result<ContractBuilder, StashError<P>> {
        let schema = self.schema(schema_id)?;

        let (types, scripts) = self.extract(schema)?;

        let builder = ContractBuilder::with(issuer, schema.clone(), types, scripts, chain_net);
        Ok(builder)
    }

    pub(super) fn transition_builder(
        &self,
        contract_id: ContractId,
        transition_name: impl Into<FieldName>,
    ) -> Result<TransitionBuilder, StashError<P>> {
        let schema = self.provider.contract_schema(contract_id)?;
        let (types, _) = self.extract(schema)?;

        let transition_type = schema.transition_type(transition_name);
        let builder = TransitionBuilder::with(contract_id, schema.clone(), transition_type, types);

        Ok(builder)
    }

    pub(super) fn transition_builder_raw(
        &self,
        contract_id: ContractId,
        transition_type: TransitionType,
    ) -> Result<TransitionBuilder, StashError<P>> {
        let schema = self.provider.contract_schema(contract_id)?;

        let (types, _) = self.extract(schema)?;

        let builder = TransitionBuilder::with(contract_id, schema.clone(), transition_type, types);

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

        for schema in kit.schemata {
            self.provider
                .replace_schema(schema)
                .map_err(StashError::WriteProvider)?;
        }

        Ok(())
    }

    pub(super) fn resolve_secrets<const TRANSFER: bool>(
        &self,
        mut consignment: Consignment<TRANSFER>,
    ) -> Result<Consignment<TRANSFER>, StashError<P>> {
        consignment = consignment.reveal_terminal_seals(|secret| {
            self.provider
                .seal_secret(secret)
                .map_err(StashError::ReadProvider)
        })?;
        Ok(consignment)
    }

    pub(super) fn consume_consignment<const TRANSFER: bool>(
        &mut self,
        consignment: Consignment<TRANSFER>,
    ) -> Result<(), StashError<P>> {
        let contract_id = consignment.contract_id();

        let genesis = match self.genesis(contract_id) {
            Ok(g) => {
                let mut g = g.clone();
                g.merge_reveal(&consignment.genesis)?;
                g
            }
            Err(_) => consignment.genesis,
        };
        self.provider
            .replace_genesis(genesis)
            .map_err(StashError::WriteProvider)?;

        for witness_bundles in consignment.bundles {
            self.consume_witness_bundle(contract_id, witness_bundles)?;
        }

        self.consume_kit(Kit {
            version: consignment.version,
            schemata: tiny_bset![consignment.schema],
            types: consignment.types,
            scripts: Confined::from_checked(consignment.scripts.release()),
        })
    }

    fn consume_witness_bundle(
        &mut self,
        contract_id: ContractId,
        witness_bundle: WitnessBundle,
    ) -> Result<(), StashError<P>> {
        let bundle = witness_bundle.bundle();
        let eanchor = witness_bundle.eanchor();

        let bundle_id = bundle.bundle_id();
        self.consume_bundle(bundle.clone())?;

        let proto = mpc::ProtocolId::from_byte_array(contract_id.to_byte_array());
        let msg = mpc::Message::from_byte_array(bundle_id.to_byte_array());
        let merkle_block = MerkleBlock::with(&eanchor.mpc_proof, proto, msg)?;

        let witness = SealWitness {
            public: witness_bundle.pub_witness.clone(),
            merkle_block,
            dbc_proof: eanchor.dbc_proof,
        };
        self.consume_witness(&witness)?;

        Ok(())
    }

    pub(crate) fn consume_witness(&mut self, witness: &SealWitness) -> Result<bool, StashError<P>> {
        let witness = match self.provider.witness(witness.witness_id()).cloned() {
            Ok(w) => {
                let mut w = w.clone();
                w.merge_reveal(witness)?;
                w
            }
            Err(_) => witness.clone(),
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
            Ok(b) => {
                let mut b = b.clone();
                b.merge_reveal(&bundle)?;
                b
            }
            Err(_) => bundle,
        };
        self.provider
            .replace_bundle(bundle)
            .map_err(StashError::WriteProvider)
    }

    pub(crate) fn store_secret_seal(&mut self, seal: GraphSeal) -> Result<bool, StashError<P>> {
        self.begin_transaction()?;
        let seal = self
            .provider
            .add_secret_seal(seal)
            .inspect_err(|_| self.rollback_transaction())
            .map_err(StashError::WriteProvider)?;
        self.commit_transaction()?;
        Ok(seal)
    }
}

impl<P: StashProvider> StoreTransaction for Stash<P> {
    type TransactionErr = StashError<P>;

    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.provider
            .begin_transaction()
            .map_err(StashError::WriteProvider)
    }

    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.provider
            .commit_transaction()
            .map_err(StashError::WriteProvider)
    }

    fn rollback_transaction(&mut self) { self.provider.rollback_transaction() }
}

pub trait StashProvider:
    Debug + CloneNoPersistence + Persisting + StashReadProvider + StashWriteProvider
{
}

pub trait StashReadProvider {
    /// Error type which must indicate problems on data retrieval.
    type Error: Clone + Eq + Error;

    fn type_system(&self) -> Result<&TypeSystem, Self::Error>;
    fn lib(&self, id: LibId) -> Result<&Lib, ProviderError<Self::Error>>;

    fn schemata(&self) -> Result<impl Iterator<Item = &Schema>, Self::Error>;
    fn schema(&self, schema_id: SchemaId) -> Result<&Schema, ProviderError<Self::Error>>;
    fn geneses(&self) -> Result<impl Iterator<Item = &Genesis>, Self::Error>;
    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, ProviderError<Self::Error>>;

    fn contract_schema(
        &self,
        contract_id: ContractId,
    ) -> Result<&Schema, ProviderError<Self::Error>> {
        let genesis = self.genesis(contract_id)?;
        self.schema(genesis.schema_id)
    }

    fn witness_ids(&self) -> Result<impl Iterator<Item = Txid>, Self::Error>;
    fn bundle_ids(&self) -> Result<impl Iterator<Item = BundleId>, Self::Error>;
    fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, ProviderError<Self::Error>>;
    fn witness(&self, witness_id: Txid) -> Result<&SealWitness, ProviderError<Self::Error>>;

    fn taprets(&self) -> Result<impl Iterator<Item = (Txid, TapretCommitment)>, Self::Error>;
    fn seal_secret(&self, secret: SecretSeal) -> Result<Option<GraphSeal>, Self::Error>;
    fn secret_seals(&self) -> Result<impl Iterator<Item = GraphSeal>, Self::Error>;
}

pub trait StashWriteProvider: StoreTransaction<TransactionErr = Self::Error> {
    type Error: Error;

    fn replace_schema(&mut self, schema: Schema) -> Result<bool, Self::Error>;
    fn replace_genesis(&mut self, genesis: Genesis) -> Result<bool, Self::Error>;
    fn replace_bundle(&mut self, bundle: TransitionBundle) -> Result<bool, Self::Error>;
    fn replace_witness(&mut self, witness: SealWitness) -> Result<bool, Self::Error>;

    fn replace_lib(&mut self, lib: Lib) -> Result<bool, Self::Error>;
    fn consume_types(&mut self, types: TypeSystem) -> Result<(), Self::Error>;

    fn add_secret_seal(&mut self, seal: GraphSeal) -> Result<bool, Self::Error>;
}
