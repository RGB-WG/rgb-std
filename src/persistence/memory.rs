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
#[cfg(feature = "fs")]
use std::path::PathBuf;

use aluvm::library::{Lib, LibId};
use amplify::confinement::{
    self, Confined, LargeOrdMap, MediumBlob, MediumOrdMap, MediumOrdSet, SmallOrdMap, TinyOrdMap,
    TinyOrdSet,
};
use bp::dbc::tapret::TapretCommitment;
use commit_verify::{CommitId, Conceal};
use rgb::{
    Assign, AssignmentType, AttachId, BundleId, ContractHistory, ContractId, ExposedState,
    Extension, Genesis, GenesisSeal, GraphSeal, Identity, OpId, Operation, Opout, Schema, SchemaId,
    SecretSeal, TransitionBundle, XChain, XOutputSeal, XWitnessId,
};
use strict_encoding::{SerializeError, StrictDeserialize, StrictSerialize};
use strict_types::TypeSystem;

use super::{
    ContractIfaceError, IndexInconsistency, IndexProvider, IndexReadError, IndexReadProvider,
    IndexWriteError, IndexWriteProvider, SchemaIfaces, StashInconsistency, StashProvider,
    StashProviderError, StashReadProvider, StashWriteProvider, StateProvider, StateReadProvider,
    StateUpdateError, StateWriteProvider, StoreTransaction,
};
use crate::containers::{
    AnchorSet, ContentId, ContentRef, ContentSigs, SealWitness, SigBlob, Supplement, TrustLevel,
};
use crate::interface::{Iface, IfaceClass, IfaceId, IfaceImpl, IfaceRef};
#[cfg(feature = "fs")]
use crate::persistence::fs::FsStored;
use crate::resolvers::ResolveHeight;
use crate::LIB_NAME_RGB_STORAGE;

//////////
// STASH
//////////

/// Hoard is an in-memory stash useful for WASM implementations.
#[derive(Getters, Clone, Debug, Default)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
pub struct MemStash {
    #[strict_type(skip)]
    dirty: bool,
    #[cfg(feature = "fs")]
    #[strict_type(skip)]
    filename: PathBuf,

    schemata: TinyOrdMap<SchemaId, SchemaIfaces>,
    ifaces: TinyOrdMap<IfaceId, Iface>,
    geneses: TinyOrdMap<ContractId, Genesis>,
    suppl: TinyOrdMap<ContentRef, TinyOrdSet<Supplement>>,
    bundles: LargeOrdMap<BundleId, TransitionBundle>,
    extensions: LargeOrdMap<OpId, Extension>,
    witnesses: LargeOrdMap<XWitnessId, SealWitness>,
    attachments: SmallOrdMap<AttachId, MediumBlob>,
    secret_seals: MediumOrdSet<XChain<GraphSeal>>,
    type_system: TypeSystem,
    identities: SmallOrdMap<Identity, TrustLevel>,
    libs: SmallOrdMap<LibId, Lib>,
    sigs: SmallOrdMap<ContentId, ContentSigs>,
}

impl StrictSerialize for MemStash {}
impl StrictDeserialize for MemStash {}

impl StoreTransaction for MemStash {
    type TransactionErr = SerializeError;

    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.dirty = true;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        #[cfg(feature = "fs")]
        if self.dirty {
            self.store()?;
        }
        Ok(())
    }

    fn rollback_transaction(&mut self) { unreachable!() }
}

impl StashProvider for MemStash {}

impl StashReadProvider for MemStash {
    // With in-memory data we have no connectivity or I/O errors
    type Error = Infallible;

    fn type_system(&self) -> Result<&TypeSystem, Self::Error> { Ok(&self.type_system) }

    fn lib(&self, id: LibId) -> Result<&Lib, StashProviderError<Self::Error>> {
        self.libs
            .get(&id)
            .ok_or_else(|| StashInconsistency::LibAbsent(id).into())
    }

    fn ifaces(&self) -> Result<impl Iterator<Item = &Iface>, Self::Error> {
        Ok(self.ifaces.values())
    }

    fn iface(&self, iface: impl Into<IfaceRef>) -> Result<&Iface, StashProviderError<Self::Error>> {
        let iref = iface.into();
        match iref {
            IfaceRef::Name(ref name) => self.ifaces.values().find(|iface| &iface.name == name),
            IfaceRef::Id(ref id) => self.ifaces.get(id),
        }
        .ok_or_else(|| StashInconsistency::IfaceAbsent(iref).into())
    }

    fn schemata(&self) -> Result<impl Iterator<Item = &SchemaIfaces>, Self::Error> {
        Ok(self.schemata.values())
    }
    fn schemata_by<C: IfaceClass>(
        &self,
    ) -> Result<impl Iterator<Item = &SchemaIfaces>, Self::Error> {
        Ok(self
            .schemata
            .values()
            .filter(|schema_ifaces| self.impl_for::<C>(schema_ifaces).is_ok()))
    }

    fn impl_for<'a, C: IfaceClass + 'a>(
        &'a self,
        schema_ifaces: &'a SchemaIfaces,
    ) -> Result<&'a IfaceImpl, StashProviderError<Self::Error>> {
        schema_ifaces
            .iimpls
            .values()
            .find(|iimpl| C::IFACE_IDS.contains(&iimpl.iface_id))
            .or_else(|| {
                schema_ifaces.iimpls.keys().find_map(|id| {
                    let iface = self.iface(id.clone()).ok()?;
                    iface.find_abstractable_impl(schema_ifaces)
                })
            })
            .ok_or_else(move || {
                ContractIfaceError::NoAbstractImpl(
                    C::IFACE_IDS[0],
                    schema_ifaces.schema.schema_id(),
                )
                .into()
            })
    }

    fn schema(
        &self,
        schema_id: SchemaId,
    ) -> Result<&SchemaIfaces, StashProviderError<Self::Error>> {
        self.schemata
            .get(&schema_id)
            .ok_or_else(|| StashInconsistency::SchemaAbsent(schema_id).into())
    }

    fn get_trust(&self, identity: &Identity) -> Result<TrustLevel, Self::Error> {
        Ok(self.identities.get(identity).copied().unwrap_or_default())
    }

    fn supplement(&self, content_ref: ContentRef) -> Result<Option<&Supplement>, Self::Error> {
        Ok(self.suppl.get(&content_ref).and_then(|s| s.first()))
    }

    fn supplements(
        &self,
        content_ref: ContentRef,
    ) -> Result<impl Iterator<Item = Supplement>, Self::Error> {
        Ok(self
            .suppl
            .get(&content_ref)
            .cloned()
            .unwrap_or_default()
            .into_iter())
    }

    fn sigs_for(&self, content_id: &ContentId) -> Result<Option<&ContentSigs>, Self::Error> {
        Ok(self.sigs.get(content_id))
    }

    fn geneses(&self) -> Result<impl Iterator<Item = &Genesis>, Self::Error> {
        Ok(self.geneses.values())
    }

    fn geneses_by<C: IfaceClass>(&self) -> Result<impl Iterator<Item = &Genesis>, Self::Error> {
        Ok(self.schemata_by::<C>()?.flat_map(|schema_ifaces| {
            self.geneses
                .values()
                .filter(|genesis| schema_ifaces.schema.schema_id() == genesis.schema_id)
        }))
    }

    fn genesis(
        &self,
        contract_id: ContractId,
    ) -> Result<&Genesis, StashProviderError<Self::Error>> {
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

    fn bundle(
        &self,
        bundle_id: BundleId,
    ) -> Result<&TransitionBundle, StashProviderError<Self::Error>> {
        self.bundles
            .get(&bundle_id)
            .ok_or(StashInconsistency::BundleAbsent(bundle_id).into())
    }

    fn extension_ids(&self) -> Result<impl Iterator<Item = OpId>, Self::Error> {
        Ok(self.extensions.keys().copied())
    }

    fn extension(&self, op_id: OpId) -> Result<&Extension, StashProviderError<Self::Error>> {
        self.extensions
            .get(&op_id)
            .ok_or(StashInconsistency::OperationAbsent(op_id).into())
    }

    fn witness(
        &self,
        witness_id: XWitnessId,
    ) -> Result<&SealWitness, StashProviderError<Self::Error>> {
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

    fn seal_secret(
        &self,
        secret: XChain<SecretSeal>,
    ) -> Result<Option<XChain<GraphSeal>>, Self::Error> {
        Ok(self
            .secret_seals
            .iter()
            .find(|s| s.conceal() == secret)
            .copied())
    }

    fn secret_seals(&self) -> Result<impl Iterator<Item = XChain<GraphSeal>>, Self::Error> {
        Ok(self.secret_seals.iter().copied())
    }
}

impl StashWriteProvider for MemStash {
    type Error = SerializeError;

    fn replace_schema(&mut self, schema: Schema) -> Result<bool, Self::Error> {
        let schema_id = schema.schema_id();
        if !self.schemata.contains_key(&schema_id) {
            self.schemata.insert(schema_id, SchemaIfaces::new(schema))?;
            return Ok(true);
        }
        Ok(false)
    }

    fn replace_iface(&mut self, iface: Iface) -> Result<bool, Self::Error> {
        let iface_id = iface.iface_id();
        if !self.ifaces.contains_key(&iface_id) {
            self.ifaces.insert(iface_id, iface)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn replace_iimpl(&mut self, iimpl: IfaceImpl) -> Result<bool, Self::Error> {
        let schema_ifaces = self
            .schemata
            .get_mut(&iimpl.schema_id)
            .expect("unknown schema");
        let iface = self.ifaces.get(&iimpl.iface_id).expect("unknown interface");
        let iface_name = iface.name.clone();
        let present = schema_ifaces.iimpls.contains_key(&iface_name);
        schema_ifaces.iimpls.insert(iface_name, iimpl)?;
        Ok(!present)
    }

    fn set_trust(
        &mut self,
        identity: Identity,
        trust: TrustLevel,
    ) -> Result<(), confinement::Error> {
        self.identities.insert(identity, trust)?;
        Ok(())
    }

    fn add_supplement(&mut self, suppl: Supplement) -> Result<(), Self::Error> {
        match self.suppl.get_mut(&suppl.content_id) {
            None => {
                self.suppl.insert(suppl.content_id, confined_bset![suppl])?;
            }
            Some(suppls) => suppls.push(suppl)?,
        }
        Ok(())
    }

    fn replace_genesis(&mut self, genesis: Genesis) -> Result<bool, Self::Error> {
        let contract_id = genesis.contract_id();
        let present = self.geneses.insert(contract_id, genesis)?.is_some();
        Ok(!present)
    }

    fn replace_extension(&mut self, extension: Extension) -> Result<bool, Self::Error> {
        let opid = extension.id();
        let present = self.extensions.insert(opid, extension)?.is_some();
        Ok(!present)
    }

    fn replace_bundle(&mut self, bundle: TransitionBundle) -> Result<bool, Self::Error> {
        let bundle_id = bundle.bundle_id();
        let present = self.bundles.insert(bundle_id, bundle)?.is_some();
        Ok(!present)
    }

    fn replace_witness(&mut self, witness: SealWitness) -> Result<bool, Self::Error> {
        let witness_id = witness.witness_id();
        let present = self.witnesses.insert(witness_id, witness)?.is_some();
        Ok(!present)
    }

    fn replace_attachment(
        &mut self,
        id: AttachId,
        attach: MediumBlob,
    ) -> Result<bool, Self::Error> {
        let present = self.attachments.insert(id, attach)?.is_some();
        Ok(!present)
    }

    fn consume_types(&mut self, types: TypeSystem) -> Result<(), Self::Error> {
        Ok(self.type_system.extend(types)?)
    }

    fn replace_lib(&mut self, lib: Lib) -> Result<bool, Self::Error> {
        let present = self.libs.insert(lib.id(), lib)?.is_some();
        Ok(!present)
    }

    fn import_sigs<I>(&mut self, content_id: ContentId, sigs: I) -> Result<(), Self::Error>
    where I: IntoIterator<Item = (Identity, SigBlob)> {
        let sigs = sigs.into_iter().filter(|(id, _)| {
            match self.identities.get(id) {
                Some(level) => *level,
                None => {
                    let level = TrustLevel::default();
                    // We ignore if the identities are full
                    self.identities.insert(id.clone(), level).ok();
                    level
                }
            }
            .should_accept()
        });
        if let Some(prev_sigs) = self.sigs.get_mut(&content_id) {
            prev_sigs.extend(sigs)?;
        } else {
            let sigs = Confined::try_from_iter(sigs)?;
            self.sigs.insert(content_id, ContentSigs::from(sigs)).ok();
        }
        Ok(())
    }

    fn add_secret_seal(&mut self, seal: XChain<GraphSeal>) -> Result<bool, Self::Error> {
        let present = self.secret_seals.contains(&seal);
        self.secret_seals.push(seal)?;
        Ok(!present)
    }
}

//////////
// STATE
//////////

impl From<confinement::Error> for StateUpdateError<confinement::Error> {
    fn from(err: confinement::Error) -> Self { StateUpdateError::Connectivity(err) }
}

#[derive(Getters, Clone, Debug, Default)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
pub struct MemState {
    #[strict_type(skip)]
    dirty: bool,
    #[cfg(feature = "fs")]
    #[strict_type(skip)]
    filename: PathBuf,

    history: TinyOrdMap<ContractId, ContractHistory>,
}

impl StrictSerialize for MemState {}
impl StrictDeserialize for MemState {}

impl StoreTransaction for MemState {
    type TransactionErr = SerializeError;

    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.dirty = true;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        #[cfg(feature = "fs")]
        if self.dirty {
            self.store()?;
        }
        Ok(())
    }

    fn rollback_transaction(&mut self) { unreachable!() }
}

impl StateProvider for MemState {}

impl StateReadProvider for MemState {
    type Error = confinement::Error;

    fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<Option<&ContractHistory>, Self::Error> {
        Ok(self.history.get(&contract_id))
    }
}

impl StateWriteProvider for MemState {
    type Error = SerializeError;

    fn create_or_update_state<R: ResolveHeight>(
        &mut self,
        contract_id: ContractId,
        updater: impl FnOnce(Option<ContractHistory>) -> Result<ContractHistory, String>,
    ) -> Result<(), StateUpdateError<Self::Error>> {
        let state = self.history.get(&contract_id);
        let updated =
            updater(state.cloned()).map_err(|e| StateUpdateError::Resolver(e.to_string()))?;
        self.history
            .insert(contract_id, updated)
            .map_err(|e| StateUpdateError::Connectivity(e.into()))?;
        Ok(())
    }

    fn update_state<R: ResolveHeight>(
        &mut self,
        contract_id: ContractId,
        mut updater: impl FnMut(&mut ContractHistory) -> Result<(), String>,
    ) -> Result<(), StateUpdateError<Self::Error>> {
        let state = self
            .history
            .get_mut(&contract_id)
            .ok_or(StateUpdateError::UnknownContract(contract_id))?;
        updater(state).map_err(|e| StateUpdateError::Resolver(e.to_string()))?;
        Ok(())
    }
}

//////////
// INDEX
//////////

impl From<confinement::Error> for IndexReadError<confinement::Error> {
    fn from(err: confinement::Error) -> Self { IndexReadError::Connectivity(err) }
}

impl From<confinement::Error> for IndexWriteError<confinement::Error> {
    fn from(err: confinement::Error) -> Self { IndexWriteError::Connectivity(err) }
}

#[derive(Clone, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractIndex {
    public_opouts: MediumOrdSet<Opout>,
    outpoint_opouts: MediumOrdMap<XOutputSeal, MediumOrdSet<Opout>>,
}

#[derive(Getters, Clone, Debug, Default)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
pub struct MemIndex {
    #[strict_type(skip)]
    dirty: bool,
    #[cfg(feature = "fs")]
    #[strict_type(skip)]
    filename: PathBuf,

    op_bundle_index: MediumOrdMap<OpId, BundleId>,
    bundle_contract_index: MediumOrdMap<BundleId, ContractId>,
    bundle_witness_index: MediumOrdMap<BundleId, XWitnessId>,
    contract_index: TinyOrdMap<ContractId, ContractIndex>,
    terminal_index: MediumOrdMap<XChain<SecretSeal>, Opout>,
}

impl StrictSerialize for MemIndex {}
impl StrictDeserialize for MemIndex {}

impl StoreTransaction for MemIndex {
    type TransactionErr = SerializeError;

    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.dirty = true;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        #[cfg(feature = "fs")]
        if self.dirty {
            self.store()?;
        }
        Ok(())
    }

    fn rollback_transaction(&mut self) { unreachable!() }
}

impl IndexProvider for MemIndex {}

impl IndexReadProvider for MemIndex {
    type Error = Infallible;

    fn contracts_assigning(
        &self,
        outputs: BTreeSet<XOutputSeal>,
    ) -> Result<impl Iterator<Item = ContractId> + '_, Self::Error> {
        Ok(self
            .contract_index
            .iter()
            .flat_map(move |(contract_id, index)| {
                outputs.clone().into_iter().filter_map(|outpoint| {
                    if index.outpoint_opouts.contains_key(&outpoint) {
                        Some(*contract_id)
                    } else {
                        None
                    }
                })
            }))
    }

    fn public_opouts(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, IndexReadError<Self::Error>> {
        let index = self
            .contract_index
            .get(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;
        Ok(index.public_opouts.to_inner())
    }

    fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<BTreeSet<Opout>, IndexReadError<Self::Error>> {
        let index = self
            .contract_index
            .get(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;
        let mut opouts = BTreeSet::new();
        for output in outputs.into_iter().map(|o| o.into()) {
            let set = index
                .outpoint_opouts
                .get(&output)
                .ok_or(IndexInconsistency::OutpointUnknown(output, contract_id))?;
            opouts.extend(set)
        }
        Ok(opouts)
    }

    fn opouts_by_terminals(
        &self,
        terminals: impl IntoIterator<Item = XChain<SecretSeal>>,
    ) -> Result<BTreeSet<Opout>, Self::Error> {
        let terminals = terminals.into_iter().collect::<BTreeSet<_>>();
        Ok(self
            .terminal_index
            .iter()
            .filter(|(seal, _)| terminals.contains(*seal))
            .map(|(_, opout)| *opout)
            .collect())
    }

    fn bundle_id_for_op(&self, opid: OpId) -> Result<BundleId, IndexReadError<Self::Error>> {
        self.op_bundle_index
            .get(&opid)
            .copied()
            .ok_or(IndexInconsistency::BundleAbsent(opid).into())
    }

    fn bundle_info(
        &self,
        bundle_id: BundleId,
    ) -> Result<(XWitnessId, ContractId), IndexReadError<Self::Error>> {
        let witness_id = self
            .bundle_witness_index
            .get(&bundle_id)
            .ok_or(IndexInconsistency::BundleWitnessUnknown(bundle_id))?;
        let contract_id = self
            .bundle_contract_index
            .get(&bundle_id)
            .ok_or(IndexInconsistency::BundleContractUnknown(bundle_id))?;
        Ok((*witness_id, *contract_id))
    }
}

impl IndexWriteProvider for MemIndex {
    type Error = SerializeError;

    fn register_contract(&mut self, contract_id: ContractId) -> Result<bool, Self::Error> {
        if !self.contract_index.contains_key(&contract_id) {
            self.contract_index.insert(contract_id, empty!())?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn register_bundle(
        &mut self,
        bundle_id: BundleId,
        witness_id: XWitnessId,
        contract_id: ContractId,
    ) -> Result<bool, IndexWriteError<Self::Error>> {
        if let Some(alt) = self
            .bundle_witness_index
            .get(&bundle_id)
            .filter(|alt| *alt != &witness_id)
        {
            return Err(IndexInconsistency::DistinctBundleWitness {
                bundle_id,
                present: *alt,
                expected: witness_id,
            }
            .into());
        }
        if let Some(alt) = self
            .bundle_contract_index
            .get(&bundle_id)
            .filter(|alt| *alt != &contract_id)
        {
            return Err(IndexInconsistency::DistinctBundleContract {
                bundle_id,
                present: *alt,
                expected: contract_id,
            }
            .into());
        }
        let present1 = self
            .bundle_witness_index
            .insert(bundle_id, witness_id)?
            .is_some();
        let present2 = self
            .bundle_contract_index
            .insert(bundle_id, contract_id)?
            .is_some();
        debug_assert_eq!(present1, present2);
        Ok(!present1)
    }

    fn register_operation(
        &mut self,
        opid: OpId,
        bundle_id: BundleId,
    ) -> Result<bool, IndexWriteError<Self::Error>> {
        if let Some(alt) = self
            .op_bundle_index
            .get(&opid)
            .filter(|alt| *alt != &bundle_id)
        {
            return Err(IndexInconsistency::DistinctBundleOp {
                opid,
                present: *alt,
                expected: bundle_id,
            }
            .into());
        }
        let present = self.op_bundle_index.insert(opid, bundle_id)?.is_some();
        Ok(!present)
    }

    fn index_genesis_assignments<State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        vec: &[Assign<State, GenesisSeal>],
        opid: OpId,
        type_id: AssignmentType,
    ) -> Result<(), IndexWriteError<Self::Error>> {
        let index = self
            .contract_index
            .get_mut(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;

        for (no, a) in vec.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            if let Assign::ConfidentialState { seal, .. } | Assign::Revealed { seal, .. } = a {
                let output = seal
                    .to_output_seal()
                    .expect("genesis seals always have outpoint");
                match index.outpoint_opouts.get_mut(&output) {
                    Some(opouts) => {
                        opouts.push(opout)?;
                    }
                    None => {
                        index
                            .outpoint_opouts
                            .insert(output, confined_bset!(opout))?;
                    }
                }
            }
            if let Assign::Confidential { seal, .. } | Assign::ConfidentialSeal { seal, .. } = a {
                self.terminal_index.insert(*seal, opout)?;
            }
        }
        Ok(())
    }

    fn index_transition_assignments<State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        vec: &[Assign<State, GraphSeal>],
        opid: OpId,
        type_id: AssignmentType,
        witness_id: XWitnessId,
    ) -> Result<(), IndexWriteError<Self::Error>> {
        let index = self
            .contract_index
            .get_mut(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;

        for (no, assign) in vec.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            if let Assign::ConfidentialState { seal, .. } | Assign::Revealed { seal, .. } = assign {
                let output = seal.try_to_output_seal(witness_id).unwrap_or_else(|_| {
                    panic!(
                        "chain mismatch between assignment vout seal ({}) and witness transaction \
                         ({})",
                        seal, witness_id
                    )
                });
                match index.outpoint_opouts.get_mut(&output) {
                    Some(opouts) => {
                        opouts.push(opout)?;
                    }
                    None => {
                        index
                            .outpoint_opouts
                            .insert(output, confined_bset!(opout))?;
                    }
                }
            }
            if let Assign::Confidential { seal, .. } | Assign::ConfidentialSeal { seal, .. } =
                assign
            {
                self.terminal_index.insert(*seal, opout)?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "fs")]
mod fs {
    use std::path::{Path, PathBuf};

    use amplify::confinement::U32;
    use strict_encoding::{DeserializeError, SerializeError, StrictDeserialize, StrictSerialize};

    use crate::persistence::fs::FsStored;
    use crate::persistence::{MemIndex, MemStash, MemState};

    impl FsStored for MemStash {
        fn new(filename: impl ToOwned<Owned = PathBuf>) -> Self {
            Self {
                dirty: true,
                filename: filename.to_owned(),
                ..default!()
            }
        }

        fn load(path: impl ToOwned<Owned = PathBuf>) -> Result<Self, DeserializeError> {
            let path = path.to_owned();
            let mut me = Self::strict_deserialize_from_file::<U32>(&path)?;
            me.set_filename(path);
            Ok(me)
        }

        fn is_dirty(&self) -> bool { self.dirty }

        fn filename(&self) -> &Path { &self.filename }

        fn set_filename(&mut self, filename: impl ToOwned<Owned = PathBuf>) -> PathBuf {
            let prev = self.filename.to_owned();
            self.filename = filename.to_owned();
            self.dirty = self.filename != prev;
            prev
        }

        fn store(&self) -> Result<(), SerializeError> {
            if self.is_dirty() {
                self.strict_serialize_to_file::<U32>(&self.filename())
            } else {
                Ok(())
            }
        }
    }

    impl FsStored for MemState {
        fn new(filename: impl ToOwned<Owned = PathBuf>) -> Self {
            Self {
                dirty: true,
                filename: filename.to_owned(),
                ..default!()
            }
        }

        fn load(path: impl ToOwned<Owned = PathBuf>) -> Result<Self, DeserializeError> {
            let path = path.to_owned();
            let mut me = Self::strict_deserialize_from_file::<U32>(&path)?;
            me.set_filename(path);
            Ok(me)
        }

        fn is_dirty(&self) -> bool { self.dirty }

        fn filename(&self) -> &Path { &self.filename }

        fn set_filename(&mut self, filename: impl ToOwned<Owned = PathBuf>) -> PathBuf {
            let prev = self.filename.to_owned();
            self.filename = filename.to_owned();
            self.dirty = self.filename != prev;
            prev
        }

        fn store(&self) -> Result<(), SerializeError> {
            if self.is_dirty() {
                self.strict_serialize_to_file::<U32>(&self.filename())
            } else {
                Ok(())
            }
        }
    }

    impl FsStored for MemIndex {
        fn new(filename: impl ToOwned<Owned = PathBuf>) -> Self {
            Self {
                dirty: true,
                filename: filename.to_owned(),
                ..default!()
            }
        }

        fn load(path: impl ToOwned<Owned = PathBuf>) -> Result<Self, DeserializeError> {
            let path = path.to_owned();
            let mut me = Self::strict_deserialize_from_file::<U32>(&path)?;
            me.set_filename(path);
            Ok(me)
        }

        fn is_dirty(&self) -> bool { self.dirty }

        fn filename(&self) -> &Path { &self.filename }

        fn set_filename(&mut self, filename: impl ToOwned<Owned = PathBuf>) -> PathBuf {
            let prev = self.filename.to_owned();
            self.filename = filename.to_owned();
            self.dirty = self.filename != prev;
            prev
        }

        fn store(&self) -> Result<(), SerializeError> {
            if self.is_dirty() {
                self.strict_serialize_to_file::<U32>(&self.filename())
            } else {
                Ok(())
            }
        }
    }
}
