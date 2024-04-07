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
use std::ops::{Deref, DerefMut};

use amplify::confinement::{MediumOrdMap, MediumOrdSet, TinyOrdMap};
use amplify::ByteArray;
use commit_verify::Conceal;
use rgb::validation::{Validity, Warning};
use rgb::{
    validation, Assign, AssignmentType, BundleId, ContractHistory, ContractId, ContractState,
    ExposedState, Extension, Genesis, GenesisSeal, GraphSeal, OpId, Operation, Opout, Schema,
    SecretSeal, Transition, TransitionBundle, TypedAssigns, WitnessAnchor, XChain, XOutpoint,
    XOutputSeal, XWitnessId,
};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::containers::{
    AnchoredBundles, BundledWitness, Cert, Consignment, ContentId, Contract, PubWitness,
    SealWitness, TerminalSeal, ToWitnessId, Transfer,
};
use crate::interface::{ContractIface, Iface, IfaceId, IfaceImpl, IfacePair, SchemaIfaces};
use crate::persistence::inventory::{DataError, IfaceImplError, InventoryInconsistency};
use crate::persistence::{
    Hoard, Inventory, InventoryDataError, InventoryError, PersistedState, Stash, StashInconsistency,
};
use crate::resolvers::ResolveHeight;
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractIndex {
    public_opouts: MediumOrdSet<Opout>,
    outpoint_opouts: MediumOrdMap<XOutputSeal, MediumOrdSet<Opout>>,
}

/// Stock is an in-memory inventory (stash, index, contract state) useful for
/// WASM implementations.
///
/// Can hold data about up to 256 contracts.
#[derive(Clone, Debug, Getters)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct Stock {
    // stash
    hoard: Hoard,
    // state
    history: TinyOrdMap<ContractId, ContractHistory>,
    // index
    op_bundle_index: MediumOrdMap<OpId, BundleId>,
    bundle_contract_index: MediumOrdMap<BundleId, ContractId>,
    bundle_witness_index: MediumOrdMap<BundleId, XWitnessId>,
    contract_index: TinyOrdMap<ContractId, ContractIndex>,
    terminal_index: MediumOrdMap<XChain<SecretSeal>, Opout>,
    // secrets
    seal_secrets: MediumOrdSet<XChain<GraphSeal>>,
}

impl Default for Stock {
    fn default() -> Self {
        Stock {
            hoard: Hoard::preset(),
            history: empty!(),
            op_bundle_index: empty!(),
            bundle_witness_index: empty!(),
            bundle_contract_index: empty!(),
            contract_index: empty!(),
            terminal_index: empty!(),
            seal_secrets: empty!(),
        }
    }
}

impl StrictSerialize for Stock {}
impl StrictDeserialize for Stock {}

impl Deref for Stock {
    type Target = Hoard;

    fn deref(&self) -> &Self::Target { &self.hoard }
}

impl DerefMut for Stock {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.hoard }
}

#[allow(clippy::result_large_err)]
impl Stock {
    fn consume_consignment<R: ResolveHeight, const TYPE: bool>(
        &mut self,
        mut consignment: Consignment<TYPE>,
        resolver: &mut R,
        force: bool,
    ) -> Result<validation::Status, InventoryError<Infallible>>
    where
        R::Error: 'static,
    {
        let mut status = validation::Status::new();
        match consignment.validation_status() {
            None => return Err(DataError::NotValidated.into()),
            Some(status) if status.validity() == Validity::Invalid => {
                return Err(DataError::Invalid(status.clone()).into());
            }
            Some(status) if status.validity() == Validity::UnresolvedTransactions && !force => {
                return Err(DataError::UnresolvedTransactions.into());
            }
            Some(status) if status.validity() == Validity::UnminedTerminals && !force => {
                return Err(DataError::TerminalsUnmined.into());
            }
            Some(s) if s.validity() == Validity::UnresolvedTransactions && !force => {
                status.add_warning(Warning::Custom(s!(
                    "contract contains unknown transactions and was forcefully imported"
                )));
            }
            Some(s) if s.validity() == Validity::UnminedTerminals && !force => {
                status.add_warning(Warning::Custom(s!("contract contains not yet mined final \
                                                       transactions and was forcefully imported")));
            }
            _ => {}
        }

        let id = consignment.contract_id();

        self.import_schema(consignment.schema.clone())?;
        for IfacePair { iface, iimpl } in consignment.ifaces.values() {
            self.import_iface(iface.clone())?;
            self.import_iface_impl(iimpl.clone())?;
        }

        // clone needed due to borrow checker
        for (bundle_id, terminal) in consignment.terminals.clone() {
            for secret in terminal
                .seals
                .iter()
                .filter_map(|seal| seal.map_ref(TerminalSeal::secret_seal).transpose())
            {
                if let Some(seal) = self.seal_secrets.iter().find(|s| s.conceal() == secret) {
                    consignment = consignment.reveal_bundle_seal(bundle_id, *seal);
                }
            }
        }

        // Update existing contract state
        let history = consignment
            .update_history(self.history.get(&id), resolver)
            .map_err(|err| DataError::HeightResolver(Box::new(err)))?;
        self.history.insert(id, history)?;

        let contract_id = consignment.contract_id();
        if !self.contract_index.contains_key(&contract_id) {
            self.contract_index.insert(contract_id, empty!())?;
        }
        self.index_genesis(contract_id, &consignment.genesis)?;
        for extension in &consignment.extensions {
            self.index_extension(contract_id, extension)?;
        }
        for BundledWitness {
            pub_witness,
            anchored_bundles,
        } in &consignment.bundles
        {
            let witness_id = pub_witness.to_witness_id();
            for bundle in anchored_bundles.bundles() {
                self.bundle_witness_index
                    .insert(bundle.bundle_id(), witness_id)?;
                self.index_bundle(contract_id, bundle, witness_id)?;
            }
        }

        self.hoard.consume_consignment(consignment)?;

        Ok(status)
    }

    fn index_genesis(
        &mut self,
        id: ContractId,
        genesis: &Genesis,
    ) -> Result<(), InventoryError<<Self as Inventory>::Error>> {
        let opid = genesis.id();
        for (type_id, assign) in genesis.assignments.iter() {
            match assign {
                TypedAssigns::Declarative(vec) => {
                    self.index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Fungible(vec) => {
                    self.index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Structured(vec) => {
                    self.index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Attachment(vec) => {
                    self.index_genesis_assignments(id, vec, opid, *type_id)?;
                }
            }
        }
        Ok(())
    }

    fn index_extension(
        &mut self,
        id: ContractId,
        extension: &Extension,
    ) -> Result<(), InventoryError<<Self as Inventory>::Error>> {
        let opid = extension.id();
        for (type_id, assign) in extension.assignments.iter() {
            match assign {
                TypedAssigns::Declarative(vec) => {
                    self.index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Fungible(vec) => {
                    self.index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Structured(vec) => {
                    self.index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Attachment(vec) => {
                    self.index_genesis_assignments(id, vec, opid, *type_id)?;
                }
            }
        }
        Ok(())
    }

    fn index_bundle(
        &mut self,
        id: ContractId,
        bundle: &TransitionBundle,
        witness_id: XWitnessId,
    ) -> Result<(), InventoryError<<Self as Inventory>::Error>> {
        let bundle_id = bundle.bundle_id();
        for (opid, transition) in &bundle.known_transitions {
            self.op_bundle_index.insert(*opid, bundle_id)?;
            self.bundle_contract_index.insert(bundle_id, id)?;
            for (type_id, assign) in transition.assignments.iter() {
                match assign {
                    TypedAssigns::Declarative(vec) => {
                        self.index_transition_assignments(id, vec, *opid, *type_id, witness_id)?;
                    }
                    TypedAssigns::Fungible(vec) => {
                        self.index_transition_assignments(id, vec, *opid, *type_id, witness_id)?;
                    }
                    TypedAssigns::Structured(vec) => {
                        self.index_transition_assignments(id, vec, *opid, *type_id, witness_id)?;
                    }
                    TypedAssigns::Attachment(vec) => {
                        self.index_transition_assignments(id, vec, *opid, *type_id, witness_id)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn index_genesis_assignments<State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        vec: &[Assign<State, GenesisSeal>],
        opid: OpId,
        type_id: AssignmentType,
    ) -> Result<(), InventoryError<<Self as Inventory>::Error>> {
        let index = self
            .contract_index
            .get_mut(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id))?;

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
    ) -> Result<(), InventoryError<<Self as Inventory>::Error>> {
        let index = self
            .contract_index
            .get_mut(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id))?;

        for (no, a) in vec.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            if let Assign::ConfidentialState { seal, .. } | Assign::Revealed { seal, .. } = a {
                let output = seal
                    .try_to_output_seal(witness_id)
                    .map_err(|_| DataError::ChainMismatch)?;
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
}

impl Inventory for Stock {
    type Stash = Hoard;
    // In-memory representation doesn't have connectivity errors
    type Error = Infallible;

    fn stash(&self) -> &Self::Stash { self }

    fn import_sigs<I>(
        &mut self,
        content_id: ContentId,
        sigs: I,
    ) -> Result<(), InventoryDataError<Self::Error>>
    where
        I: IntoIterator<Item = Cert>,
        I::IntoIter: ExactSizeIterator<Item = Cert>,
    {
        self.import_sigs_internal(content_id, sigs)?;
        Ok(())
    }

    fn import_schema(
        &mut self,
        schema: Schema,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>> {
        let id = schema.schema_id();

        let mut status = schema.verify();
        if !status.failures.is_empty() {
            return Err(status.into());
        }
        if self.schemata.contains_key(&id) {
            status.add_warning(Warning::Custom(format!("schema {id::<0} is already known")));
        } else {
            let schema_ifaces = SchemaIfaces::new(schema);
            self.schemata.insert(id, schema_ifaces)?;
        }

        Ok(status)
    }

    fn import_iface(
        &mut self,
        iface: Iface,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>> {
        let id = iface.iface_id();

        let mut status = validation::Status::new();

        // TODO: Do interface check on internal consistency
        if self.ifaces.insert(id, iface)?.is_some() {
            status.add_warning(Warning::Custom(format!("interface {id::<0} is already known")));
        }

        Ok(status)
    }

    fn import_iface_impl(
        &mut self,
        iimpl: IfaceImpl,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>> {
        let iface_id = iimpl.iface_id;
        let impl_id = iimpl.impl_id();

        let mut status = validation::Status::new();

        if !self.ifaces.contains_key(&iface_id) {
            return Err(IfaceImplError::UnknownIface(iface_id).into());
        }
        let Some(schema_ifaces) = self.schemata.get_mut(&iimpl.schema_id) else {
            return Err(IfaceImplError::UnknownSchema(iimpl.schema_id).into());
        };
        // TODO: Do interface check on internal consistency
        if schema_ifaces.iimpls.insert(iface_id, iimpl)?.is_some() {
            status.add_warning(Warning::Custom(format!(
                "interface implementation {impl_id::<0} is already known",
            )));
        }

        Ok(status)
    }

    fn import_contract<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, InventoryError<Self::Error>>
    where
        R::Error: 'static,
    {
        self.consume_consignment(contract, resolver, false)
    }

    fn accept_transfer<R: ResolveHeight>(
        &mut self,
        transfer: Transfer,
        resolver: &mut R,
        force: bool,
    ) -> Result<validation::Status, InventoryError<Self::Error>>
    where
        R::Error: 'static,
    {
        self.consume_consignment(transfer, resolver, force)
    }

    unsafe fn consume_witness(
        &mut self,
        witness: SealWitness,
    ) -> Result<(), InventoryError<Self::Error>> {
        for (proto, _) in witness.anchor.mpc_proof.to_known_message_map() {
            let bundle_id = BundleId::from_byte_array(proto.to_byte_array());
            self.bundle_witness_index
                .insert(bundle_id, witness.witness_id())?;
        }
        self.hoard.consume_witness(witness)?;
        Ok(())
    }

    unsafe fn consume_bundle(
        &mut self,
        contract_id: ContractId,
        bundle: TransitionBundle,
        witness_id: XWitnessId,
    ) -> Result<(), InventoryError<<Self as Inventory>::Error>> {
        self.index_bundle(contract_id, &bundle, witness_id)?;
        let history = self
            .history
            .get_mut(&contract_id)
            .ok_or(InventoryInconsistency::StateAbsent(contract_id))?;
        for transition in bundle.known_transitions.values() {
            let witness_anchor = WitnessAnchor::from_mempool(witness_id);
            history.add_transition(transition, witness_anchor);
        }
        self.hoard.consume_bundle(bundle)?;
        Ok(())
    }

    unsafe fn import_contract_force<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, InventoryError<Self::Error>>
    where
        R::Error: 'static,
    {
        self.consume_consignment(contract, resolver, true)
    }

    fn contract_iface_id(
        &self,
        contract_id: ContractId,
        iface_id: IfaceId,
    ) -> Result<ContractIface, InventoryError<Self::Error>> {
        let history = self
            .history
            .get(&contract_id)
            .ok_or(InventoryInconsistency::StateAbsent(contract_id))?
            .clone();
        let schema_id = history.schema_id();
        let schema_ifaces = self
            .schemata
            .get(&schema_id)
            .ok_or(StashInconsistency::SchemaAbsent(schema_id))?;
        let state = ContractState {
            schema: schema_ifaces.schema.clone(),
            history,
        };
        let iimpl = schema_ifaces
            .iimpls
            .get(&iface_id)
            .ok_or(StashInconsistency::IfaceImplAbsent(iface_id, schema_id))?
            .clone();
        Ok(ContractIface {
            state,
            iface: iimpl,
        })
    }

    fn transition(&self, opid: OpId) -> Result<&Transition, InventoryError<Self::Error>> {
        let bundle_id = self
            .op_bundle_index
            .get(&opid)
            .ok_or(InventoryInconsistency::BundleAbsent(opid))?;
        let bundle = self.bundle(*bundle_id)?;
        let transition = bundle
            .known_transitions
            .get(&opid)
            .ok_or(DataError::Concealed)?;
        Ok(transition)
    }

    fn op_bundle_id(&self, opid: OpId) -> Result<BundleId, InventoryError<Self::Error>> {
        self.op_bundle_index
            .get(&opid)
            .copied()
            .ok_or(InventoryInconsistency::BundleAbsent(opid).into())
    }

    fn bundled_witness(
        &self,
        bundle_id: BundleId,
    ) -> Result<BundledWitness, InventoryError<Self::Error>> {
        let witness_id = self
            .bundle_witness_index
            .get(&bundle_id)
            .ok_or(InventoryInconsistency::NoBundleAnchor(bundle_id))?;
        let contract_id = self
            .bundle_contract_index
            .get(&bundle_id)
            .ok_or(InventoryInconsistency::BundleContractUnknown(bundle_id))?;

        let bundle = self.bundle(bundle_id)?.clone();
        let anchor = self.anchor(*witness_id)?;
        let anchor = anchor.to_merkle_proof(*contract_id)?;
        let anchored_bundles = AnchoredBundles::with(anchor, bundle);
        // TODO: Conceal all transitions except the one we need

        // TODO: recover Tx and SPV
        Ok(BundledWitness {
            pub_witness: witness_id.map(PubWitness::new),
            anchored_bundles,
        })
    }

    fn contracts_by_outputs(
        &self,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<BTreeSet<ContractId>, InventoryError<Self::Error>> {
        let outputs = outputs
            .into_iter()
            .map(|o| o.into())
            .collect::<BTreeSet<_>>();
        let mut selected = BTreeSet::new();
        for (contract_id, index) in &self.contract_index {
            for outpoint in &outputs {
                if index.outpoint_opouts.contains_key(outpoint) {
                    selected.insert(*contract_id);
                }
            }
        }
        Ok(selected)
    }

    fn public_opouts(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>> {
        let index = self
            .contract_index
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id))?;
        Ok(index.public_opouts.to_inner())
    }

    fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>> {
        let index = self
            .contract_index
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id))?;
        let mut opouts = BTreeSet::new();
        for output in outputs.into_iter().map(|o| o.into()) {
            let set = index
                .outpoint_opouts
                .get(&output)
                .ok_or(DataError::OutpointUnknown(output, contract_id))?;
            opouts.extend(set)
        }
        Ok(opouts)
    }

    fn opouts_by_terminals(
        &self,
        terminals: impl IntoIterator<Item = XChain<SecretSeal>>,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>> {
        let terminals = terminals.into_iter().collect::<BTreeSet<_>>();
        Ok(self
            .terminal_index
            .iter()
            .filter(|(seal, _)| terminals.contains(*seal))
            .map(|(_, opout)| *opout)
            .collect())
    }

    fn state_for_outpoints(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<XOutpoint>>,
    ) -> Result<BTreeMap<(Opout, XOutputSeal), PersistedState>, InventoryError<Self::Error>> {
        let outputs: BTreeSet<XOutpoint> = outputs.into_iter().map(|o| o.into()).collect();

        let history = self
            .history
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id))?;

        let mut res = BTreeMap::new();

        for item in history.fungibles() {
            if outputs.contains::<XOutpoint>(&item.seal.into()) {
                res.insert(
                    (item.opout, item.seal),
                    PersistedState::Amount(
                        item.state.value.into(),
                        item.state.blinding,
                        item.state.tag,
                    ),
                );
            }
        }

        for item in history.data() {
            if outputs.contains::<XOutpoint>(&item.seal.into()) {
                res.insert(
                    (item.opout, item.seal),
                    PersistedState::Data(item.state.value.clone(), item.state.salt),
                );
            }
        }

        for item in history.rights() {
            if outputs.contains::<XOutpoint>(&item.seal.into()) {
                res.insert((item.opout, item.seal), PersistedState::Void);
            }
        }

        for item in history.attach() {
            if outputs.contains::<XOutpoint>(&item.seal.into()) {
                res.insert(
                    (item.opout, item.seal),
                    PersistedState::Attachment(item.state.clone().into(), item.state.salt),
                );
            }
        }

        Ok(res)
    }

    fn store_seal_secret(
        &mut self,
        seal: XChain<GraphSeal>,
    ) -> Result<(), InventoryError<Self::Error>> {
        self.seal_secrets.push(seal)?;
        Ok(())
    }

    fn seal_secrets(&self) -> Result<BTreeSet<XChain<GraphSeal>>, InventoryError<Self::Error>> {
        Ok(self.seal_secrets.to_inner())
    }
}
