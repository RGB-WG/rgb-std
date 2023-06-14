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
use std::ops::{Deref, DerefMut};

use amplify::confinement::{MediumOrdMap, MediumOrdSet, TinyOrdMap};
use amplify::RawArray;
use bp::dbc::Anchor;
use bp::Txid;
use commit_verify::mpc::MerkleBlock;
use rgb::validation::{Status, Validity, Warning};
use rgb::{
    validation, AnchorId, AnchoredBundle, Assign, AssignmentType, BundleId, ContractHistory,
    ContractId, ContractState, ExposedState, Extension, Genesis, GenesisSeal, GraphSeal, OpId,
    Operation, Opout, SecretSeal, SubSchema, Transition, TransitionBundle, TxoSeal, TypedAssigns,
};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::containers::{Bindle, Cert, Consignment, ContentId, Contract, TerminalSeal, Transfer};
use crate::interface::{
    ContractIface, Iface, IfaceId, IfaceImpl, IfacePair, SchemaIfaces, TypedState,
};
use crate::persistence::inventory::{DataError, IfaceImplError, InventoryInconsistency};
use crate::persistence::{
    Hoard, Inventory, InventoryDataError, InventoryError, Stash, StashInconsistency,
};
use crate::resolvers::ResolveHeight;
use crate::{Outpoint, LIB_NAME_RGB_STD};

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct IndexedBundle(ContractId, BundleId);

#[derive(Clone, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct ContractIndex {
    public_opouts: MediumOrdSet<Opout>,
    outpoint_opouts: MediumOrdMap<Outpoint, MediumOrdSet<Opout>>,
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
    bundle_op_index: MediumOrdMap<OpId, IndexedBundle>,
    anchor_bundle_index: MediumOrdMap<BundleId, AnchorId>,
    contract_index: TinyOrdMap<ContractId, ContractIndex>,
    terminal_index: MediumOrdMap<SecretSeal, Opout>,
    // secrets
    seal_secrets: MediumOrdSet<GraphSeal>,
}

impl Default for Stock {
    fn default() -> Self {
        Stock {
            hoard: Hoard::preset(),
            history: empty!(),
            bundle_op_index: empty!(),
            anchor_bundle_index: empty!(),
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
        for terminal in consignment.terminals.clone() {
            if let TerminalSeal::ConcealedUtxo(secret) = terminal.seal {
                if let Some(seal) = self
                    .seal_secrets
                    .iter()
                    .find(|s| s.to_concealed_seal() == secret)
                {
                    consignment.reveal_bundle_seal(terminal.bundle_id, *seal);
                }
            }
        }

        // Update existing contract state
        let history = consignment
            .update_history(self.history.get(&id), resolver)
            .map_err(|err| DataError::HeightResolver(Box::new(err)))?;
        self.history.insert(id, history)?;

        let contract_id = consignment.contract_id();
        self.contract_index.insert(contract_id, ContractIndex {
            public_opouts: empty!(),
            outpoint_opouts: empty!(),
        })?;
        self.index_genesis(contract_id, &consignment.genesis)?;
        for extension in &consignment.extensions {
            self.index_extension(contract_id, extension)?;
        }
        for AnchoredBundle { anchor, bundle } in &mut consignment.bundles {
            let bundle_id = bundle.bundle_id();
            let anchor_id = anchor.anchor_id(contract_id, bundle_id.into())?;
            self.anchor_bundle_index.insert(bundle_id, anchor_id)?;
            self.index_bundle(contract_id, bundle, anchor.txid)?;
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
        witness_txid: Txid,
    ) -> Result<(), InventoryError<<Self as Inventory>::Error>> {
        let bundle_id = bundle.bundle_id();
        for (opid, item) in bundle.iter() {
            if let Some(transition) = &item.transition {
                self.bundle_op_index
                    .insert(*opid, IndexedBundle(id, bundle_id))?;
                for (type_id, assign) in transition.assignments.iter() {
                    match assign {
                        TypedAssigns::Declarative(vec) => {
                            self.index_transition_assignments(
                                id,
                                vec,
                                *opid,
                                *type_id,
                                witness_txid,
                            )?;
                        }
                        TypedAssigns::Fungible(vec) => {
                            self.index_transition_assignments(
                                id,
                                vec,
                                *opid,
                                *type_id,
                                witness_txid,
                            )?;
                        }
                        TypedAssigns::Structured(vec) => {
                            self.index_transition_assignments(
                                id,
                                vec,
                                *opid,
                                *type_id,
                                witness_txid,
                            )?;
                        }
                        TypedAssigns::Attachment(vec) => {
                            self.index_transition_assignments(
                                id,
                                vec,
                                *opid,
                                *type_id,
                                witness_txid,
                            )?;
                        }
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
                let outpoint = seal.outpoint_or(seal.txid);
                match index.outpoint_opouts.get_mut(&outpoint) {
                    Some(opouts) => {
                        opouts.push(opout)?;
                    }
                    None => {
                        index
                            .outpoint_opouts
                            .insert(outpoint, confined_bset!(opout))?;
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
        witness_txid: Txid,
    ) -> Result<(), InventoryError<<Self as Inventory>::Error>> {
        let index = self
            .contract_index
            .get_mut(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id))?;

        for (no, a) in vec.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            if let Assign::ConfidentialState { seal, .. } | Assign::Revealed { seal, .. } = a {
                let outpoint = seal.outpoint_or(witness_txid);
                match index.outpoint_opouts.get_mut(&outpoint) {
                    Some(opouts) => {
                        opouts.push(opout)?;
                    }
                    None => {
                        index
                            .outpoint_opouts
                            .insert(outpoint, confined_bset!(opout))?;
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
        schema: impl Into<Bindle<SubSchema>>,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>> {
        let bindle = schema.into();
        let (schema, sigs) = bindle.into_split();
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

        let content_id = ContentId::Schema(id);
        // Do not bother if we can't import all the sigs
        self.import_sigs_internal(content_id, sigs).ok();

        Ok(status)
    }

    fn import_iface(
        &mut self,
        iface: impl Into<Bindle<Iface>>,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>> {
        let bindle = iface.into();
        let (iface, sigs) = bindle.into_split();
        let id = iface.iface_id();

        let mut status = validation::Status::new();

        // TODO: Do interface check on internal consistency
        if self.ifaces.insert(id, iface)?.is_some() {
            status.add_warning(Warning::Custom(format!("interface {id::<0} is already known")));
        }

        let content_id = ContentId::Iface(id);
        // Do not bother if we can't import all the sigs
        self.import_sigs_internal(content_id, sigs).ok();

        Ok(status)
    }

    fn import_iface_impl(
        &mut self,
        iimpl: impl Into<Bindle<IfaceImpl>>,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>> {
        let bindle = iimpl.into();
        let (iimpl, sigs) = bindle.into_split();
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

        let content_id = ContentId::IfaceImpl(impl_id);
        // Do not bother if we can't import all the sigs
        self.import_sigs_internal(content_id, sigs).ok();

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
    ) -> Result<Status, InventoryError<Self::Error>>
    where
        R::Error: 'static,
    {
        self.consume_consignment(transfer, resolver, force)
    }

    fn consume_anchor(
        &mut self,
        anchor: Anchor<MerkleBlock>,
    ) -> Result<(), InventoryError<Self::Error>> {
        let anchor_id = anchor.anchor_id();
        for (_, bundle_id) in anchor.mpc_proof.to_known_message_map() {
            self.anchor_bundle_index
                .insert(bundle_id.to_raw_array().into(), anchor_id)?;
        }
        self.hoard.consume_anchor(anchor)?;
        Ok(())
    }

    fn consume_bundle(
        &mut self,
        contract_id: ContractId,
        bundle: TransitionBundle,
        witness_txid: Txid,
    ) -> Result<(), InventoryError<<Self as Inventory>::Error>> {
        self.index_bundle(contract_id, &bundle, witness_txid)?;
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

    fn contract_iface(
        &mut self,
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
        let IndexedBundle(_, bundle_id) = self
            .bundle_op_index
            .get(&opid)
            .ok_or(InventoryInconsistency::BundleAbsent(opid))?;
        let bundle = self.bundle(*bundle_id)?;
        let item = bundle.get(&opid).ok_or(DataError::Concealed)?;
        let transition = item.transition.as_ref().ok_or(DataError::Concealed)?;
        Ok(transition)
    }

    fn anchored_bundle(&self, opid: OpId) -> Result<AnchoredBundle, InventoryError<Self::Error>> {
        let IndexedBundle(contract_id, bundle_id) = self
            .bundle_op_index
            .get(&opid)
            .ok_or(InventoryInconsistency::BundleAbsent(opid))?;

        let anchor_id = self
            .anchor_bundle_index
            .get(bundle_id)
            .ok_or(InventoryInconsistency::NoBundleAnchor(*bundle_id))?;

        let bundle = self.bundle(*bundle_id)?.clone();
        let anchor = self.anchor(*anchor_id)?;
        let anchor = anchor.to_merkle_proof(*contract_id)?;
        // TODO: Conceal all transitions except the one we need

        Ok(AnchoredBundle { anchor, bundle })
    }

    fn contracts_by_outpoints(
        &mut self,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeSet<ContractId>, InventoryError<Self::Error>> {
        let outpoints = outpoints
            .into_iter()
            .map(|o| o.into())
            .collect::<BTreeSet<_>>();
        let mut selected = BTreeSet::new();
        for (contract_id, index) in &self.contract_index {
            for outpoint in &outpoints {
                if index.outpoint_opouts.contains_key(outpoint) {
                    selected.insert(*contract_id);
                }
            }
        }
        Ok(selected)
    }

    fn public_opouts(
        &mut self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>> {
        let index = self
            .contract_index
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id))?;
        Ok(index.public_opouts.to_inner())
    }

    fn opouts_by_outpoints(
        &mut self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeSet<Opout>, InventoryError<Self::Error>> {
        let index = self
            .contract_index
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id))?;
        let mut opouts = BTreeSet::new();
        for outpoint in outpoints.into_iter().map(|o| o.into()) {
            let set = index
                .outpoint_opouts
                .get(&outpoint)
                .ok_or(DataError::OutpointUnknown(outpoint, contract_id))?;
            opouts.extend(set)
        }
        Ok(opouts)
    }

    fn opouts_by_terminals(
        &mut self,
        terminals: impl IntoIterator<Item = SecretSeal>,
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
        &mut self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeMap<Opout, TypedState>, InventoryError<Self::Error>> {
        let outpoints = outpoints
            .into_iter()
            .map(|o| o.into())
            .collect::<BTreeSet<_>>();

        let history = self
            .history
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id))?;

        let mut res = BTreeMap::new();

        for output in history.fungibles() {
            if outpoints.contains(&output.seal) {
                res.insert(output.opout, TypedState::Amount(output.state.value.as_u64()));
            }
        }

        for output in history.data() {
            if outpoints.contains(&output.seal) {
                res.insert(output.opout, TypedState::Data(output.state.clone()));
            }
        }

        for output in history.rights() {
            if outpoints.contains(&output.seal) {
                res.insert(output.opout, TypedState::Void);
            }
        }

        for output in history.attach() {
            if outpoints.contains(&output.seal) {
                res.insert(output.opout, TypedState::Attachment(output.state.clone().into()));
            }
        }

        Ok(res)
    }

    fn store_seal_secret(&mut self, seal: GraphSeal) -> Result<(), InventoryError<Self::Error>> {
        self.seal_secrets.push(seal)?;
        Ok(())
    }

    fn seal_secrets(&mut self) -> Result<BTreeSet<GraphSeal>, InventoryError<Self::Error>> {
        Ok(self.seal_secrets.to_inner())
    }
}
