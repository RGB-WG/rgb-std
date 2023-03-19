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

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::ops::{Deref, DerefMut};

use amplify::confinement::{self, Confined, MediumOrdMap, MediumOrdSet, TinyOrdMap};
use rgb::validation::{Validity, Warning};
use rgb::{
    validation, AnchoredBundle, BundleId, ContractHistory, ContractId, ContractState, OpId, Opout,
    SubSchema,
};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::containers::{Bindle, Cert, ContentId, ContentSigs, Contract};
use crate::interface::{ContractIface, Iface, IfaceId, IfaceImpl, IfacePair, SchemaIfaces};
use crate::persistence::inventory::{DataError, IfaceImplError, InventoryInconsistency};
use crate::persistence::{
    Hoard, Inventory, InventoryDataError, InventoryError, StashInconsistency,
};
use crate::resolvers::ResolveHeight;
use crate::{Outpoint, LIB_NAME_RGB_STD};

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub(super) struct IndexedBundle(ContractId, BundleId);

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
#[derive(Clone, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct Stock {
    // stash
    hoard: Hoard,
    // state
    history: TinyOrdMap<ContractId, ContractHistory>,
    // index
    bundle_op_index: MediumOrdMap<OpId, IndexedBundle>,
    contract_index: TinyOrdMap<ContractId, ContractIndex>,
}

impl Default for Stock {
    fn default() -> Self {
        Stock {
            hoard: Hoard::preset(),
            history: empty!(),
            bundle_op_index: empty!(),
            contract_index: empty!(),
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

impl Stock {
    fn import_sigs_internal<I>(
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

    fn _import_contract<R: ResolveHeight>(
        &mut self,
        mut contract: Contract,
        resolver: &mut R,
        force: bool,
    ) -> Result<validation::Status, InventoryDataError<Infallible>>
    where
        R::Error: 'static,
    {
        let mut status = validation::Status::new();
        match contract.validation_status() {
            None => return Err(DataError::NotValidated.into()),
            Some(status) if status.validity() == Validity::Invalid => {
                return Err(DataError::Invalid(status.clone()).into());
            }
            Some(status) if status.validity() == Validity::UnresolvedTransactions && !force => {
                return Err(DataError::UnresolvedTransactions.into());
            }
            Some(status) if status.validity() == Validity::ValidExceptEndpoints && !force => {
                return Err(DataError::TerminalsUnmined.into());
            }
            Some(s) if s.validity() == Validity::UnresolvedTransactions && !force => {
                status.add_warning(Warning::Custom(s!(
                    "contract contains unknown transactions and was forcefully imported"
                )));
            }
            Some(s) if s.validity() == Validity::ValidExceptEndpoints && !force => {
                status.add_warning(Warning::Custom(s!("contract contains not yet mined final \
                                                       transactions and was forcefully imported")));
            }
            _ => {}
        }

        let id = contract.contract_id();

        self.import_schema(contract.schema.clone())?;
        for IfacePair { iface, iimpl } in contract.ifaces.values() {
            self.import_iface(iface.clone())?;
            self.import_iface_impl(iimpl.clone())?;
        }
        for (content_id, sigs) in contract.signatures {
            // Do not bother if we can't import all the sigs
            self.import_sigs_internal(content_id, sigs).ok();
        }
        contract.signatures = none!();

        // TODO: Update existing contract state
        let history = contract
            .build_history(resolver)
            .map_err(|err| DataError::HeightResolver(Box::new(err)))?;
        self.history.insert(id, history)?;

        // TODO: Merge contracts
        if self.contracts.insert(id, contract)?.is_some() {
            status.add_warning(Warning::Custom(format!(
                "contract {id::<0} has replaced previously known contract version",
            )));
        }

        Ok(status)
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
    ) -> Result<validation::Status, InventoryDataError<Self::Error>>
    where
        R::Error: 'static,
    {
        self._import_contract(contract, resolver, false)
            .map_err(InventoryDataError::from)
    }

    unsafe fn import_contract_force<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, InventoryDataError<Self::Error>>
    where
        R::Error: 'static,
    {
        self._import_contract(contract, resolver, true)
            .map_err(InventoryDataError::from)
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

    // TODO: Should return anchored bundle with the transition revealed
    fn anchored_bundle(&self, opid: OpId) -> Result<&AnchoredBundle, InventoryError<Self::Error>> {
        let IndexedBundle(contract_id, bundle_id) = self
            .bundle_op_index
            .get(&opid)
            .ok_or(StashInconsistency::TransitionAbsent(opid))?;
        let anchored_bundle = self
            .contract(*contract_id)?
            .anchored_bundle(*bundle_id)
            .ok_or(StashInconsistency::BundleAbsent(*contract_id, *bundle_id))?;
        Ok(anchored_bundle)
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

    fn outpoint_opouts(
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
}
