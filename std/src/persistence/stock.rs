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

use amplify::confinement::{self, Confined, SmallOrdMap, TinyOrdMap};
use rgb::validation::Warning;
use rgb::{validation, ContractId, ContractState, SchemaId, SubSchema};

use crate::containers::{Bindle, Cert, ContentId, ContentSigs, Contract};
use crate::interface::{ContractIface, Iface, IfaceId, IfaceImpl, SchemaIfaces};
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IfaceImplError {
    /// interface implementation references unknown schema {0::<0}
    UnknownSchema(SchemaId),

    /// interface implementation references unknown interface {0::<0}
    UnknownIface(IfaceId),
}

#[derive(Clone, Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from]
    Invalid(validation::Status),

    #[from]
    Confinement(confinement::Error),

    #[from]
    IfaceImpl(IfaceImplError),
}

/// Stock is an in-memory inventory (stash, index, contract state) usefult for
/// WASM implementations.
#[derive(Clone, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct Stock {
    // stash
    schemata: TinyOrdMap<SchemaId, SchemaIfaces>,
    ifaces: TinyOrdMap<IfaceId, Iface>,
    contracts: TinyOrdMap<ContractId, Contract>,
    sigs: SmallOrdMap<ContentId, ContentSigs>,

    // state
    state: TinyOrdMap<ContractId, ContractState>,
    // index
}

impl Stock {
    pub fn import_sigs<I>(
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

    pub fn import_schema(
        &mut self,
        schema: impl Into<Bindle<SubSchema>>,
    ) -> Result<validation::Status, Error> {
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
        self.import_sigs(content_id, sigs).ok();

        Ok(status)
    }

    pub fn import_iface(
        &mut self,
        iface: impl Into<Bindle<Iface>>,
    ) -> Result<validation::Status, Error> {
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
        self.import_sigs(content_id, sigs).ok();

        Ok(status)
    }

    pub fn import_iface_impl(
        &mut self,
        iimpl: impl Into<Bindle<IfaceImpl>>,
    ) -> Result<validation::Status, Error> {
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
        self.import_sigs(content_id, sigs).ok();

        Ok(status)
    }

    pub fn import_contract(
        &mut self,
        iimpl: impl Into<Bindle<Contract>>,
    ) -> Result<validation::Status, Error> {
        todo!()
    }

    pub fn export_contract(
        &mut self,
        contract_id: ContractId,
    ) -> Result<Bindle<Contract>, InternalError> {
        todo!()
    }

    pub fn contract_iface(
        &mut self,
        contract_id: ContractId,
        iface_id: IfaceId,
    ) -> Result<ContractIface, InternalError> {
        let contract_state = self
            .state
            .get(&contract_id)
            .ok_or(InternalError::NoContract(contract_id))?
            .clone();
        let schema_id = contract_state.schema_id();
        let schema = self
            .schemata
            .get(schema_id)
            .ok_or(InternalError::NoSchema(*schema_id))?;
        let iimpl = schema
            .iimpls
            .get(&iface_id)
            .ok_or(InternalError::NoIfaceImpl(iface_id, *schema_id))?
            .clone();
        Ok(ContractIface {
            state: contract_state,
            iface: iimpl,
        })
    }
}

/// Errors caused by internal inconsistency of the Stock object data. This is
/// possible due to the modification of the stored data from outside of this
/// library.
#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum InternalError {
    /// contract is absent - {0::<0}.
    NoContract(ContractId),

    /// schema is absent - {0::<0}.
    NoSchema(SchemaId),

    /// interface {0::<0} is not implemented for the schema {1::<0}.
    NoIfaceImpl(IfaceId, SchemaId),
}
