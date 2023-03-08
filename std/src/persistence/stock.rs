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
use rgb::validation::{Validity, Warning};
use rgb::{validation, ContractHistory, ContractId, ContractState, SchemaId, SubSchema};

use crate::containers::{Bindle, Cert, ContentId, ContentSigs, Contract};
use crate::interface::{ContractIface, Iface, IfaceId, IfaceImpl, IfacePair, SchemaIfaces};
use crate::persistence::Inventory;
use crate::resolvers::ResolveHeight;
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IfaceImplError {
    /// interface implementation references unknown schema {0::<0}
    UnknownSchema(SchemaId),

    /// interface implementation references unknown interface {0::<0}
    UnknownIface(IfaceId),
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    /// the consignment was not validated by the local host and thus can't be
    /// imported.
    NotValidated,

    /// consignment is invalid and can't be imported.
    #[from]
    Invalid(validation::Status),

    /// consignment has transactions which are not known and thus the contract
    /// can't be imported. If you are sure that you'd like to take the risc,
    /// call `import_contract_force`.
    UnresolvedTransactions,

    /// consignment final transactions are not yet mined. If you are sure that
    /// you'd like to take the risc, call `import_contract_force`.
    TerminalsUnmined,

    #[from]
    Confinement(confinement::Error),

    #[from]
    IfaceImpl(IfaceImplError),

    #[from]
    HeightResolver(Box<dyn std::error::Error>),
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
    history: TinyOrdMap<ContractId, ContractHistory>,
    // index
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
}

impl Inventory for Stock {
    type ImportError = Error;
    type ConsignError = Error;
    type InternalError = InternalError;

    fn import_sigs<I>(&mut self, content_id: ContentId, sigs: I) -> Result<(), Self::ImportError>
    where
        I: IntoIterator<Item = Cert>,
        I::IntoIter: ExactSizeIterator<Item = Cert>,
    {
        self.import_sigs_internal(content_id, sigs)
            .map_err(Error::from)
    }

    fn import_schema(
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
        self.import_sigs_internal(content_id, sigs).ok();

        Ok(status)
    }

    fn import_iface(
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
        self.import_sigs_internal(content_id, sigs).ok();

        Ok(status)
    }

    fn import_iface_impl(
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
        self.import_sigs_internal(content_id, sigs).ok();

        Ok(status)
    }

    fn import_contract<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, Self::ImportError>
    where
        R::Error: 'static,
    {
        self._import_contract(contract, resolver, false)
    }

    unsafe fn import_contract_force<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, Self::ImportError>
    where
        R::Error: 'static,
    {
        self._import_contract(contract, resolver, true)
    }

    fn export_contract(
        &mut self,
        _contract_id: ContractId,
    ) -> Result<Bindle<Contract>, InternalError> {
        todo!()
    }

    fn contract_iface(
        &mut self,
        contract_id: ContractId,
        iface_id: IfaceId,
    ) -> Result<ContractIface, InternalError> {
        let history = self
            .history
            .get(&contract_id)
            .ok_or(InternalError::NoContract(contract_id))?
            .clone();
        let schema_id = history.schema_id();
        let schema_ifaces = self
            .schemata
            .get(&schema_id)
            .ok_or(InternalError::NoSchema(schema_id))?;
        let state = ContractState {
            schema: schema_ifaces.schema.clone(),
            history,
        };
        let iimpl = schema_ifaces
            .iimpls
            .get(&iface_id)
            .ok_or(InternalError::NoIfaceImpl(iface_id, schema_id))?
            .clone();
        Ok(ContractIface {
            state,
            iface: iimpl,
        })
    }
}

impl Stock {
    fn _import_contract<R: ResolveHeight>(
        &mut self,
        mut contract: Contract,
        resolver: &mut R,
        force: bool,
    ) -> Result<validation::Status, Error>
    where
        R::Error: 'static,
    {
        let mut status = validation::Status::new();
        match contract.validation_status() {
            None => return Err(Error::NotValidated),
            Some(status) if status.validity() == Validity::Invalid => {
                return Err(Error::Invalid(status.clone()));
            }
            Some(status) if status.validity() == Validity::UnresolvedTransactions && !force => {
                return Err(Error::UnresolvedTransactions);
            }
            Some(status) if status.validity() == Validity::ValidExceptEndpoints && !force => {
                return Err(Error::TerminalsUnmined);
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
            .map_err(|err| Error::HeightResolver(Box::new(err)))?;
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
