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

use std::collections::BTreeMap;

use amplify::confinement::{Confined, TinyOrdMap, U8};
use amplify::{confinement, Wrapper};
use bp::secp256k1::rand::thread_rng;
use bp::{Chain, Outpoint};
use rgb::{
    fungible, Assign, FungibleType, Genesis, GlobalState, OwnedState, OwnedStateType, StateSchema,
    SubSchema, TypedAssign,
};
use strict_encoding::{SerializeError, StrictSerialize, TypeName};
use strict_types::reify;

use crate::containers::Contract;
use crate::interface::{Iface, IfaceImpl, IfacePair};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ForgeError {
    /// interface implementation references different interface that the one
    /// provided to the forge.
    InterfaceMismatch,

    /// interface implementation references different schema that the one
    /// provided to the forge.
    SchemaMismatch,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BuilderError {
    /// type `{0}` is not known to the schema.
    TypeNotFound(TypeName),

    /// state `{0}` provided to the builder has invalid type
    InvalidStateType(TypeName),

    #[from]
    #[display(inner)]
    StrictEncode(SerializeError),

    #[from]
    #[display(inner)]
    Reify(reify::Error),

    #[from]
    #[display(inner)]
    Confinement(confinement::Error),
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IssueError {}

#[derive(Clone, Debug)]
pub struct ContractBuilder {
    schema: SubSchema,
    iface: Iface,
    imp: IfaceImpl,

    chain: Chain,
    global: GlobalState,
    // rights: TinyOrdMap<OwnedStateType, Confined<BTreeSet<Outpoint>, 1, U8>>,
    fungible: TinyOrdMap<OwnedStateType, Confined<BTreeMap<Outpoint, fungible::Revealed>, 1, U8>>,
    // data: TinyOrdMap<OwnedStateType, Confined<BTreeMap<Outpoint, SmallBlob>, 1, U8>>,
    // TODO: add attachments
    // TODO: add valencies
}

impl ContractBuilder {
    pub fn with(iface: Iface, schema: SubSchema, imp: IfaceImpl) -> Result<Self, ForgeError> {
        if imp.iface_id != iface.iface_id() {
            return Err(ForgeError::InterfaceMismatch);
        }
        if imp.schema_id != schema.schema_id() {
            return Err(ForgeError::SchemaMismatch);
        }

        // TODO: check schema internal consistency
        // TODO: check interface internal consistency
        // TODO: check implmenetation internal consistency

        Ok(ContractBuilder {
            schema,
            iface,
            imp,

            chain: default!(),
            global: none!(),
            fungible: none!(),
        })
    }

    pub fn set_chain(mut self, chain: Chain) -> Self {
        self.chain = chain;
        self
    }

    pub fn add_global_state(
        mut self,
        name: impl Into<TypeName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let serialized = value.to_strict_serialized::<{ u16::MAX as usize }>()?;

        // Check value matches type requirements
        let Some(id) = self.imp.global_state.iter().find(|t| t.name == name).map(|t| t.id) else {
            return Err(BuilderError::TypeNotFound(name));
        };
        let ty_id = self
            .schema
            .global_types
            .get(&id)
            .expect("schema should match interface: must be checked by the constructor")
            .sem_id;
        self.schema.type_system.reify(ty_id, &serialized)?;

        self.global.add_state(id, serialized.into())?;

        Ok(self)
    }

    pub fn add_fungible_state(
        mut self,
        name: impl Into<TypeName>,
        seal: impl Into<Outpoint>,
        value: u64,
    ) -> Result<Self, BuilderError> {
        let name = name.into();

        let Some(id) = self.imp.owned_state.iter().find(|t| t.name == name).map(|t| t.id) else {
            return Err(BuilderError::TypeNotFound(name));
        };
        let ty = self
            .schema
            .owned_types
            .get(&id)
            .expect("schema should match interface: must be checked by the constructor");
        if *ty != StateSchema::Fungible(FungibleType::Unsigned64Bit) {
            return Err(BuilderError::InvalidStateType(name));
        }

        let state = fungible::Revealed::new(value, &mut thread_rng());
        match self.fungible.get_mut(&id) {
            Some(assignments) => {
                assignments.insert(seal.into(), state)?;
            }
            None => {
                self.fungible
                    .insert(id, Confined::with((seal.into(), state)))?;
            }
        }
        Ok(self)
    }

    pub fn issue_contract(self) -> Result<Contract, IssueError> {
        let owned_state = self.fungible.into_iter().map(|(id, vec)| {
            let vec = vec.into_iter().map(|(seal, value)| Assign::Revealed {
                seal: seal.into(),
                state: value,
            });
            let state = Confined::try_from_iter(vec).expect("at least one element");
            let state = TypedAssign::Fungible(state);
            (id, state)
        });
        let owned_state = Confined::try_from_iter(owned_state).expect("same size");
        let owned_state = OwnedState::from_inner(owned_state);

        let genesis = Genesis {
            ffv: none!(),
            schema_id: self.schema.schema_id(),
            chain: self.chain,
            metadata: None,
            global_state: self.global,
            owned_state,
            valencies: none!(),
        };

        // TODO: Validate against schema

        Ok(Contract::new(
            self.schema.clone(),
            IfacePair::with(self.iface.clone(), self.imp.clone()),
            genesis,
        ))
    }
}
