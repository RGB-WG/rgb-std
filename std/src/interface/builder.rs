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
use std::ops::{Deref, DerefMut};

use amplify::confinement::{Confined, TinyOrdMap, U8};
use amplify::{confinement, Wrapper};
use bp::secp256k1::rand::thread_rng;
use bp::{Chain, Outpoint};
use rgb::{
    fungible, Assign, AssignmentType, Assignments, ExposedSeal, FungibleType, Genesis, GlobalState,
    PrevOuts, StateSchema, SubSchema, Transition, TransitionType, TypedAssigns,
};
use strict_encoding::{SerializeError, StrictSerialize, TypeName};
use strict_types::decode;

use crate::containers::Contract;
use crate::interface::{Iface, IfaceImpl, IfacePair};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BuilderError {
    /// interface implementation references different interface that the one
    /// provided to the forge.
    InterfaceMismatch,

    /// interface implementation references different schema that the one
    /// provided to the forge.
    SchemaMismatch,

    /// type `{0}` is not known to the schema.
    TypeNotFound(TypeName),

    /// state `{0}` provided to the builder has invalid type
    InvalidStateType(TypeName),

    /// interface doesn't specifies default operation name, thus an explicit
    /// operation type must be provided with `set_operation_type` method.
    NoOperationSubtype,

    #[from]
    #[display(inner)]
    StrictEncode(SerializeError),

    #[from]
    #[display(inner)]
    Reify(decode::Error),

    #[from]
    #[display(inner)]
    Confinement(confinement::Error),
}

#[derive(Clone, Debug)]
pub struct ContractBuilder {
    builder: OperationBuilder,
    chain: Chain,
}

impl Deref for ContractBuilder {
    type Target = OperationBuilder;
    fn deref(&self) -> &Self::Target { &self.builder }
}

impl DerefMut for ContractBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.builder }
}

impl ContractBuilder {
    pub fn with(iface: Iface, schema: SubSchema, iimpl: IfaceImpl) -> Result<Self, BuilderError> {
        Ok(Self {
            builder: OperationBuilder::with(iface, schema, iimpl)?,
            chain: default!(),
        })
    }

    pub fn set_chain(mut self, chain: Chain) -> Self {
        self.chain = chain;
        self
    }

    pub fn issue_contract(self) -> Result<Contract, BuilderError> {
        let (schema, iface_pair, global, assignments) = self.builder.complete();

        let genesis = Genesis {
            ffv: none!(),
            schema_id: schema.schema_id(),
            chain: self.chain,
            metadata: empty!(),
            globals: global,
            assignments,
            valencies: none!(),
        };

        // TODO: Validate against schema

        let mut contract = Contract::new(schema, genesis);
        contract.ifaces = tiny_bmap! { iface_pair.iface_id() => iface_pair };

        Ok(contract)
    }
}

#[derive(Clone, Debug)]
pub struct TransitionBuilder {
    builder: OperationBuilder,
    transition_type: Option<TransitionType>,
    inputs: PrevOuts,
}

impl Deref for TransitionBuilder {
    type Target = OperationBuilder;
    fn deref(&self) -> &Self::Target { &self.builder }
}

impl DerefMut for TransitionBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.builder }
}

impl TransitionBuilder {
    pub fn with(iface: Iface, schema: SubSchema, iimpl: IfaceImpl) -> Result<Self, BuilderError> {
        Ok(Self {
            builder: OperationBuilder::with(iface, schema, iimpl)?,
            transition_type: None,
            inputs: none!(),
        })
    }

    pub fn complete_transition(self) -> Result<Transition, BuilderError> {
        let (_, pair, global, assignments) = self.builder.complete();

        let transition_type = self
            .transition_type
            .or_else(|| {
                pair.iface
                    .default_operation
                    .as_ref()
                    .and_then(|name| pair.transition_type(name))
            })
            .ok_or(BuilderError::NoOperationSubtype)?;

        let transition = Transition {
            ffv: none!(),
            transition_type,
            metadata: empty!(),
            globals: global,
            inputs: self.inputs,
            assignments,
            valencies: none!(),
        };

        // TODO: Validate against schema

        Ok(transition)
    }
}

#[derive(Clone, Debug)]
pub struct OperationBuilder {
    schema: SubSchema,
    iface: Iface,
    iimpl: IfaceImpl,

    global: GlobalState,
    // rights: TinyOrdMap<AssignmentType, Confined<BTreeSet<Outpoint>, 1, U8>>,
    fungible: TinyOrdMap<AssignmentType, Confined<BTreeMap<Outpoint, fungible::Revealed>, 1, U8>>,
    // data: TinyOrdMap<AssignmentType, Confined<BTreeMap<Outpoint, SmallBlob>, 1, U8>>,
    // TODO: add attachments
    // TODO: add valencies
}

impl OperationBuilder {
    pub fn with(iface: Iface, schema: SubSchema, iimpl: IfaceImpl) -> Result<Self, BuilderError> {
        if iimpl.iface_id != iface.iface_id() {
            return Err(BuilderError::InterfaceMismatch);
        }
        if iimpl.schema_id != schema.schema_id() {
            return Err(BuilderError::SchemaMismatch);
        }

        // TODO: check schema internal consistency
        // TODO: check interface internal consistency
        // TODO: check implmenetation internal consistency

        Ok(OperationBuilder {
            schema,
            iface,
            iimpl,

            global: none!(),
            fungible: none!(),
        })
    }

    pub fn add_global_state(
        mut self,
        name: impl Into<TypeName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let serialized = value.to_strict_serialized::<{ u16::MAX as usize }>()?;

        // Check value matches type requirements
        let Some(id) = self.iimpl.global_state.iter().find(|t| t.name == name).map(|t| t.id) else {
            return Err(BuilderError::TypeNotFound(name));
        };
        let ty_id = self
            .schema
            .global_types
            .get(&id)
            .expect("schema should match interface: must be checked by the constructor")
            .sem_id;
        self.schema
            .type_system
            .strict_deserialize_type(ty_id, &serialized)?;

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

        let Some(id) = self.iimpl.owned_state.iter().find(|t| t.name == name).map(|t| t.id) else {
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

    fn complete<Seal: ExposedSeal>(self) -> (SubSchema, IfacePair, GlobalState, Assignments<Seal>) {
        let owned_state = self.fungible.into_iter().map(|(id, vec)| {
            let vec = vec.into_iter().map(|(seal, value)| Assign::Revealed {
                seal: seal.into(),
                state: value,
            });
            let state = Confined::try_from_iter(vec).expect("at least one element");
            let state = TypedAssigns::Fungible(state);
            (id, state)
        });
        let owned_state = Confined::try_from_iter(owned_state).expect("same size");
        let assignments = Assignments::from_inner(owned_state);

        let iface_pair = IfacePair::with(self.iface.clone(), self.iimpl);

        (self.schema, iface_pair, self.global, assignments)
    }
}
