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

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashSet};

use amplify::confinement::{Confined, NonEmptyOrdSet, TinyOrdMap, U16};
use amplify::{confinement, Wrapper};
use chrono::Utc;
use invoice::Amount;
use rgb::assignments::AssignVec;
use rgb::validation::Scripts;
use rgb::{
    validation, Assign, AssignmentType, Assignments, ChainNet, ContractId, ExposedSeal,
    FungibleType, Genesis, GenesisSeal, GlobalState, GraphSeal, Identity, Layer1, MetadataError,
    Opout, OwnedStateSchema, RevealedData, RevealedValue, Schema, Transition, TransitionType,
    TypedAssigns,
};
use rgbcore::{GlobalStateSchema, GlobalStateType, MetaType, Metadata};
use strict_encoding::{FieldName, SerializeError, StrictSerialize};
use strict_types::{decode, SemId, TypeSystem};

use crate::containers::{BuilderSeal, ContainerVer, Contract, ValidConsignment};
use crate::contract::resolver::DumbResolver;
use crate::contract::AllocatedState;
use crate::persistence::StashInconsistency;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BuilderError {
    #[from]
    #[display(inner)]
    MetadataInvalid(MetadataError),

    /// unknown owned state name `{0}`.
    InvalidStateField(FieldName),

    /// state `{0}` provided to the builder has invalid type.
    InvalidStateType(AssignmentType),

    /// {0} is not supported by the contract genesis.
    InvalidLayer1(Layer1),

    #[from]
    #[display(inner)]
    StrictEncode(SerializeError),

    #[from]
    #[display(inner)]
    Reify(decode::Error),

    #[from]
    #[display(inner)]
    Confinement(confinement::Error),

    #[from]
    #[display(doc_comments)]
    Inconsistency(StashInconsistency),

    #[from]
    #[display(inner)]
    ContractInconsistency(validation::Status),
}

#[derive(Clone, Debug)]
pub struct ContractBuilder {
    builder: OperationBuilder<GenesisSeal>,
    scripts: Scripts,
    issuer: Identity,
    chain_net: ChainNet,
}

impl ContractBuilder {
    pub fn with(
        issuer: Identity,
        schema: Schema,
        types: TypeSystem,
        scripts: Scripts,
        chain_net: ChainNet,
    ) -> Self {
        Self {
            builder: OperationBuilder::with(schema, types),
            scripts,
            issuer,
            chain_net,
        }
    }

    pub fn type_system(&self) -> &TypeSystem { self.builder.type_system() }

    #[inline]
    pub fn global_type(&self, name: impl Into<FieldName>) -> GlobalStateType {
        self.builder.global_type(name)
    }

    #[inline]
    pub fn meta_name(&self, type_id: MetaType) -> &FieldName { self.builder.meta_name(type_id) }

    #[inline]
    pub fn add_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_metadata(name, value)?;
        Ok(self)
    }

    #[inline]
    pub fn add_metadata_raw(
        mut self,
        type_id: MetaType,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_metadata_raw(type_id, value)?;
        Ok(self)
    }

    #[inline]
    pub fn add_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_global_state(name, value)?;
        Ok(self)
    }

    #[inline]
    pub fn add_global_state_raw(
        mut self,
        type_id: GlobalStateType,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_global_state_raw(type_id, value)?;
        Ok(self)
    }

    pub fn add_rights(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.builder = self.builder.add_rights(name, seal)?;
        Ok(self)
    }

    pub fn add_rights_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.builder = self.builder.add_rights_raw(type_id, seal)?;
        Ok(self)
    }

    pub fn add_fungible_state(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        value: impl Into<Amount>,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.builder = self.builder.add_fungible_state(name, seal, value)?;
        Ok(self)
    }

    pub fn add_fungible_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        value: impl Into<Amount>,
    ) -> Result<Self, BuilderError> {
        let state = RevealedValue::new(value.into());
        self.builder = self.builder.add_fungible_state_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn add_data(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.builder = self.builder.add_data(name, seal, value)?;
        Ok(self)
    }

    pub fn add_data_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        state: RevealedData,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.builder = self.builder.add_data_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn issue_contract(self) -> Result<ValidConsignment<false>, BuilderError> {
        self.issue_contract_raw(Utc::now().timestamp())
    }

    pub fn issue_contract_raw(
        self,
        timestamp: i64,
    ) -> Result<ValidConsignment<false>, BuilderError> {
        let (schema, global, assignments, types, metadata) = self.builder.complete();

        let genesis = Genesis {
            ffv: none!(),
            schema_id: schema.schema_id(),
            timestamp,
            chain_net: self.chain_net,
            seal_closing_strategy: Default::default(),
            metadata,
            globals: global,
            assignments,
            issuer: self.issuer,
        };

        let scripts = Confined::from_iter_checked(self.scripts.into_values());

        let contract = Contract {
            version: ContainerVer::V0,
            transfer: false,
            terminals: none!(),
            genesis,
            bundles: none!(),
            schema,

            types,
            scripts,
        };

        let valid_contract = contract.validate(&DumbResolver, self.chain_net, None)?;

        Ok(valid_contract)
    }
}

#[derive(Clone, Debug)]
pub struct TransitionBuilder {
    contract_id: ContractId,
    builder: OperationBuilder<GraphSeal>,
    nonce: u64,
    transition_type: TransitionType,
    inputs: TinyOrdMap<Opout, AllocatedState>,
}

impl TransitionBuilder {
    pub fn named_transition(
        contract_id: ContractId,
        schema: Schema,
        transition_name: impl Into<FieldName>,
        types: TypeSystem,
    ) -> Result<Self, BuilderError> {
        let transition_type = schema.transition_type(transition_name);
        Ok(Self::with(contract_id, schema, transition_type, types))
    }

    pub fn with(
        contract_id: ContractId,
        schema: Schema,
        transition_type: TransitionType,
        types: TypeSystem,
    ) -> Self {
        Self {
            contract_id,
            builder: OperationBuilder::with(schema, types),
            nonce: u64::MAX,
            transition_type,
            inputs: none!(),
        }
    }

    pub fn type_system(&self) -> &TypeSystem { self.builder.type_system() }

    pub fn transition_type(&self) -> TransitionType { self.transition_type }

    pub fn set_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    #[inline]
    pub fn add_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_metadata(name, value)?;
        Ok(self)
    }

    #[inline]
    pub fn add_metadata_raw(
        mut self,
        type_id: MetaType,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_metadata_raw(type_id, value)?;
        Ok(self)
    }

    #[inline]
    pub fn add_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_global_state(name, value)?;
        Ok(self)
    }

    pub fn add_input(mut self, opout: Opout, state: AllocatedState) -> Result<Self, BuilderError> {
        self.inputs.insert(opout, state)?;
        Ok(self)
    }

    #[inline]
    pub fn assignment_type(&self, name: impl Into<FieldName>) -> AssignmentType {
        self.builder.assignment_type(name)
    }

    #[inline]
    pub fn global_type(&self, name: impl Into<FieldName>) -> GlobalStateType {
        self.builder.global_type(name)
    }

    #[inline]
    pub fn meta_name(&self, type_id: MetaType) -> &FieldName { self.builder.meta_name(type_id) }

    pub fn add_owned_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        state: AllocatedState,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_owned_state_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn add_rights(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_rights(name, seal)?;
        Ok(self)
    }

    pub fn add_rights_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_rights_raw(type_id, seal)?;
        Ok(self)
    }

    pub fn add_fungible_state(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: impl Into<Amount>,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_fungible_state(name, seal, value)?;
        Ok(self)
    }

    pub fn add_fungible_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: impl Into<Amount>,
    ) -> Result<Self, BuilderError> {
        let state = RevealedValue::new(value.into());
        self.builder = self.builder.add_fungible_state_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn add_data(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_data(name, seal, value)?;
        Ok(self)
    }

    pub fn add_data_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        state: RevealedData,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_data_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn has_inputs(&self) -> bool { !self.inputs.is_empty() }

    pub fn complete_transition(self) -> Result<Transition, BuilderError> {
        let (_, global, assignments, _, metadata) = self.builder.complete();

        let transition = Transition {
            ffv: none!(),
            contract_id: self.contract_id,
            nonce: self.nonce,
            transition_type: self.transition_type,
            metadata,
            globals: global,
            inputs: NonEmptyOrdSet::from_iter_checked(self.inputs.into_keys()).into(),
            assignments,
            signature: none!(),
        };

        // TODO: Validate against schema

        Ok(transition)
    }
}

#[derive(Clone, Debug)]
pub struct OperationBuilder<Seal: ExposedSeal> {
    schema: Schema,

    global: GlobalState,
    meta: Metadata,
    rights: TinyOrdMap<AssignmentType, Confined<HashSet<BuilderSeal<Seal>>, 1, U16>>,
    fungible:
        TinyOrdMap<AssignmentType, Confined<BTreeMap<BuilderSeal<Seal>, RevealedValue>, 1, U16>>,
    data: TinyOrdMap<AssignmentType, Confined<BTreeMap<BuilderSeal<Seal>, RevealedData>, 1, U16>>,
    types: TypeSystem,
}

impl<Seal: ExposedSeal> OperationBuilder<Seal> {
    fn with(schema: Schema, types: TypeSystem) -> Self {
        OperationBuilder {
            schema,

            global: none!(),
            meta: none!(),
            rights: none!(),
            fungible: none!(),
            data: none!(),

            types,
        }
    }

    fn type_system(&self) -> &TypeSystem { &self.types }

    fn assignment_type(&self, name: impl Into<FieldName>) -> AssignmentType {
        self.schema.assignment_type(name)
    }

    fn meta_type(&self, name: impl Into<FieldName>) -> MetaType { self.schema.meta_type(name) }

    fn meta_name(&self, ty: MetaType) -> &FieldName { self.schema.meta_name(ty) }

    fn global_type(&self, name: impl Into<FieldName>) -> GlobalStateType {
        self.schema.global_type(name)
    }

    #[inline]
    fn state_schema(&self, type_id: AssignmentType) -> &OwnedStateSchema {
        &self
            .schema
            .owned_types
            .get(&type_id)
            .expect("schema should support the assignment type: must be checked by the constructor")
            .owned_state_schema
    }

    #[inline]
    fn meta_schema(&self, type_id: MetaType) -> &SemId {
        &self
            .schema
            .meta_types
            .get(&type_id)
            .expect("schema should support the meta type: must be checked by the constructor")
            .sem_id
    }

    #[inline]
    fn global_schema(&self, type_id: GlobalStateType) -> &GlobalStateSchema {
        &self
            .schema
            .global_types
            .get(&type_id)
            .expect(
                "schema should support the global state type: must be checked by the constructor",
            )
            .global_state_schema
    }

    pub fn add_metadata(
        self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let type_id = self.meta_type(name);
        self.add_metadata_raw(type_id, value)
    }

    pub fn add_metadata_raw(
        mut self,
        type_id: MetaType,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let serialized = value.to_strict_serialized::<{ u16::MAX as usize }>()?;

        let sem_id = self.meta_schema(type_id);
        self.types.strict_deserialize_type(*sem_id, &serialized)?;
        self.meta.add_value(type_id, serialized.into())?;
        Ok(self)
    }

    pub fn add_global_state(
        self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let type_id = self.global_type(name);
        self.add_global_state_raw(type_id, value)
    }

    pub fn add_global_state_raw(
        mut self,
        type_id: GlobalStateType,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let serialized = value.to_strict_serialized::<{ u16::MAX as usize }>()?;

        // Check value matches type requirements
        let sem_id = self.global_schema(type_id).sem_id;
        self.types.strict_deserialize_type(sem_id, &serialized)?;

        self.global.add_state(type_id, serialized.into())?;

        Ok(self)
    }

    fn add_owned_state_raw(
        self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: AllocatedState,
    ) -> Result<Self, BuilderError> {
        match state {
            AllocatedState::Void => self.add_rights_raw(type_id, seal),
            AllocatedState::Amount(value) => self.add_fungible_state_raw(type_id, seal, value),
            AllocatedState::Data(data) => self.add_data_raw(type_id, seal, data),
        }
    }

    fn add_rights(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
    ) -> Result<Self, BuilderError> {
        let type_id = self.assignment_type(name);
        self.add_rights_raw(type_id, seal)
    }

    fn add_rights_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if *state_schema != OwnedStateSchema::Declarative {
            return Err(BuilderError::InvalidStateType(type_id));
        }

        let seal = seal.into();
        match self.rights.get_mut(&type_id) {
            Some(assignments) => {
                assignments.push(seal)?;
            }
            None => {
                self.rights.insert(type_id, Confined::with(seal))?;
            }
        }

        Ok(self)
    }

    fn add_fungible_state(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        value: impl Into<Amount>,
    ) -> Result<Self, BuilderError> {
        let type_id = self.assignment_type(name);
        let state = RevealedValue::new(value.into());
        self.add_fungible_state_raw(type_id, seal, state)
    }

    fn add_fungible_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: RevealedValue,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if *state_schema != OwnedStateSchema::Fungible(FungibleType::Unsigned64Bit) {
            return Err(BuilderError::InvalidStateType(type_id));
        }

        let seal = seal.into();
        match self.fungible.get_mut(&type_id) {
            Some(assignments) => {
                assignments.insert(seal, state)?;
            }
            None => {
                self.fungible
                    .insert(type_id, Confined::with((seal, state)))?;
            }
        }

        Ok(self)
    }

    fn add_data(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let serialized = value.to_strict_serialized::<U16>()?;
        let state = RevealedData::from(serialized);

        let type_id = self.assignment_type(name);
        self.add_data_raw(type_id, seal, state)
    }

    fn add_data_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: RevealedData,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if let OwnedStateSchema::Structured(_) = *state_schema {
            let seal = seal.into();
            match self.data.get_mut(&type_id) {
                Some(assignments) => {
                    assignments.insert(seal, state)?;
                }
                None => {
                    self.data.insert(type_id, Confined::with((seal, state)))?;
                }
            }
        } else {
            return Err(BuilderError::InvalidStateType(type_id));
        }
        Ok(self)
    }

    fn complete(self) -> (Schema, GlobalState, Assignments<Seal>, TypeSystem, Metadata) {
        let owned_state = self.fungible.into_iter().map(|(id, vec)| {
            let vec = vec
                .into_iter()
                .map(|(seal, value)| match seal {
                    BuilderSeal::Revealed(seal) => Assign::Revealed { seal, state: value },
                    BuilderSeal::Concealed(seal) => Assign::ConfidentialSeal { seal, state: value },
                })
                .collect::<Vec<_>>();
            let state = Confined::try_from_iter(vec).expect("at least one element");
            let state = TypedAssigns::Fungible(AssignVec::with(state));
            (id, state)
        });
        let owned_data = self.data.into_iter().map(|(id, vec)| {
            let vec_data = vec.into_iter().map(|(seal, value)| match seal {
                BuilderSeal::Revealed(seal) => Assign::Revealed { seal, state: value },
                BuilderSeal::Concealed(seal) => Assign::ConfidentialSeal { seal, state: value },
            });
            let state_data = Confined::try_from_iter(vec_data).expect("at least one element");
            let state_data = TypedAssigns::Structured(AssignVec::with(state_data));
            (id, state_data)
        });
        let owned_rights = self.rights.into_iter().map(|(id, vec)| {
            let vec_data = vec.into_iter().map(|seal| match seal {
                BuilderSeal::Revealed(seal) => Assign::Revealed {
                    seal,
                    state: none!(),
                },
                BuilderSeal::Concealed(seal) => Assign::ConfidentialSeal {
                    seal,
                    state: none!(),
                },
            });
            let state_data = Confined::try_from_iter(vec_data).expect("at least one element");
            let state_data = TypedAssigns::Declarative(AssignVec::with(state_data));
            (id, state_data)
        });

        let owned_state = Confined::try_from_iter(owned_state).expect("same size");
        let owned_data = Confined::try_from_iter(owned_data).expect("same size");
        let owned_rights = Confined::try_from_iter(owned_rights).expect("same size");

        let mut assignments = Assignments::from_inner(owned_state);
        assignments
            .extend(Assignments::from_inner(owned_data).into_inner())
            .expect("too many assignments");
        assignments
            .extend(Assignments::from_inner(owned_rights).into_inner())
            .expect("too many assignments");

        (self.schema, self.global, assignments, self.types, self.meta)
    }
}
