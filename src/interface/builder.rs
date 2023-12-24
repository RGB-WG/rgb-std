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

use std::collections::{HashMap, HashSet};

use amplify::confinement::{Confined, TinyOrdMap, TinyOrdSet, U16};
use amplify::{confinement, Wrapper};
use rgb::{
    AltLayer1, AltLayer1Set, AssetTag, Assign, AssignmentType, Assignments, BlindingFactor,
    ContractId, ExposedSeal, FungibleType, Genesis, GenesisSeal, GlobalState, GraphSeal, Input,
    Opout, RevealedData, RevealedValue, StateSchema, SubSchema, Transition, TransitionType,
    TypedAssigns,
};
use strict_encoding::{FieldName, SerializeError, StrictSerialize, TypeName};
use strict_types::decode;

use crate::containers::{BuilderSeal, Contract};
use crate::interface::contract::AttachedState;
use crate::interface::{Iface, IfaceImpl, IfacePair, TransitionIface, TypedState};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BuilderError {
    /// interface implementation references different interface that the one
    /// provided to the builder.
    InterfaceMismatch,

    /// interface implementation references different schema that the one
    /// provided to the builder.
    SchemaMismatch,

    /// contract already has too many layers1.
    TooManyLayers1,

    /// global state `{0}` is not known to the schema.
    GlobalNotFound(FieldName),

    /// assignment `{0}` is not known to the schema.
    AssignmentNotFound(FieldName),

    /// transition `{0}` is not known to the schema.
    TransitionNotFound(TypeName),

    /// state `{0}` provided to the builder has invalid name.
    InvalidStateField(FieldName),

    /// state `{0}` provided to the builder has invalid name.
    InvalidState(AssignmentType),

    /// asset tag for state `{0}` must be added before any fungible state of
    /// the same type.
    AssetTagMissed(AssignmentType),

    /// asset tag for state `{0}` was already automatically created. Please call
    /// `add_asset_tag` before adding any fungible state to the builder.
    AssetTagAutomatic(AssignmentType),

    /// state data for state type `{0}` are invalid: asset tag doesn't match the
    /// tag defined by the contract.
    AssetTagInvalid(AssignmentType),

    /// interface doesn't specifies default operation name, thus an explicit
    /// operation type must be provided with `set_operation_type` method.
    NoOperationSubtype,

    /// interface doesn't have a default assignment type.
    NoDefaultAssignment,

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
    builder: OperationBuilder<GenesisSeal>,
    testnet: bool,
    alt_layers1: AltLayer1Set,
}

impl ContractBuilder {
    pub fn with(
        iface: Iface,
        schema: SubSchema,
        iimpl: IfaceImpl,
        testnet: bool,
    ) -> Result<Self, BuilderError> {
        Ok(Self {
            builder: OperationBuilder::with(iface, schema, iimpl)?,
            testnet,
            alt_layers1: none!(),
        })
    }

    pub fn mainnet(
        iface: Iface,
        schema: SubSchema,
        iimpl: IfaceImpl,
    ) -> Result<Self, BuilderError> {
        Ok(Self {
            builder: OperationBuilder::with(iface, schema, iimpl)?,
            testnet: false,
            alt_layers1: none!(),
        })
    }

    pub fn testnet(
        iface: Iface,
        schema: SubSchema,
        iimpl: IfaceImpl,
    ) -> Result<Self, BuilderError> {
        Ok(Self {
            builder: OperationBuilder::with(iface, schema, iimpl)?,
            testnet: true,
            alt_layers1: none!(),
        })
    }

    pub fn add_layer1(mut self, layer1: AltLayer1) -> Result<Self, BuilderError> {
        self.alt_layers1
            .push(layer1)
            .map_err(|_| BuilderError::TooManyLayers1)?;
        Ok(self)
    }

    #[inline]
    pub fn add_asset_tag(
        mut self,
        name: impl Into<FieldName>,
        asset_tag: AssetTag,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_asset_tag(name, asset_tag, None)?;
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

    pub fn add_owned_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        state: TypedState,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_owned_state_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn add_rights(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_rights(name, seal, None)?;
        Ok(self)
    }

    pub fn add_fungible_state(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        value: u64,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let type_id = self
            .builder
            .assignments_type(&name, None)
            .ok_or(BuilderError::AssignmentNotFound(name.clone()))?;
        let tag = match self.builder.asset_tags.get(&type_id) {
            Some(asset_tag) => *asset_tag,
            None => {
                let asset_tag = AssetTag::new_random(
                    format!(
                        "{}/{}",
                        self.builder.schema.schema_id(),
                        self.builder.iface.iface_id()
                    ),
                    type_id,
                );
                self.builder.asset_tags.insert(type_id, asset_tag)?;
                asset_tag
            }
        };

        self.builder = self
            .builder
            .add_fungible_state(name, seal, value, tag, None)?;
        Ok(self)
    }

    pub fn add_data(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_data(name, seal, value, None)?;
        Ok(self)
    }

    pub fn add_attachment(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        attachment: AttachedState,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_attachment(name, seal, attachment, None)?;
        Ok(self)
    }

    pub fn issue_contract(self) -> Result<Contract, BuilderError> {
        let (schema, iface_pair, global, assignments, asset_tags) = self.builder.complete(None);

        let genesis = Genesis {
            ffv: none!(),
            schema_id: schema.schema_id(),
            testnet: self.testnet,
            alt_layers1: self.alt_layers1,
            metadata: empty!(),
            globals: global,
            assignments,
            valencies: none!(),
        };

        // TODO: Validate against schema

        let mut contract = Contract::new(schema, genesis, asset_tags);
        contract.ifaces = tiny_bmap! { iface_pair.iface_id() => iface_pair };

        Ok(contract)
    }
}

#[derive(Clone, Debug)]
pub struct TransitionBuilder {
    builder: OperationBuilder<GraphSeal>,
    transition_type: TransitionType,
    inputs: TinyOrdMap<Input, TypedState>,
}

impl TransitionBuilder {
    pub fn blank_transition(
        iface: Iface,
        schema: SubSchema,
        iimpl: IfaceImpl,
    ) -> Result<Self, BuilderError> {
        Self::with(iface, schema, iimpl, TransitionType::BLANK)
    }

    pub fn default_transition(
        iface: Iface,
        schema: SubSchema,
        iimpl: IfaceImpl,
    ) -> Result<Self, BuilderError> {
        let transition_type = iface
            .default_operation
            .as_ref()
            .and_then(|name| iimpl.transition_type(name))
            .ok_or(BuilderError::NoOperationSubtype)?;
        Self::with(iface, schema, iimpl, transition_type)
    }

    pub fn named_transition(
        iface: Iface,
        schema: SubSchema,
        iimpl: IfaceImpl,
        transition_name: impl Into<TypeName>,
    ) -> Result<Self, BuilderError> {
        let transition_name = transition_name.into();
        let transition_type = iimpl
            .transition_type(&transition_name)
            .ok_or(BuilderError::TransitionNotFound(transition_name))?;
        Self::with(iface, schema, iimpl, transition_type)
    }

    fn with(
        iface: Iface,
        schema: SubSchema,
        iimpl: IfaceImpl,
        transition_type: TransitionType,
    ) -> Result<Self, BuilderError> {
        Ok(Self {
            builder: OperationBuilder::with(iface, schema, iimpl)?,
            transition_type,
            inputs: none!(),
        })
    }

    #[inline]
    pub fn add_asset_tag(
        mut self,
        name: impl Into<FieldName>,
        asset_tag: AssetTag,
    ) -> Result<Self, BuilderError> {
        self.builder = self
            .builder
            .add_asset_tag(name, asset_tag, Some(self.transition_type))?;
        Ok(self)
    }

    #[inline]
    pub fn add_asset_tag_raw(
        mut self,
        type_id: AssignmentType,
        asset_tag: AssetTag,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_asset_tag_raw(type_id, asset_tag)?;
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

    pub fn add_input(mut self, opout: Opout, state: TypedState) -> Result<Self, BuilderError> {
        self.inputs.insert(Input::with(opout), state)?;
        Ok(self)
    }

    pub fn default_assignment(&self) -> Result<&FieldName, BuilderError> {
        self.builder
            .transition_iface(self.transition_type)
            .default_assignment
            .as_ref()
            .ok_or(BuilderError::NoDefaultAssignment)
    }

    #[inline]
    pub fn assignments_type(&self, name: &FieldName) -> Option<AssignmentType> {
        self.builder
            .assignments_type(name, Some(self.transition_type))
    }

    pub fn add_owned_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        state: TypedState,
    ) -> Result<Self, BuilderError> {
        if matches!(state, TypedState::Amount(_, _, tag) if self.builder.asset_tag(type_id)? != tag)
        {
            return Err(BuilderError::AssetTagInvalid(type_id));
        }
        self.builder = self.builder.add_owned_state_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn add_rights(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
    ) -> Result<Self, BuilderError> {
        self.builder = self
            .builder
            .add_rights(name, seal, Some(self.transition_type))?;
        Ok(self)
    }

    pub fn add_fungible_default_state(
        self,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: u64,
    ) -> Result<Self, BuilderError> {
        let assignment_name = self.default_assignment()?.clone();
        self.add_fungible_state(assignment_name, seal.into(), value)
    }

    pub fn add_fungible_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: u64,
        blinding: BlindingFactor,
    ) -> Result<Self, BuilderError> {
        let tag = self.builder.asset_tag(type_id)?;
        let state = RevealedValue::with_blinding(value, blinding, tag);
        self.builder = self.builder.add_fungible_state_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn add_fungible_state(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: u64,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let type_id = self
            .builder
            .assignments_type(&name, None)
            .ok_or(BuilderError::AssignmentNotFound(name.clone()))?;
        let tag = self.builder.asset_tag(type_id)?;

        self.builder =
            self.builder
                .add_fungible_state(name, seal, value, tag, Some(self.transition_type))?;
        Ok(self)
    }

    pub fn add_data(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self
            .builder
            .add_data(name, seal, value, Some(self.transition_type))?;
        Ok(self)
    }

    pub fn add_data_default(
        self,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let assignment_name = self.default_assignment()?.clone();
        self.add_data(assignment_name, seal.into(), value)
    }

    pub fn add_attachment(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        attachment: AttachedState,
    ) -> Result<Self, BuilderError> {
        self.builder =
            self.builder
                .add_attachment(name, seal, attachment, Some(self.transition_type))?;
        Ok(self)
    }

    pub fn complete_transition(self, contract_id: ContractId) -> Result<Transition, BuilderError> {
        let (_, _, global, assignments, _) = self.builder.complete(Some(&self.inputs));

        let transition = Transition {
            ffv: none!(),
            contract_id,
            transition_type: self.transition_type,
            metadata: empty!(),
            globals: global,
            inputs: TinyOrdSet::try_from_iter(self.inputs.into_keys())
                .expect("same size iter")
                .into(),
            assignments,
            valencies: none!(),
        };

        // TODO: Validate against schema

        Ok(transition)
    }
}

#[derive(Clone, Debug)]
pub struct OperationBuilder<Seal: ExposedSeal> {
    // TODO: use references instead of owned values
    schema: SubSchema,
    iface: Iface,
    iimpl: IfaceImpl,
    asset_tags: TinyOrdMap<AssignmentType, AssetTag>,

    global: GlobalState,
    rights: TinyOrdMap<AssignmentType, Confined<HashSet<BuilderSeal<Seal>>, 1, U16>>,
    fungible:
        TinyOrdMap<AssignmentType, Confined<HashMap<BuilderSeal<Seal>, RevealedValue>, 1, U16>>,
    data: TinyOrdMap<AssignmentType, Confined<HashMap<BuilderSeal<Seal>, RevealedData>, 1, U16>>,
    attachments:
        TinyOrdMap<AssignmentType, Confined<HashMap<BuilderSeal<Seal>, AttachedState>, 1, U16>>,
    // TODO: add valencies
}

impl<Seal: ExposedSeal> OperationBuilder<Seal> {
    fn with(iface: Iface, schema: SubSchema, iimpl: IfaceImpl) -> Result<Self, BuilderError> {
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
            asset_tags: none!(),

            global: none!(),
            rights: none!(),
            fungible: none!(),
            attachments: none!(),
            data: none!(),
        })
    }

    fn transition_iface(&self, ty: TransitionType) -> &TransitionIface {
        let transition_name = self.iimpl.transition_name(ty).expect("reverse type");
        self.iface
            .transitions
            .get(transition_name)
            .expect("internal inconsistency")
    }

    fn assignments_type(
        &self,
        name: &FieldName,
        ty: Option<TransitionType>,
    ) -> Option<AssignmentType> {
        let assignments = match ty {
            None => &self.iface.genesis.assignments,
            Some(ty) => &self.transition_iface(ty).assignments,
        };
        let name = assignments.get(name)?.name.as_ref().unwrap_or(name);
        self.iimpl.assignments_type(name)
    }

    #[inline]
    fn state_schema(&self, type_id: AssignmentType) -> &StateSchema {
        self.schema
            .owned_types
            .get(&type_id)
            .expect("schema should match interface: must be checked by the constructor")
    }

    #[inline]
    pub fn asset_tag(&self, type_id: AssignmentType) -> Result<AssetTag, BuilderError> {
        self.asset_tags
            .get(&type_id)
            .ok_or(BuilderError::AssetTagMissed(type_id))
            .copied()
    }

    #[inline]
    pub fn add_asset_tag(
        self,
        name: impl Into<FieldName>,
        asset_tag: AssetTag,
        ty: Option<TransitionType>,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let type_id = self
            .assignments_type(&name, ty)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        self.add_asset_tag_raw(type_id, asset_tag)
    }

    #[inline]
    pub fn add_asset_tag_raw(
        mut self,
        type_id: AssignmentType,
        asset_tag: AssetTag,
    ) -> Result<Self, BuilderError> {
        if self.fungible.contains_key(&type_id) {
            return Err(BuilderError::AssetTagAutomatic(type_id));
        }

        self.asset_tags.insert(type_id, asset_tag)?;
        Ok(self)
    }

    pub fn add_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let serialized = value.to_strict_serialized::<{ u16::MAX as usize }>()?;

        // Check value matches type requirements
        let Some(type_id) = self
            .iimpl
            .global_state
            .iter()
            .find(|t| t.name == name)
            .map(|t| t.id)
        else {
            return Err(BuilderError::GlobalNotFound(name));
        };
        let sem_id = self
            .schema
            .global_types
            .get(&type_id)
            .expect("schema should match interface: must be checked by the constructor")
            .sem_id;
        self.schema
            .type_system
            .strict_deserialize_type(sem_id, &serialized)?;

        self.global.add_state(type_id, serialized.into())?;

        Ok(self)
    }

    fn add_owned_state_raw(
        self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: TypedState,
    ) -> Result<Self, BuilderError> {
        match state {
            TypedState::Void => self.add_rights_raw(type_id, seal),
            TypedState::Amount(value, blinding, tag) => self.add_fungible_state_raw(
                type_id,
                seal,
                RevealedValue::with_blinding(value, blinding, tag),
            ),
            TypedState::Data(data) => self.add_data_raw(type_id, seal, data),
            TypedState::Attachment(attach) => self.add_attachment_raw(type_id, seal, attach),
        }
    }

    fn add_rights_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if *state_schema != StateSchema::Fungible(FungibleType::Unsigned64Bit) {
            return Err(BuilderError::InvalidState(type_id));
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

    fn add_rights(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        ty: Option<TransitionType>,
    ) -> Result<Self, BuilderError> {
        let name = name.into();

        let type_id = self
            .assignments_type(&name, ty)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        self.add_rights_raw(type_id, seal)
    }

    fn add_fungible_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: RevealedValue,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if *state_schema != StateSchema::Fungible(FungibleType::Unsigned64Bit) {
            return Err(BuilderError::InvalidState(type_id));
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

    fn add_fungible_state(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        value: u64,
        tag: AssetTag,
        ty: Option<TransitionType>,
    ) -> Result<Self, BuilderError> {
        let name = name.into();

        let type_id = self
            .assignments_type(&name, ty)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        let state = RevealedValue::new_random_blinding(value, tag);
        self.add_fungible_state_raw(type_id, seal, state)
    }

    fn add_data_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: RevealedData,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if let StateSchema::Structured(_) = *state_schema {
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
            return Err(BuilderError::InvalidState(type_id));
        }
        Ok(self)
    }

    fn add_data(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        value: impl StrictSerialize,
        ty: Option<TransitionType>,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let serialized = value.to_strict_serialized::<U16>()?;
        let state = RevealedData::from(serialized);

        let type_id = self
            .assignments_type(&name, ty)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        self.add_data_raw(type_id, seal, state)
    }

    fn add_attachment_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: AttachedState,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if let StateSchema::Structured(_) = *state_schema {
            let seal = seal.into();
            match self.attachments.get_mut(&type_id) {
                Some(assignments) => {
                    assignments.insert(seal, state)?;
                }
                None => {
                    self.attachments
                        .insert(type_id, Confined::with((seal, state)))?;
                }
            }
        } else {
            return Err(BuilderError::InvalidState(type_id));
        }
        Ok(self)
    }

    fn add_attachment(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        state: AttachedState,
        ty: Option<TransitionType>,
    ) -> Result<Self, BuilderError> {
        let name = name.into();

        let type_id = self
            .assignments_type(&name, ty)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        self.add_attachment_raw(type_id, seal, state)
    }

    fn complete(
        self,
        inputs: Option<&TinyOrdMap<Input, TypedState>>,
    ) -> (SubSchema, IfacePair, GlobalState, Assignments<Seal>, TinyOrdMap<AssignmentType, AssetTag>)
    {
        let owned_state = self.fungible.into_iter().map(|(id, vec)| {
            let mut blindings = Vec::with_capacity(vec.len());
            let mut vec = vec
                .into_iter()
                .map(|(seal, value)| {
                    blindings.push(value.blinding);
                    match seal {
                        BuilderSeal::Revealed(seal) => Assign::Revealed { seal, state: value },
                        BuilderSeal::Concealed(seal) => {
                            Assign::ConfidentialSeal { seal, state: value }
                        }
                    }
                })
                .collect::<Vec<_>>();
            if let Some(assignment) = vec.last_mut() {
                blindings.pop();
                let state = assignment
                    .as_revealed_state_mut()
                    .expect("builder always operates revealed state");
                let mut inputs = inputs
                    .map(|i| {
                        i.iter()
                            .filter(|(out, _)| out.prev_out.ty == id)
                            .map(|(_, ts)| match ts {
                                TypedState::Amount(_, blinding, _) => *blinding,
                                _ => panic!("previous state has invalid type"),
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if inputs.is_empty() {
                    inputs = vec![BlindingFactor::EMPTY];
                }
                state.blinding = BlindingFactor::zero_balanced(inputs, blindings).expect(
                    "malformed set of blinding factors; probably random generator is broken",
                );
            }
            let state = Confined::try_from_iter(vec).expect("at least one element");
            let state = TypedAssigns::Fungible(state);
            (id, state)
        });
        let owned_data = self.data.into_iter().map(|(id, vec)| {
            let vec_data = vec.into_iter().map(|(seal, value)| match seal {
                BuilderSeal::Revealed(seal) => Assign::Revealed { seal, state: value },
                BuilderSeal::Concealed(seal) => Assign::ConfidentialSeal { seal, state: value },
            });
            let state_data = Confined::try_from_iter(vec_data).expect("at least one element");
            let state_data = TypedAssigns::Structured(state_data);
            (id, state_data)
        });

        let owned_state = Confined::try_from_iter(owned_state).expect("same size");
        let owned_data = Confined::try_from_iter(owned_data).expect("same size");

        let mut assignments = Assignments::from_inner(owned_state);
        assignments
            .extend(Assignments::from_inner(owned_data).into_inner())
            .expect("");

        let iface_pair = IfacePair::with(self.iface, self.iimpl);

        (self.schema, iface_pair, self.global, assignments, self.asset_tags)
    }
}
