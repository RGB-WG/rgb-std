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

use amplify::confinement::{Confined, SmallOrdSet, TinyOrdMap, U16};
use amplify::{confinement, Wrapper};
use invoice::{Allocation, Amount};
use rgb::{
    validation, AltLayer1, AltLayer1Set, AssetTag, Assign, AssignmentType, Assignments,
    BlindingFactor, ContractId, DataState, ExposedSeal, FungibleType, Genesis, GenesisSeal,
    GlobalState, GraphSeal, Input, Layer1, Opout, RevealedAttach, RevealedData, RevealedValue,
    Schema, StateSchema, Transition, TransitionType, TypedAssigns, XChain, XOutpoint,
};
use strict_encoding::{FieldName, SerializeError, StrictSerialize, TypeName};
use strict_types::decode;

use crate::containers::{BuilderSeal, Contract};
use crate::interface::contract::AttachedState;
use crate::interface::resolver::DumbResolver;
use crate::interface::{
    Iface, IfaceClass, IfaceImpl, IfacePair, IssuerTriplet, SchemaIssuer, TransitionIface,
    WrongImplementation,
};
use crate::persistence::PersistedState;
use crate::Outpoint;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BuilderError {
    #[from]
    #[display(inner)]
    WrongImplementation(WrongImplementation),

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
    #[display(inner)]
    ContractInconsistency(validation::Status),
}

mod private {
    pub trait Sealed {}
}

pub trait TxOutpoint: Copy + Eq + private::Sealed {
    fn is_liquid(&self) -> bool;
    fn is_bitcoin(&self) -> bool;
    fn map_to_xchain<U>(self, f: impl FnOnce(Outpoint) -> U) -> XChain<U>;
}

impl private::Sealed for Outpoint {}
impl private::Sealed for XOutpoint {}
impl TxOutpoint for Outpoint {
    fn is_liquid(&self) -> bool { false }
    fn is_bitcoin(&self) -> bool { true }
    fn map_to_xchain<U>(self, f: impl FnOnce(Outpoint) -> U) -> XChain<U> {
        XChain::Bitcoin(f(self))
    }
}
impl TxOutpoint for XOutpoint {
    fn is_liquid(&self) -> bool { XChain::is_liquid(self) }
    fn is_bitcoin(&self) -> bool { XChain::is_bitcoin(self) }
    fn map_to_xchain<U>(self, f: impl FnOnce(Outpoint) -> U) -> XChain<U> { self.map(f) }
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
        schema: Schema,
        iimpl: IfaceImpl,
        testnet: bool,
    ) -> Result<Self, WrongImplementation> {
        Ok(Self {
            builder: OperationBuilder::with(iface, schema, iimpl)?,
            testnet,
            alt_layers1: none!(),
        })
    }

    pub fn mainnet(
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
    ) -> Result<Self, WrongImplementation> {
        Ok(Self {
            builder: OperationBuilder::with(iface, schema, iimpl)?,
            testnet: false,
            alt_layers1: none!(),
        })
    }

    pub fn testnet(
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
    ) -> Result<Self, WrongImplementation> {
        Ok(Self {
            builder: OperationBuilder::with(iface, schema, iimpl)?,
            testnet: true,
            alt_layers1: none!(),
        })
    }

    pub fn has_layer1(&self, layer1: Layer1) -> bool {
        match layer1 {
            Layer1::Bitcoin => true,
            Layer1::Liquid => self.alt_layers1.contains(&AltLayer1::Liquid),
        }
    }
    pub fn check_layer1(&self, layer1: Layer1) -> Result<(), BuilderError> {
        if !self.has_layer1(layer1) {
            return Err(BuilderError::InvalidLayer1(layer1));
        }
        Ok(())
    }

    pub fn add_layer1(mut self, layer1: AltLayer1) -> Result<Self, BuilderError> {
        self.alt_layers1
            .push(layer1)
            .map_err(|_| BuilderError::TooManyLayers1)?;
        Ok(self)
    }

    #[inline]
    pub fn asset_tag(&self, name: impl Into<FieldName>) -> Result<AssetTag, BuilderError> {
        self.builder.asset_tag(name)
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

    pub fn add_owned_state_det(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        state: PersistedState,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_owned_state_det(name, seal, state)?;
        Ok(self)
    }

    pub fn add_rights(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
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
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
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
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_data(name, seal, value, None)?;
        Ok(self)
    }

    pub fn add_attachment(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        attachment: AttachedState,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_attachment(name, seal, attachment, None)?;
        Ok(self)
    }

    pub fn issue_contract(self) -> Result<Contract, BuilderError> {
        let (schema, iface_pair, global, assignments, asset_tags) = self.builder.complete(None);

        let genesis = Genesis {
            ffv: none!(),
            schema_id: schema.schema_id(),
            flags: none!(),
            timestamp: 0,
            testnet: self.testnet,
            alt_layers1: self.alt_layers1,
            metadata: empty!(),
            globals: global,
            assignments,
            valencies: none!(),
            // TODO: Add APIs for providing issuer information
            issuer: none!(),
            script: none!(),
        };

        let mut contract = Contract::new(schema, genesis, asset_tags);
        contract.ifaces = tiny_bmap! { iface_pair.iface_id() => iface_pair };

        let verified_contract =
            contract
                .validate(&mut DumbResolver, self.testnet)
                .map_err(|consignment| {
                    consignment
                        .into_validation_status()
                        .expect("status always present upon validation")
                })?;

        Ok(verified_contract)
    }
}

#[derive(Clone, Debug)]
pub struct TransitionBuilder {
    contract_id: ContractId,
    builder: OperationBuilder<GraphSeal>,
    transition_type: TransitionType,
    inputs: TinyOrdMap<Input, PersistedState>,
}

impl TransitionBuilder {
    pub fn blank_transition(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
    ) -> Result<Self, WrongImplementation> {
        Self::with(contract_id, iface, schema, iimpl, TransitionType::BLANK)
    }

    pub fn default_transition(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
    ) -> Result<Self, BuilderError> {
        let transition_type = iface
            .default_operation
            .as_ref()
            .and_then(|name| iimpl.transition_type(name))
            .ok_or(BuilderError::NoOperationSubtype)?;
        Ok(Self::with(contract_id, iface, schema, iimpl, transition_type)?)
    }

    pub fn named_transition(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        transition_name: impl Into<TypeName>,
    ) -> Result<Self, BuilderError> {
        let transition_name = transition_name.into();
        let transition_type = iimpl
            .transition_type(&transition_name)
            .ok_or(BuilderError::TransitionNotFound(transition_name))?;
        Ok(Self::with(contract_id, iface, schema, iimpl, transition_type)?)
    }

    fn with(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        transition_type: TransitionType,
    ) -> Result<Self, WrongImplementation> {
        Ok(Self {
            contract_id,
            builder: OperationBuilder::with(iface, schema, iimpl)?,
            transition_type,
            inputs: none!(),
        })
    }

    pub fn transition_type(&self) -> TransitionType { self.transition_type }

    #[inline]
    pub fn asset_tag(&self, name: impl Into<FieldName>) -> Result<AssetTag, BuilderError> {
        self.builder.asset_tag(name)
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

    pub fn add_input(mut self, opout: Opout, state: PersistedState) -> Result<Self, BuilderError> {
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

    pub fn add_owned_state_det(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        state: PersistedState,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_owned_state_det(name, seal, state)?;
        Ok(self)
    }

    pub fn add_owned_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        state: PersistedState,
    ) -> Result<Self, BuilderError> {
        if matches!(state, PersistedState::Amount(_, _, tag) if self.builder.asset_tag_raw(type_id)? != tag)
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
        value: impl Into<Amount>,
        blinding: BlindingFactor,
    ) -> Result<Self, BuilderError> {
        let tag = self.builder.asset_tag_raw(type_id)?;
        let state = RevealedValue::with_blinding(value.into(), blinding, tag);
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
        let tag = self.builder.asset_tag_raw(type_id)?;

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

    pub fn add_data_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        allocation: impl Into<Allocation>,
        blinding: u64,
    ) -> Result<Self, BuilderError> {
        let revelead_state = RevealedData::with_salt(allocation.into(), blinding.into());
        self.builder = self.builder.add_data_raw(type_id, seal, revelead_state)?;
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

    pub fn complete_transition(self) -> Result<Transition, BuilderError> {
        let (_, _, global, assignments, _) = self.builder.complete(Some(&self.inputs));

        let transition = Transition {
            ffv: none!(),
            contract_id: self.contract_id,
            transition_type: self.transition_type,
            metadata: empty!(),
            globals: global,
            inputs: SmallOrdSet::from_iter_unsafe(self.inputs.into_keys()).into(),
            assignments,
            valencies: none!(),
            witness: none!(),
            script: none!(),
        };

        // TODO: Validate against schema

        Ok(transition)
    }
}

#[derive(Clone, Debug)]
pub struct OperationBuilder<Seal: ExposedSeal> {
    // TODO: use references instead of owned values
    schema: Schema,
    iface: Iface,
    iimpl: IfaceImpl,
    asset_tags: TinyOrdMap<AssignmentType, AssetTag>,

    global: GlobalState,
    rights: TinyOrdMap<AssignmentType, Confined<HashSet<BuilderSeal<Seal>>, 1, U16>>,
    fungible:
        TinyOrdMap<AssignmentType, Confined<BTreeMap<BuilderSeal<Seal>, RevealedValue>, 1, U16>>,
    data: TinyOrdMap<AssignmentType, Confined<BTreeMap<BuilderSeal<Seal>, RevealedData>, 1, U16>>,
    attachments:
        TinyOrdMap<AssignmentType, Confined<BTreeMap<BuilderSeal<Seal>, RevealedAttach>, 1, U16>>,
    // TODO: add valencies
}

impl<Seal: ExposedSeal> From<IssuerTriplet> for OperationBuilder<Seal> {
    fn from(triplet: IssuerTriplet) -> Self {
        let (iface, schema, iimpl) = triplet.into_split();

        OperationBuilder {
            schema,
            iface,
            iimpl,
            asset_tags: none!(),

            global: none!(),
            rights: none!(),
            fungible: none!(),
            attachments: none!(),
            data: none!(),
        }
    }
}

impl<Seal: ExposedSeal, I: IfaceClass> From<SchemaIssuer<I>> for OperationBuilder<Seal> {
    fn from(issuer: SchemaIssuer<I>) -> Self { Self::from(issuer.into_triplet()) }
}

impl<Seal: ExposedSeal> OperationBuilder<Seal> {
    fn with(iface: Iface, schema: Schema, iimpl: IfaceImpl) -> Result<Self, WrongImplementation> {
        let triplet = IssuerTriplet::new(iface, schema, iimpl)?;
        Ok(Self::from(triplet))
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

    pub fn asset_tag(&self, name: impl Into<FieldName>) -> Result<AssetTag, BuilderError> {
        let name = name.into();
        let type_id = self
            .assignments_type(&name, None)
            .ok_or(BuilderError::AssignmentNotFound(name.clone()))?;
        self.asset_tag_raw(type_id)
    }

    #[inline]
    fn asset_tag_raw(&self, type_id: AssignmentType) -> Result<AssetTag, BuilderError> {
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
            .types
            .strict_deserialize_type(sem_id, &serialized)?;

        self.global
            .add_state(type_id, RevealedData::new_random_salt(serialized))?;

        Ok(self)
    }

    fn add_owned_state_det(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        state: PersistedState,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let type_id = self
            .assignments_type(&name, None)
            .ok_or(BuilderError::AssignmentNotFound(name.clone()))?;
        self.add_owned_state_raw(type_id, seal, state)
    }

    fn add_owned_state_raw(
        self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: PersistedState,
    ) -> Result<Self, BuilderError> {
        match state {
            PersistedState::Void => self.add_rights_raw(type_id, seal),
            PersistedState::Amount(value, blinding, tag) => {
                if self.asset_tag_raw(type_id)? != tag {
                    return Err(BuilderError::AssetTagInvalid(type_id));
                }

                self.add_fungible_state_raw(
                    type_id,
                    seal,
                    RevealedValue::with_blinding(value, blinding, tag),
                )
            }
            PersistedState::Data(data, salt) => {
                self.add_data_raw(type_id, seal, RevealedData::with_salt(data, salt))
            }
            PersistedState::Attachment(attach, salt) => self.add_attachment_raw(
                type_id,
                seal,
                RevealedAttach::with_salt(attach.id, attach.media_type, salt),
            ),
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
        let state = DataState::from(serialized);

        let type_id = self
            .assignments_type(&name, ty)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        self.add_data_raw(type_id, seal, RevealedData::new_random_salt(state))
    }

    fn add_attachment_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: RevealedAttach,
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

        self.add_attachment_raw(
            type_id,
            seal,
            RevealedAttach::new_random_salt(state.id, state.media_type),
        )
    }

    fn complete(
        self,
        inputs: Option<&TinyOrdMap<Input, PersistedState>>,
    ) -> (Schema, IfacePair, GlobalState, Assignments<Seal>, TinyOrdMap<AssignmentType, AssetTag>)
    {
        let owned_state = self.fungible.into_iter().map(|(id, vec)| {
            let mut blindings = Vec::with_capacity(vec.len());
            let mut vec = vec
                .into_iter()
                .map(|(seal, value)| {
                    blindings.push(value.blinding);
                    match seal {
                        BuilderSeal::Revealed(seal) => Assign::Revealed {
                            seal,
                            state: value,
                            lock: none!(),
                        },
                        BuilderSeal::Concealed(seal) => Assign::ConfidentialSeal {
                            seal,
                            state: value,
                            lock: none!(),
                        },
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
                                PersistedState::Amount(_, blinding, _) => *blinding,
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
                BuilderSeal::Revealed(seal) => Assign::Revealed {
                    seal,
                    state: value,
                    lock: none!(),
                },
                BuilderSeal::Concealed(seal) => Assign::ConfidentialSeal {
                    seal,
                    state: value,
                    lock: none!(),
                },
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
