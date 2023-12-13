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

use std::collections::{BTreeSet, HashSet};
use std::ops::Deref;

use amplify::confinement::{LargeOrdMap, LargeVec, SmallVec};
use bp::Outpoint;
use rgb::{
    AssetTag, AssignmentType, AttachId, BlindingFactor, ContractId, ContractState, FungibleOutput,
    MediaType, Output, RevealedAttach, RevealedData, WitnessId,
};
use strict_encoding::FieldName;
use strict_types::typify::TypedVal;
use strict_types::{decode, StrictVal};

use crate::interface::{IfaceId, IfaceImpl};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ContractError {
    /// field name {0} is unknown to the contract interface
    FieldNameUnknown(FieldName),

    #[from]
    #[display(inner)]
    Reify(decode::Error),
}

#[derive(Clone, Eq, PartialEq, Debug, Hash, Display, From)]
#[display(inner)]
pub enum TypedState {
    #[display("")]
    Void,
    Amount(u64, BlindingFactor, AssetTag),
    #[from]
    Data(RevealedData),
    #[from]
    Attachment(AttachedState),
}

impl TypedState {
    pub fn update_blinding(&mut self, blinding: BlindingFactor) {
        match self {
            TypedState::Void => {}
            TypedState::Amount(_, b, _) => *b = blinding,
            TypedState::Data(_) => {}
            TypedState::Attachment(_) => {}
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{id}:{media_type}")]
pub struct AttachedState {
    pub id: AttachId,
    pub media_type: MediaType,
}

impl From<RevealedAttach> for AttachedState {
    fn from(attach: RevealedAttach) -> Self {
        AttachedState {
            id: attach.id,
            media_type: attach.media_type,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display)]
pub enum AllocationWitness {
    #[display("~")]
    Absent,
    #[display(inner)]
    Present(WitnessId),
}

impl From<Option<WitnessId>> for AllocationWitness {
    fn from(value: Option<WitnessId>) -> Self {
        match value {
            None => AllocationWitness::Absent,
            Some(id) => AllocationWitness::Present(id),
        }
    }
}

// TODO: Consider removing type in favour of `FungibleOutput`
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct FungibleAllocation {
    pub owner: Output,
    pub witness: AllocationWitness,
    pub value: u64,
}

impl From<FungibleOutput> for FungibleAllocation {
    fn from(out: FungibleOutput) -> Self { Self::from(&out) }
}

impl From<&FungibleOutput> for FungibleAllocation {
    fn from(out: &FungibleOutput) -> Self {
        FungibleAllocation {
            owner: out.output,
            witness: out.witness.into(),
            value: out.state.value.as_u64(),
        }
    }
}

pub trait OutpointFilter {
    fn include_output(&self, output: Output) -> bool;
}

pub struct FilterIncludeAll;
pub struct FilterExclude<T: OutpointFilter>(pub T);

impl<T: OutpointFilter> OutpointFilter for &T {
    fn include_output(&self, output: Output) -> bool { (*self).include_output(output) }
}

impl<T: OutpointFilter> OutpointFilter for &mut T {
    fn include_output(&self, output: Output) -> bool { self.deref().include_output(output) }
}

impl<T: OutpointFilter> OutpointFilter for Option<T> {
    fn include_output(&self, output: Output) -> bool {
        self.as_ref()
            .map(|filter| filter.include_output(output))
            .unwrap_or(true)
    }
}

impl OutpointFilter for FilterIncludeAll {
    fn include_output(&self, _: Output) -> bool { true }
}

impl<T: OutpointFilter> OutpointFilter for FilterExclude<T> {
    fn include_output(&self, output: Output) -> bool { !self.0.include_output(output) }
}

impl OutpointFilter for &[Output] {
    fn include_output(&self, output: Output) -> bool { self.contains(&output) }
}

impl OutpointFilter for Vec<Output> {
    fn include_output(&self, output: Output) -> bool { self.contains(&output) }
}

impl OutpointFilter for HashSet<Output> {
    fn include_output(&self, output: Output) -> bool { self.contains(&output) }
}

impl OutpointFilter for BTreeSet<Output> {
    fn include_output(&self, output: Output) -> bool { self.contains(&output) }
}

/// Contract state is an in-memory structure providing API to read structured
/// data from the [`rgb::ContractHistory`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ContractIface {
    pub state: ContractState,
    pub iface: IfaceImpl,
}

impl ContractIface {
    pub fn contract_id(&self) -> ContractId { self.state.contract_id() }

    /// # Panics
    ///
    /// If data are corrupted and contract schema doesn't match interface
    /// implementations.
    pub fn global(&self, name: impl Into<FieldName>) -> Result<SmallVec<StrictVal>, ContractError> {
        let name = name.into();
        let type_system = &self.state.schema.type_system;
        let type_id = self
            .iface
            .global_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))?;
        let type_schema = self
            .state
            .schema
            .global_types
            .get(&type_id)
            .expect("schema doesn't match interface");
        let state = unsafe { self.state.global_unchecked(type_id) };
        let state = state
            .into_iter()
            .map(|revealed| {
                type_system
                    .strict_deserialize_type(type_schema.sem_id, revealed.as_ref())
                    .map(TypedVal::unbox)
            })
            .take(type_schema.max_items as usize)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SmallVec::try_from_iter(state).expect("same or smaller collection size"))
    }

    pub fn fungible(
        &self,
        name: impl Into<FieldName>,
        filter: &impl OutpointFilter,
    ) -> Result<LargeVec<FungibleAllocation>, ContractError> {
        let name = name.into();
        let type_id = self
            .iface
            .assignments_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))?;
        let state = self
            .state
            .fungibles()
            .iter()
            .filter(|outp| outp.opout.ty == type_id)
            .filter(|outp| filter.include_output(outp.output))
            .map(FungibleAllocation::from);
        Ok(LargeVec::try_from_iter(state).expect("same or smaller collection size"))
    }

    // TODO: Add rights, attachments and structured data APIs
    pub fn outpoint(
        &self,
        _outpoint: Outpoint,
    ) -> LargeOrdMap<AssignmentType, LargeVec<TypedState>> {
        todo!()
    }

    pub fn wrap<W: IfaceWrapper>(self) -> W { W::from(self) }
}

pub trait IfaceWrapper: From<ContractIface> {
    const IFACE_NAME: &'static str;
    const IFACE_ID: IfaceId;
}
