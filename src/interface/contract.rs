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

use amplify::confinement::SmallVec;
use invoice::Amount;
use rgb::{
    AttachId, ContractId, ContractState, DataState, KnownState, MediaType, OutputAssignment,
    RevealedAttach, RevealedData, RevealedValue, VoidState, XOutpoint,
};
use strict_encoding::FieldName;
use strict_types::typify::TypedVal;
use strict_types::{decode, StrictVal};

use crate::interface::{IfaceId, IfaceImpl};
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ContractError {
    /// field name {0} is unknown to the contract interface
    FieldNameUnknown(FieldName),

    #[from]
    #[display(inner)]
    Reify(decode::Error),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[display(inner)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AllocatedState {
    #[from(())]
    #[from(VoidState)]
    #[display("~")]
    #[strict_type(tag = 0, dumb)]
    Void,

    #[from]
    #[from(RevealedValue)]
    #[strict_type(tag = 1)]
    Amount(Amount),

    #[from]
    #[from(RevealedData)]
    #[strict_type(tag = 2)]
    Data(DataState),

    #[from]
    #[from(RevealedAttach)]
    #[strict_type(tag = 3)]
    Attachment(AttachedState),
}

impl KnownState for AllocatedState {}

pub type OwnedAllocation = OutputAssignment<AllocatedState>;
pub type RightsAllocation = OutputAssignment<VoidState>;
pub type FungibleAllocation = OutputAssignment<Amount>;
pub type DataAllocation = OutputAssignment<DataState>;
pub type AttachAllocation = OutputAssignment<AttachedState>;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[display("{id}:{media_type}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AttachedState {
    pub id: AttachId,
    pub media_type: MediaType,
}

impl KnownState for AttachedState {}

impl From<RevealedAttach> for AttachedState {
    fn from(attach: RevealedAttach) -> Self {
        AttachedState {
            id: attach.id,
            media_type: attach.media_type,
        }
    }
}

pub trait OutpointFilter {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool;
}

pub struct FilterIncludeAll;
pub struct FilterExclude<T: OutpointFilter>(pub T);

impl<T: OutpointFilter> OutpointFilter for &T {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        (*self).include_outpoint(outpoint)
    }
}

impl<T: OutpointFilter> OutpointFilter for &mut T {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        self.deref().include_outpoint(outpoint)
    }
}

impl<T: OutpointFilter> OutpointFilter for Option<T> {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        self.as_ref()
            .map(|filter| filter.include_outpoint(outpoint))
            .unwrap_or(true)
    }
}

impl OutpointFilter for FilterIncludeAll {
    fn include_outpoint(&self, _: impl Into<XOutpoint>) -> bool { true }
}

impl<T: OutpointFilter> OutpointFilter for FilterExclude<T> {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        !self.0.include_outpoint(outpoint.into())
    }
}

impl OutpointFilter for XOutpoint {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool { *self == outpoint.into() }
}

impl<const LEN: usize> OutpointFilter for [XOutpoint; LEN] {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        self.contains(&outpoint.into())
    }
}

impl OutpointFilter for &[XOutpoint] {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        self.contains(&outpoint.into())
    }
}

impl OutpointFilter for Vec<XOutpoint> {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        self.contains(&outpoint.into())
    }
}

impl OutpointFilter for HashSet<XOutpoint> {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        self.contains(&outpoint.into())
    }
}

impl OutpointFilter for BTreeSet<XOutpoint> {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        self.contains(&outpoint.into())
    }
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
                    .strict_deserialize_type(type_schema.sem_id, revealed.value.as_ref())
                    .map(TypedVal::unbox)
            })
            .take(type_schema.max_items as usize)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SmallVec::try_from_iter(state).expect("same or smaller collection size"))
    }

    fn extract_state<'c, 'f: 'c, S: KnownState + 'c, U: KnownState + 'c>(
        &'c self,
        state: impl IntoIterator<Item = &'c OutputAssignment<S>> + 'c,
        name: impl Into<FieldName>,
        filter: &'f impl OutpointFilter,
    ) -> Result<impl Iterator<Item = OutputAssignment<U>> + 'c, ContractError>
    where
        S: Clone,
        U: From<S>,
    {
        let name = name.into();
        let type_id = self
            .iface
            .assignments_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))?;
        Ok(state
            .into_iter()
            .filter(move |outp| outp.opout.ty == type_id)
            .filter(|outp| filter.include_outpoint(outp.seal))
            .cloned()
            .map(OutputAssignment::<S>::transmute))
    }

    pub fn rights<'c, 'f: 'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: &'f impl OutpointFilter,
    ) -> Result<impl Iterator<Item = RightsAllocation> + 'c, ContractError> {
        self.extract_state(self.state.rights(), name, filter)
    }

    pub fn fungible<'c, 'f: 'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: &'f impl OutpointFilter,
    ) -> Result<impl Iterator<Item = FungibleAllocation> + 'c, ContractError> {
        self.extract_state(self.state.fungibles(), name, filter)
    }

    pub fn data<'c, 'f: 'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: &'f impl OutpointFilter,
    ) -> Result<impl Iterator<Item = DataAllocation> + 'c, ContractError> {
        self.extract_state(self.state.data(), name, filter)
    }

    pub fn attachments<'c, 'f: 'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: &'f impl OutpointFilter,
    ) -> Result<impl Iterator<Item = AttachAllocation> + 'c, ContractError> {
        self.extract_state(self.state.attach(), name, filter)
    }

    pub fn outpoint_allocations(
        &self,
        outpoint: XOutpoint,
    ) -> impl Iterator<Item = OwnedAllocation> + '_ {
        fn f<'a, 'f: 'a, S: KnownState + 'a, U: KnownState + 'a>(
            filter: impl OutpointFilter + 'f,
            state: impl IntoIterator<Item = &'a OutputAssignment<S>> + 'a,
        ) -> impl Iterator<Item = OutputAssignment<U>> + 'a
        where
            S: Clone,
            U: From<S>,
        {
            state
                .into_iter()
                .filter(move |outp| filter.include_outpoint(outp.seal))
                .cloned()
                .map(OutputAssignment::<S>::transmute)
        }

        f(outpoint, self.state.rights())
            .map(OwnedAllocation::from)
            .chain(f(outpoint, self.state.fungibles()).map(OwnedAllocation::from))
            .chain(f(outpoint, self.state.data()).map(OwnedAllocation::from))
            .chain(f(outpoint, self.state.attach()).map(OwnedAllocation::from))
    }

    pub fn wrap<W: IfaceWrapper>(self) -> W { W::from(self) }
}

pub trait IfaceWrapper: From<ContractIface> {
    const IFACE_NAME: &'static str;
    const IFACE_ID: IfaceId;
}
