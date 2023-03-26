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

use amplify::confinement::{LargeOrdMap, LargeVec, SmallVec};
use bp::Outpoint;
use rgb::{attachment, AssignmentType, ContractState, FungibleOutput, SealWitness};
use strict_encoding::TypeName;
use strict_types::typify::TypedVal;
use strict_types::{decode, StrictVal};

use crate::interface::IfaceImpl;
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ContractError {
    /// type name {0} is unknown to the contract interface
    TypeNameUnknown(TypeName),

    #[from]
    #[display(inner)]
    Reify(decode::Error),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum TypedState {
    Void,
    Amount(u64),
    Data(StrictVal),
    Attachment(attachment::Revealed),
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct FungibleAssignment {
    pub owner: Outpoint,
    pub witness: SealWitness,
    pub value: u64,
}

impl From<FungibleOutput> for FungibleAssignment {
    fn from(out: FungibleOutput) -> Self { Self::from(&out) }
}

impl From<&FungibleOutput> for FungibleAssignment {
    fn from(out: &FungibleOutput) -> Self {
        FungibleAssignment {
            owner: out.seal,
            witness: out.witness,
            value: out.state.value.as_u64(),
        }
    }
}

/// Contract state is an in-memory structure providing API to read structured
/// data from the [`rgb::ContractHistory`].
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractIface {
    pub state: ContractState,
    pub iface: IfaceImpl,
}

impl ContractIface {
    /// # Panics
    ///
    /// If data are corrupted and contract schema doesn't match interface
    /// implementations.
    pub fn global(&self, name: impl Into<TypeName>) -> Result<SmallVec<StrictVal>, ContractError> {
        let name = name.into();
        let type_system = &self.state.schema.type_system;
        let type_id = self
            .iface
            .global_type(&name)
            .ok_or(ContractError::TypeNameUnknown(name))?;
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
        name: impl Into<TypeName>,
    ) -> Result<LargeVec<FungibleAssignment>, ContractError> {
        let name = name.into();
        let type_id = self
            .iface
            .assignments_type(&name)
            .ok_or(ContractError::TypeNameUnknown(name))?;
        let state = self
            .state
            .fungibles()
            .iter()
            .filter(|outp| outp.opout.ty == type_id)
            .map(FungibleAssignment::from);
        Ok(LargeVec::try_from_iter(state).expect("same or smaller collection size"))
    }

    // TODO: Add rights, attachments and structured data APIs
    pub fn outpoint(
        &self,
        _outpoint: Outpoint,
    ) -> LargeOrdMap<AssignmentType, LargeVec<TypedState>> {
        todo!()
    }
}
