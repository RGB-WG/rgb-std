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

//! RGB contract interface provides a mapping between identifiers of RGB schema-
//! defined contract state and operation types to a human-readable and
//! standardized wallet APIs.

mod iface;
mod iimpl;
mod contract;
mod builder;
pub mod rgb20;
pub mod rgb21;
pub mod rgb25;
mod suppl;
mod filters;
pub(crate) mod resolver;

pub use builder::{BuilderError, ContractBuilder, TransitionBuilder};
pub use contract::{
    AllocatedState, AttachAllocation, AttachedState, ContractError, ContractIface, DataAllocation,
    FungibleAllocation, IfaceOp, IfaceWrapper, OwnedAllocation, RightsAllocation, StateChange,
};
pub use filters::{FilterExclude, FilterIncludeAll, OutpointFilter, WitnessFilter};
pub use iface::{
    ArgMap, ArgSpec, AssignIface, ExtensionIface, GenesisIface, GlobalIface, Iface, IfaceId,
    OwnedIface, Req, TransitionIface, ValencyIface,
};
pub use iimpl::{ContractClass, IfaceImpl, IfacePair, ImplId, NamedField, NamedType, SchemaIfaces};
pub use rgb20::{AmountChange, Rgb20, Rgb20Contract, LIB_ID_RGB20, LIB_NAME_RGB20};
pub use rgb21::{rgb21, rgb21_stl, Rgb21, LIB_ID_RGB21, LIB_NAME_RGB21};
pub use rgb25::{rgb25, rgb25_stl, Rgb25, LIB_ID_RGB25, LIB_NAME_RGB25};
pub use suppl::{ContractSuppl, OwnedStateSuppl, SupplId, TickerSuppl, VelocityHint};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = crate::LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
#[non_exhaustive]
pub enum VerNo {
    #[default]
    #[display("v1")]
    V1 = 0,
}
