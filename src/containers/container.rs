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

use amplify::confinement::TinyOrdMap;
use rgb::{validation, ContractId, SchemaId};

use crate::containers::{ContainerVer, ContentSigs};
use crate::interface::{IfaceId, ImplId, SupplId};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = order, dumb = ContentId::Schema(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum ContentId {
    Schema(SchemaId),
    Genesis(ContractId),
    Iface(IfaceId),
    IfaceImpl(ImplId),
    Suppl(SupplId),
}

pub trait ContainerContent {
    type Status: StatusReport;
}

pub struct Container<C> {
    /// Status of the latest validation.
    ///
    /// The value is not saved and when the structure is read from a disk or
    /// network is left uninitialized. Thus, only locally-run verification by
    /// this library is trusted.
    #[strict_type(skip, dumb = None)]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(super) validation_status: Option<ValidationStatus<C::Status>>,

    /// Version.
    pub version: ContainerVer,

    pub content: C,

    /// Signatures on the pieces of content which are the part of the
    /// consignment.
    pub signatures: TinyOrdMap<ContentId, ContentSigs>,
}
