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

use std::collections::btree_map;

use amplify::confinement::{NonEmptyBlob, NonEmptyOrdMap};
use commit_verify::StrictHash;
use rgb::{ContractId, Identity, SchemaId};
use strict_encoding::StrictDumb;

use super::SupplId;
use crate::interface::{IfaceId, ImplId};
use crate::LIB_NAME_RGB_STD;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[non_exhaustive]
#[repr(u8)]
pub enum ContainerVer {
    // V0 and V1 was a previous version before v0.11, currently not supported.
    #[default]
    #[display("v2", alt = "2")]
    V2 = 2,
}

pub trait SigValidator {
    fn validate_sig(&self, identity: &Identity, sig: SigBlob) -> bool;
}

pub struct DumbValidator;
impl SigValidator for DumbValidator {
    fn validate_sig(&self, _: &Identity, _: SigBlob) -> bool { false }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default)]
#[display(lowercase)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
pub enum TrustLevel {
    Malicious = 0x10,
    #[default]
    Unknown = 0x20,
    Untrusted = 0x40,
    Trusted = 0x80,
    Ultimate = 0xC0,
}

impl TrustLevel {
    pub fn should_accept(self) -> bool { self >= Self::Unknown }
    pub fn should_use(self) -> bool { self >= Self::Trusted }
    pub fn must_use(self) -> bool { self >= Self::Ultimate }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
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

#[derive(Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From, Display)]
#[wrapper(Deref, AsSlice, BorrowSlice, Hex)]
#[display(LowerHex)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SigBlob(NonEmptyBlob<4096>);

impl Default for SigBlob {
    fn default() -> Self { SigBlob(NonEmptyBlob::with(0)) }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct ContentSigs(NonEmptyOrdMap<Identity, SigBlob, 10>);

impl StrictDumb for ContentSigs {
    fn strict_dumb() -> Self {
        Self(NonEmptyOrdMap::with_key_value(strict_dumb!(), SigBlob::default()))
    }
}

impl IntoIterator for ContentSigs {
    type Item = (Identity, SigBlob);
    type IntoIter = btree_map::IntoIter<Identity, SigBlob>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}
