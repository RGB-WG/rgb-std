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

use std::collections::{btree_map, BTreeMap};

use amplify::confinement::{Confined, NonEmptyBlob};
use commit_verify::StrictHash;
use rgb::{ContractId, Identity, SchemaId};
use strict_encoding::StrictDumb;

use crate::interface::{IfaceId, ImplId, SupplId};
use crate::LIB_NAME_RGB_STD;

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
pub struct ContentSigs(Confined<BTreeMap<Identity, SigBlob>, 1, 10>);

impl StrictDumb for ContentSigs {
    fn strict_dumb() -> Self {
        confined_bmap! { strict_dumb!() => SigBlob::default() }
    }
}

impl IntoIterator for ContentSigs {
    type Item = (Identity, SigBlob);
    type IntoIter = btree_map::IntoIter<Identity, SigBlob>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}
