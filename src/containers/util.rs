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

use std::collections::btree_set;
use std::iter;

use amplify::confinement::{NonEmptyOrdSet, U16};
use rgb::SecretSeal;

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
    #[default]
    #[display("v0", alt = "0")]
    V0 = 0,
}

/// Non-empty set of secret seals.
#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, dumb = Self(NonEmptyOrdSet::with(SecretSeal::strict_dumb())))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SecretSeals(NonEmptyOrdSet<SecretSeal, U16>);

impl<'a> IntoIterator for &'a SecretSeals {
    type Item = SecretSeal;
    type IntoIter = iter::Copied<btree_set::Iter<'a, SecretSeal>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter().copied() }
}
