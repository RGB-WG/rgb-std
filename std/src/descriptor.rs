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

use std::collections::BTreeMap;

use bp::dbc::tapret::TapretCommitment;
use bpstd::{Derive, DeriveSet, DeriveXOnly, Keychain, NormalIndex, ScriptPubkey, XpubDescriptor};
#[cfg(feature = "serde")]
use serde_with::DisplayFromStr;

#[cfg_attr(
    feature = "serde",
    cfg_eval,
    serde_as,
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        bound(
            serialize = "K: std::fmt::Display",
            deserialize = "K: std::str::FromStr, K::Err: std::fmt::Display"
        )
    )
)]
#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
pub struct TapretKey<K: DeriveXOnly = XpubDescriptor> {
    #[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
    pub internal_key: K,
    #[cfg_attr(feature = "serde", serde_as(as = "BTreeMap<DisplayFromStr, DisplayFromStr>"))]
    pub tweaks: BTreeMap<NormalIndex, TapretCommitment>,
}

impl<K: DeriveXOnly> TapretKey<K> {
    pub fn new_unfunded(internal_key: K) -> Self {
        TapretKey {
            internal_key,
            tweaks: empty!(),
        }
    }
}

impl<K: DeriveXOnly> Derive<ScriptPubkey> for TapretKey<K> {
    fn derive(&self, change: impl Keychain, index: impl Into<NormalIndex>) -> ScriptPubkey {
        // TODO: Apply tweaks
        let internal_key = self.internal_key.derive(change, index);
        ScriptPubkey::p2tr_key_only(internal_key)
    }
}

#[cfg_attr(
    feature = "serde",
    cfg_eval,
    serde_as,
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        bound(
            serialize = "S::XOnly: std::fmt::Display",
            deserialize = "S::XOnly: std::str::FromStr, <S::XOnly as std::str::FromStr>::Err: \
                           std::fmt::Display"
        )
    )
)]
#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
pub enum DescriptorRgb<S: DeriveSet = XpubDescriptor> {
    None,
    #[from]
    TapretKey(TapretKey<S::XOnly>),
}

impl<S: DeriveSet> Default for DescriptorRgb<S> {
    fn default() -> Self { DescriptorRgb::None }
}

impl<S: DeriveSet> Derive<ScriptPubkey> for DescriptorRgb<S> {
    fn derive(&self, change: impl Keychain, index: impl Into<NormalIndex>) -> ScriptPubkey {
        match self {
            DescriptorRgb::None => ScriptPubkey::default(),
            DescriptorRgb::TapretKey(d) => d.derive(change, index),
        }
    }
}
