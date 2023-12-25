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

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::ops::{BitOr, BitOrAssign};
use std::vec;

use amplify::confinement;
use amplify::confinement::{Confined, U24};
use bp::seals::txout::CloseMethod;
use commit_verify::mpc;
use rgb::{ContractId, OpId, Operation, OutputSeal, Transition, TransitionBundle, XAnchor};
use strict_encoding::{StrictDeserialize, StrictDumb, StrictSerialize};

use crate::containers::XchainOutpoint;
use crate::LIB_NAME_RGB_STD;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
pub enum CloseMethodSet {
    #[strict_type(dumb)]
    TapretFirst = 0x01,
    OpretFirst = 0x02,
    Both = 0x03,
}

impl BitOr<Option<CloseMethodSet>> for CloseMethodSet {
    type Output = Self;
    fn bitor(mut self, rhs: Option<CloseMethodSet>) -> Self::Output {
        if let Some(m) = rhs {
            self |= m
        };
        self
    }
}

impl BitOrAssign<Option<CloseMethodSet>> for CloseMethodSet {
    fn bitor_assign(&mut self, rhs: Option<CloseMethodSet>) {
        if let Some(m) = rhs {
            *self |= m
        };
    }
}

impl BitOr<CloseMethodSet> for Option<CloseMethodSet> {
    type Output = CloseMethodSet;
    fn bitor(self, mut rhs: CloseMethodSet) -> Self::Output {
        if let Some(m) = self {
            rhs |= m
        };
        rhs
    }
}

impl BitOrAssign<CloseMethodSet> for Option<CloseMethodSet> {
    fn bitor_assign(&mut self, rhs: CloseMethodSet) { *self = Some(rhs | *self) }
}

impl BitOr for CloseMethodSet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output { if self == rhs { self } else { Self::Both } }
}

impl BitOrAssign for CloseMethodSet {
    fn bitor_assign(&mut self, rhs: Self) { *self = self.bitor(rhs); }
}

impl From<OutputSeal> for CloseMethodSet {
    fn from(seal: OutputSeal) -> Self { seal.method().into() }
}

impl From<CloseMethod> for CloseMethodSet {
    fn from(method: CloseMethod) -> Self {
        match method {
            CloseMethod::OpretFirst => CloseMethodSet::OpretFirst,
            CloseMethod::TapretFirst => CloseMethodSet::TapretFirst,
        }
    }
}

impl CloseMethodSet {
    pub fn has_tapret_first(self) -> bool { matches!(self, Self::TapretFirst | Self::Both) }
    pub fn has_opret_first(self) -> bool { matches!(self, Self::OpretFirst | Self::Both) }
}

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionInfo {
    pub id: OpId,
    pub inputs: Confined<Vec<XchainOutpoint>, 1, U24>,
    pub transition: Transition,
    pub methods: CloseMethodSet,
}

impl StrictDumb for TransitionInfo {
    fn strict_dumb() -> Self { Self::new(strict_dumb!(), [strict_dumb!()]).unwrap() }
}

impl PartialEq for TransitionInfo {
    fn eq(&self, other: &Self) -> bool { self.id.eq(&other.id) }
}

impl Ord for TransitionInfo {
    fn cmp(&self, other: &Self) -> Ordering { self.id.cmp(&other.id) }
}

impl PartialOrd for TransitionInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Hash for TransitionInfo {
    fn hash<H: Hasher>(&self, state: &mut H) { state.write(self.id.as_slice()) }
}

impl TransitionInfo {
    pub fn new(
        transition: Transition,
        seals: impl AsRef<[OutputSeal]>,
    ) -> Result<Self, confinement::Error> {
        let inputs = Confined::<Vec<_>, 1, U24>::try_from_iter(
            seals.as_ref().iter().copied().map(XchainOutpoint::from),
        )?;
        let methods = seals
            .as_ref()
            .iter()
            .map(|seal| seal.method())
            .map(CloseMethodSet::from)
            .fold(None, |acc, i| {
                Some(match acc {
                    None => i,
                    Some(a) => a | i,
                })
            })
            .expect("confinement guarantees at least one item");
        Ok(TransitionInfo {
            id: transition.id(),
            inputs,
            transition,
            methods,
        })
    }
}

/// A batch of state transitions under different contracts which are associated
/// with some specific transfer and will be anchored within a single layer 1
/// transaction.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Batch {
    pub main: TransitionInfo,
    pub blanks: Confined<Vec<TransitionInfo>, 0, { U24 - 1 }>,
}

impl StrictSerialize for Batch {}
impl StrictDeserialize for Batch {}

impl IntoIterator for Batch {
    type Item = TransitionInfo;
    type IntoIter = vec::IntoIter<TransitionInfo>;

    fn into_iter(self) -> Self::IntoIter {
        let mut vec = self.blanks.into_inner();
        vec.push(self.main);
        vec.into_iter()
    }
}

impl Batch {
    pub fn close_method_set(&self) -> CloseMethodSet {
        let mut methods = self.main.methods;
        self.blanks.iter().for_each(|i| methods |= i.methods);
        methods
    }
}

/// Structure exported from a PSBT for merging into the stash. It contains a set
/// of finalized state transitions (under multiple contracts), packed into
/// bundles, and anchored to a single layer 1 transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Fascia {
    pub anchor: XAnchor<mpc::MerkleBlock>,
    pub bundles: Confined<BTreeMap<ContractId, TransitionBundle>, 1, U24>,
}

impl StrictDumb for Fascia {
    fn strict_dumb() -> Self {
        Fascia {
            anchor: strict_dumb!(),
            bundles: confined_bmap![strict_dumb!() => strict_dumb!()],
        }
    }
}
impl StrictSerialize for Fascia {}
impl StrictDeserialize for Fascia {}
