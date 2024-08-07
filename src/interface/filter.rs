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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Deref;

use rgb::XOutpoint;

pub trait OutpointFilter {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool;
}

pub struct FilterIncludeAll;
pub struct FilterExclude<T>(pub T);

impl OutpointFilter for FilterIncludeAll {
    fn include_outpoint(&self, _: impl Into<XOutpoint>) -> bool { true }
}

impl<T: OutpointFilter> OutpointFilter for FilterExclude<T> {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        !self.0.include_outpoint(outpoint.into())
    }
}

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

impl<V> OutpointFilter for HashMap<XOutpoint, V> {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        let outpoint = outpoint.into();
        self.keys().any(|o| *o == outpoint)
    }
}

impl<V> OutpointFilter for BTreeMap<XOutpoint, V> {
    fn include_outpoint(&self, outpoint: impl Into<XOutpoint>) -> bool {
        let outpoint = outpoint.into();
        self.keys().any(|o| *o == outpoint)
    }
}
