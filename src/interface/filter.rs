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

use rgb::{XOutpoint, XWitnessId};

pub trait AssignmentsFilter {
    fn should_include(
        &self,
        outpoint: impl Into<XOutpoint>,
        witness_id: Option<XWitnessId>,
    ) -> bool;
}

pub struct FilterIncludeAll;
pub struct FilterExclude<T>(pub T);

impl AssignmentsFilter for FilterIncludeAll {
    fn should_include(&self, _: impl Into<XOutpoint>, _: Option<XWitnessId>) -> bool { true }
}

impl<T: AssignmentsFilter> AssignmentsFilter for FilterExclude<T> {
    fn should_include(
        &self,
        outpoint: impl Into<XOutpoint>,
        witness_id: Option<XWitnessId>,
    ) -> bool {
        !self.0.should_include(outpoint.into(), witness_id)
    }
}

impl<T: AssignmentsFilter> AssignmentsFilter for &T {
    fn should_include(
        &self,
        outpoint: impl Into<XOutpoint>,
        witness_id: Option<XWitnessId>,
    ) -> bool {
        (*self).should_include(outpoint, witness_id)
    }
}

impl<T: AssignmentsFilter> AssignmentsFilter for &mut T {
    fn should_include(
        &self,
        outpoint: impl Into<XOutpoint>,
        witness_id: Option<XWitnessId>,
    ) -> bool {
        self.deref().should_include(outpoint, witness_id)
    }
}

impl<T: AssignmentsFilter> AssignmentsFilter for Option<T> {
    fn should_include(
        &self,
        outpoint: impl Into<XOutpoint>,
        witness_id: Option<XWitnessId>,
    ) -> bool {
        self.as_ref()
            .map(|filter| filter.should_include(outpoint, witness_id))
            .unwrap_or(true)
    }
}

impl AssignmentsFilter for XOutpoint {
    fn should_include(&self, outpoint: impl Into<XOutpoint>, _: Option<XWitnessId>) -> bool {
        *self == outpoint.into()
    }
}

impl<const LEN: usize> AssignmentsFilter for [XOutpoint; LEN] {
    fn should_include(&self, outpoint: impl Into<XOutpoint>, _: Option<XWitnessId>) -> bool {
        self.contains(&outpoint.into())
    }
}

impl AssignmentsFilter for &[XOutpoint] {
    fn should_include(&self, outpoint: impl Into<XOutpoint>, _: Option<XWitnessId>) -> bool {
        self.contains(&outpoint.into())
    }
}

impl AssignmentsFilter for Vec<XOutpoint> {
    fn should_include(&self, outpoint: impl Into<XOutpoint>, _: Option<XWitnessId>) -> bool {
        self.contains(&outpoint.into())
    }
}

impl AssignmentsFilter for HashSet<XOutpoint> {
    fn should_include(&self, outpoint: impl Into<XOutpoint>, _: Option<XWitnessId>) -> bool {
        self.contains(&outpoint.into())
    }
}

impl AssignmentsFilter for BTreeSet<XOutpoint> {
    fn should_include(&self, outpoint: impl Into<XOutpoint>, _: Option<XWitnessId>) -> bool {
        self.contains(&outpoint.into())
    }
}

impl<V> AssignmentsFilter for HashMap<XOutpoint, V> {
    fn should_include(&self, outpoint: impl Into<XOutpoint>, _: Option<XWitnessId>) -> bool {
        let outpoint = outpoint.into();
        self.keys().any(|o| *o == outpoint)
    }
}

impl<V> AssignmentsFilter for BTreeMap<XOutpoint, V> {
    fn should_include(&self, outpoint: impl Into<XOutpoint>, _: Option<XWitnessId>) -> bool {
        let outpoint = outpoint.into();
        self.keys().any(|o| *o == outpoint)
    }
}
