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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Deref;

use rgb::{AssignmentWitness, XOutpoint};

pub trait WitnessFilter {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool;
}

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

// WitnessFilter

impl WitnessFilter for FilterIncludeAll {
    fn include_witness(&self, _: impl Into<AssignmentWitness>) -> bool { true }
}

impl<T: WitnessFilter> WitnessFilter for FilterExclude<T> {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        !self.0.include_witness(witness.into())
    }
}

impl<T: WitnessFilter> WitnessFilter for &T {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        (*self).include_witness(witness)
    }
}

impl<T: WitnessFilter> WitnessFilter for &mut T {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        self.deref().include_witness(witness)
    }
}

impl<T: WitnessFilter> WitnessFilter for Option<T> {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        self.as_ref()
            .map(|filter| filter.include_witness(witness))
            .unwrap_or(true)
    }
}

impl WitnessFilter for AssignmentWitness {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        *self == witness.into()
    }
}

impl<const LEN: usize> WitnessFilter for [AssignmentWitness; LEN] {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        self.contains(&witness.into())
    }
}

impl WitnessFilter for &[AssignmentWitness] {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        self.contains(&witness.into())
    }
}

impl WitnessFilter for Vec<AssignmentWitness> {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        self.contains(&witness.into())
    }
}

impl WitnessFilter for HashSet<AssignmentWitness> {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        self.contains(&witness.into())
    }
}

impl WitnessFilter for BTreeSet<AssignmentWitness> {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        self.contains(&witness.into())
    }
}

impl<V> WitnessFilter for HashMap<AssignmentWitness, V> {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        let witness = witness.into();
        self.keys().any(|w| *w == witness)
    }
}

impl<V> WitnessFilter for BTreeMap<AssignmentWitness, V> {
    fn include_witness(&self, witness: impl Into<AssignmentWitness>) -> bool {
        let witness = witness.into();
        self.keys().any(|w| *w == witness)
    }
}
