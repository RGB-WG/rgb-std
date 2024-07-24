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

use rgb::validation::{ResolveWitness, WitnessResolverError};
use rgb::vm::WitnessAnchor;
use rgb::{XWitnessId, XWitnessTx};

use crate::containers::IndexedConsignment;

pub trait ResolveWitnessAnchor {
    /// Resolves position of the witness anchor in the consensus data:
    /// blockchain, state channel etc. Used for ordering of global state and for
    /// ensuring that the we account only for the actual contract state after
    /// blockchain re-orgs and channel updates.
    ///
    /// Witness resolution must happen as fast and as cheap as getting
    /// key-values from HashMap. Thus, resolver must always be caching and
    /// doesn't actually re-query indexers for deeply mined transactions.
    fn resolve_witness_anchor(&mut self, witness_id: XWitnessId) -> Result<WitnessAnchor, String>;
}

impl<T: ResolveWitnessAnchor> ResolveWitnessAnchor for &mut T {
    #[inline]
    fn resolve_witness_anchor(&mut self, witness_id: XWitnessId) -> Result<WitnessAnchor, String> {
        (*self).resolve_witness_anchor(witness_id)
    }
}

// TODO: Implement caching witness resolver

pub(crate) struct ConsignmentResolver<'cons, R: ResolveWitness, const TRANSFER: bool> {
    pub consignment: &'cons IndexedConsignment<'cons, TRANSFER>,
    pub fallback: R,
}

impl<'cons, R: ResolveWitness, const TRANSFER: bool> ResolveWitness
    for ConsignmentResolver<'cons, R, TRANSFER>
{
    fn resolve_pub_witness(
        &self,
        witness_id: XWitnessId,
    ) -> Result<XWitnessTx, WitnessResolverError> {
        self.consignment
            .pub_witness(witness_id)
            .and_then(|p| p.map_ref(|pw| pw.tx().cloned()).transpose())
            .ok_or(WitnessResolverError::Unknown(witness_id))
            .or_else(|_| self.fallback.resolve_pub_witness(witness_id))
    }
}
