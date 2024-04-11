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

use rgb::{GraphSeal, OpId, Operation, Transition, TransitionBundle, XChain};

use crate::accessors::TypedAssignsExt;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum RevealError {
    /// the provided state transition is not a part of the bundle
    UnrelatedTransition(OpId, Transition),
}

pub trait BundleExt {
    /// Ensures that the seal is revealed inside the bundle.
    fn reveal_seal(&mut self, seal: XChain<GraphSeal>);

    /// Ensures that the transition is revealed inside the bundle.
    ///
    /// # Returns
    ///
    /// `true` if the transition was previously concealed; `false` if it was
    /// already revealed; error if the transition is unrelated to the bundle.
    fn reveal_transition(&mut self, transition: Transition) -> Result<bool, RevealError>;
}

impl BundleExt for TransitionBundle {
    fn reveal_seal(&mut self, seal: XChain<GraphSeal>) {
        for (_, transition) in self.known_transitions.keyed_values_mut() {
            for (_, assign) in transition.assignments.keyed_values_mut() {
                assign.reveal_seal(seal)
            }
        }
    }

    fn reveal_transition(&mut self, transition: Transition) -> Result<bool, RevealError> {
        let opid = transition.id();
        if self.input_map.values().any(|id| id == &opid) {
            return Err(RevealError::UnrelatedTransition(opid, transition));
        }
        if self.known_transitions.contains_key(&opid) {
            return Ok(false);
        }
        self.known_transitions
            .insert(opid, transition)
            .expect("same size as input map");
        Ok(true)
    }
}
