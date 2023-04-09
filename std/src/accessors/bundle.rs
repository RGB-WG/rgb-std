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

use rgb::{GraphSeal, OpId, Operation, Transition, TransitionBundle};

use crate::accessors::TypedAssignsExt;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum RevealError {
    /// the provided state transition is not a part of the bundle
    UnrelatedTransition(OpId),
}

pub trait BundleExt {
    /// Ensures that the seal is revealed inside the bundle.
    fn reveal_seal(&mut self, seal: GraphSeal);

    /// Ensures that the transition is revealed inside the bundle.
    ///
    /// # Returns
    ///
    /// `true` if the transition was previously concealed; `false` if it was
    /// already revealed; error if the transition is unrelated to the bundle.
    fn reveal_transition(&mut self, transition: &Transition) -> Result<bool, RevealError>;
}

impl BundleExt for TransitionBundle {
    fn reveal_seal(&mut self, seal: GraphSeal) {
        for (_, item) in self.keyed_values_mut() {
            if let Some(transition) = &mut item.transition {
                for (_, assign) in transition.assignments.keyed_values_mut() {
                    assign.reveal_seal(seal)
                }
            }
        }
    }

    fn reveal_transition(&mut self, transition: &Transition) -> Result<bool, RevealError> {
        let id = transition.id();
        let item = self
            .get_mut(&id)
            .ok_or(RevealError::UnrelatedTransition(id))?;
        match item.transition {
            None => {
                item.transition = Some(transition.clone());
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }
}
