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

use amplify::confinement::Confined;
use amplify::Wrapper;
use bp::dbc::anchor::MergeError;
use commit_verify::{mpc, CommitmentId};
use rgb::{
    Anchor, Assign, Assignments, ExposedSeal, ExposedState, Extension, Genesis, OpId, Transition,
    TypedAssigns,
};

use crate::containers::{Consignment, Contract};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MergeRevealError {
    /// operations {0} and {1} has different commitment ids and can't be
    /// merge-revealed. This usually means internal application business logic
    /// error which should be reported to the software vendor.
    OperationMismatch(OpId, OpId),

    #[from]
    #[display(inner)]
    AnchorMismatch(MergeError),
}

/// A trait to merge two structures modifying the revealed status
/// of the first one. The merge operation will **consume** both the structures
/// and return a new structure with revealed states.
///
/// The resulting structure will depend on the reveal status of both of the
/// variant. And the most revealed condition among the two will be selected
/// Usage: prevent hiding already known previous state data by merging
/// incoming new consignment in stash.
///
/// The following conversion logic is intended by this trait:
///
/// merge(Revealed, Anything) => Revealed
/// merge(ConfidentialSeal, ConfidentialAmount) => Revealed
/// merge(ConfidentialAmount, ConfidentialSeal) => Revealed
/// merge(Confidential, Anything) => Anything
pub trait MergeReveal: Sized {
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError>;
}

impl MergeReveal for Anchor<mpc::MerkleBlock> {
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        self.merge_reveal(other).map_err(MergeRevealError::from)
    }
}

impl<State: ExposedState, Seal: ExposedSeal> MergeReveal for Assign<State, Seal> {
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        match (self, other) {
            // Anything + Revealed = Revealed
            (_, state @ Assign::Revealed { .. }) | (state @ Assign::Revealed { .. }, _) => {
                Ok(state)
            }

            // ConfidentialAmount + ConfidentialSeal = Revealed
            (Assign::ConfidentialSeal { state, .. }, Assign::ConfidentialState { seal, .. }) => {
                Ok(Assign::Revealed { seal, state })
            }

            // ConfidentialSeal + ConfidentialAmount = Revealed
            (Assign::ConfidentialState { seal, .. }, Assign::ConfidentialSeal { state, .. }) => {
                Ok(Assign::Revealed { seal, state })
            }

            // if self and other is of same variant return self
            (state @ Assign::ConfidentialState { .. }, Assign::ConfidentialState { .. }) => {
                Ok(state)
            }
            (state @ Assign::ConfidentialSeal { .. }, Assign::ConfidentialSeal { .. }) => Ok(state),

            // Anything + Confidential = Anything
            (state, Assign::Confidential { .. }) | (Assign::Confidential { .. }, state) => {
                Ok(state)
            }
        }
    }
}

impl<Seal: ExposedSeal> MergeReveal for TypedAssigns<Seal> {
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        match (self, other) {
            (TypedAssigns::Declarative(first_vec), TypedAssigns::Declarative(second_vec)) => {
                let mut result = Vec::with_capacity(first_vec.len());
                for (first, second) in first_vec.into_iter().zip(second_vec.into_iter()) {
                    result.push(first.merge_reveal(second)?);
                }
                Ok(TypedAssigns::Declarative(
                    Confined::try_from(result).expect("collection of the same size"),
                ))
            }

            (TypedAssigns::Fungible(first_vec), TypedAssigns::Fungible(second_vec)) => {
                let mut result = Vec::with_capacity(first_vec.len());
                for (first, second) in first_vec.into_iter().zip(second_vec.into_iter()) {
                    result.push(first.merge_reveal(second)?);
                }
                Ok(TypedAssigns::Fungible(
                    Confined::try_from(result).expect("collection of the same size"),
                ))
            }

            (TypedAssigns::Structured(first_vec), TypedAssigns::Structured(second_vec)) => {
                let mut result = Vec::with_capacity(first_vec.len());
                for (first, second) in first_vec.into_iter().zip(second_vec.into_iter()) {
                    result.push(first.merge_reveal(second)?);
                }
                Ok(TypedAssigns::Structured(
                    Confined::try_from(result).expect("collection of the same size"),
                ))
            }

            (TypedAssigns::Attachment(first_vec), TypedAssigns::Attachment(second_vec)) => {
                let mut result = Vec::with_capacity(first_vec.len());
                for (first, second) in first_vec.into_iter().zip(second_vec.into_iter()) {
                    result.push(first.merge_reveal(second)?);
                }
                Ok(TypedAssigns::Attachment(
                    Confined::try_from(result).expect("collection of the same size"),
                ))
            }
            // No other patterns possible, should not reach here
            _ => {
                unreachable!("Assignments::consensus_commitments is broken")
            }
        }
    }
}

impl<Seal: ExposedSeal> MergeReveal for Assignments<Seal> {
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        let mut result = BTreeMap::new();
        for (first, second) in self
            .into_inner()
            .into_iter()
            .zip(other.into_inner().into_iter())
        {
            result.insert(first.0, first.1.merge_reveal(second.1)?);
        }
        Ok(Assignments::from_inner(
            Confined::try_from(result).expect("collection of the same size"),
        ))
    }
}

impl MergeReveal for Genesis {
    fn merge_reveal(mut self, other: Self) -> Result<Self, MergeRevealError> {
        let self_id = self.commitment_id();
        let other_id = other.commitment_id();
        if self_id != other_id {
            return Err(MergeRevealError::OperationMismatch(
                OpId::from_inner(self_id.into_inner()),
                OpId::from_inner(other_id.into_inner()),
            ));
        }
        self.assignments = self.assignments.merge_reveal(other.assignments)?;
        Ok(self)
    }
}

impl MergeReveal for Transition {
    fn merge_reveal(mut self, other: Self) -> Result<Self, MergeRevealError> {
        let self_id = self.commitment_id();
        let other_id = other.commitment_id();
        if self_id != other_id {
            return Err(MergeRevealError::OperationMismatch(self_id, other_id));
        }
        self.assignments = self.assignments.merge_reveal(other.assignments)?;
        Ok(self)
    }
}

impl MergeReveal for Extension {
    fn merge_reveal(mut self, other: Self) -> Result<Self, MergeRevealError> {
        let self_id = self.commitment_id();
        let other_id = other.commitment_id();
        if self_id != other_id {
            return Err(MergeRevealError::OperationMismatch(self_id, other_id));
        }
        self.assignments = self.assignments.merge_reveal(other.assignments)?;
        Ok(self)
    }
}

impl Contract {
    pub fn merge<const TYPE: bool>(
        &mut self,
        consignment: Consignment<TYPE>,
    ) -> Result<(), MergeRevealError> {
        todo!()
    }
}
