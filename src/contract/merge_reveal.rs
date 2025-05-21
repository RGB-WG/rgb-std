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

use amplify::confinement::Confined;
use amplify::Wrapper;
use bp::Txid;
use commit_verify::{mpc, Conceal};
use rgb::{
    Assign, Assignments, BundleId, ExposedSeal, ExposedState, Genesis, OpId, Operation, Transition,
    TransitionBundle, TypedAssigns,
};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MergeRevealError {
    /// operations {0} and {1} have different commitment ids and can't be
    /// merge-revealed. This usually means internal application business logic
    /// error which should be reported to the software vendor.
    OperationMismatch(OpId, OpId),

    /// operations with ID {0} have different signatures and can't be merge-revealed.
    /// This usually means internal application business logic
    /// error which should be reported to the software vendor.
    SignatureMismatch(OpId),

    /// mismatch in anchor chains: one grip references bitcoin transaction
    /// {bitcoin} and the other merged part references liquid transaction
    /// {liquid}.
    ChainMismatch { bitcoin: Txid, liquid: Txid },

    /// mismatching transaction id for merge-revealed: {0} and {1}.
    TxidMismatch(Txid, Txid),

    /// anchors in anchored bundle are not equal for bundle {0}.
    AnchorsNonEqual(BundleId),

    /// assignments have different keys.
    AssignmentsDifferentKeys,

    /// contract id provided for the merge-reveal operation doesn't match
    /// multiprotocol commitment.
    #[from(mpc::InvalidProof)]
    #[from(mpc::LeafNotKnown)]
    ContractMismatch,
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
pub trait MergeReveal {
    fn merge_reveal(&mut self, other: &Self) -> Result<(), MergeRevealError>;
}

impl<State: ExposedState, Seal: ExposedSeal> MergeReveal for Assign<State, Seal> {
    fn merge_reveal(&mut self, other: &Self) -> Result<(), MergeRevealError> {
        debug_assert_eq!(self.conceal(), other.conceal());
        // Anything + Revealed = Revealed
        if let Assign::Revealed { .. } = other {
            *self = other.clone();
        }
        Ok(())
    }
}

impl<Seal: ExposedSeal> MergeReveal for TypedAssigns<Seal> {
    fn merge_reveal(&mut self, other: &Self) -> Result<(), MergeRevealError> {
        match (self, other) {
            (TypedAssigns::Declarative(first_vec), TypedAssigns::Declarative(second_vec)) => {
                for (first, second) in first_vec.iter_mut().zip(second_vec.as_ref()) {
                    first.merge_reveal(second)?;
                }
            }

            (TypedAssigns::Fungible(first_vec), TypedAssigns::Fungible(second_vec)) => {
                for (first, second) in first_vec.iter_mut().zip(second_vec.as_ref()) {
                    first.merge_reveal(second)?;
                }
            }

            (TypedAssigns::Structured(first_vec), TypedAssigns::Structured(second_vec)) => {
                for (first, second) in first_vec.iter_mut().zip(second_vec.as_ref()) {
                    first.merge_reveal(second)?;
                }
            }

            // No other patterns possible, should not reach here
            _ => {
                unreachable!("Assignments::consensus_commitments is broken")
            }
        };
        Ok(())
    }
}

impl<Seal: ExposedSeal> MergeReveal for Assignments<Seal> {
    fn merge_reveal(&mut self, other: &Self) -> Result<(), MergeRevealError> {
        for (ass_type, other_typed_assigns) in other.as_inner().iter() {
            let typed_assigns = self
                .get_mut(ass_type)
                .ok_or(MergeRevealError::AssignmentsDifferentKeys)?;
            typed_assigns.merge_reveal(other_typed_assigns)?;
        }
        Ok(())
    }
}

impl MergeReveal for TransitionBundle {
    fn merge_reveal(&mut self, other: &Self) -> Result<(), MergeRevealError> {
        debug_assert_eq!(self.bundle_id(), other.bundle_id());

        let mut self_transitions = self.known_transitions.to_unconfined();
        for (opid, other_transition) in &other.known_transitions {
            if let Some(transition) = self_transitions.get_mut(opid) {
                transition.merge_reveal(other_transition)?;
            }
        }
        self.known_transitions = Confined::from_checked(self_transitions);
        Ok(())
    }
}

impl MergeReveal for Genesis {
    fn merge_reveal(&mut self, other: &Self) -> Result<(), MergeRevealError> {
        let self_id = self.id();
        let other_id = other.id();
        if self_id != other_id {
            return Err(MergeRevealError::OperationMismatch(
                OpId::from_inner(self_id.into_inner()),
                OpId::from_inner(other_id.into_inner()),
            ));
        }
        self.assignments.merge_reveal(&other.assignments)?;
        Ok(())
    }
}

impl MergeReveal for Transition {
    fn merge_reveal(&mut self, other: &Self) -> Result<(), MergeRevealError> {
        let self_id = self.id();
        let other_id = other.id();
        if self_id != other_id {
            return Err(MergeRevealError::OperationMismatch(self_id, other_id));
        }
        self.assignments.merge_reveal(&other.assignments)?;
        match (self.signature.take(), other.signature.as_ref()) {
            (None, None) => {}
            (Some(sig), None) => {
                self.signature = Some(sig);
            }
            (None, Some(sig)) => {
                self.signature = Some(sig.clone());
            }
            (Some(sig1), Some(sig2)) if sig1 == *sig2 => {
                self.signature = Some(sig1);
            }
            _ => {
                return Err(MergeRevealError::SignatureMismatch(self_id));
            }
        };
        Ok(())
    }
}
