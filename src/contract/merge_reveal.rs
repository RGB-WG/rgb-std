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

use std::collections::BTreeMap;

use amplify::confinement::Confined;
use amplify::Wrapper;
use bp::Txid;
use commit_verify::{mpc, Conceal};
use rgb::assignments::AssignVec;
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

    /// the merged bundles contain more transitions than inputs.
    InsufficientInputs,

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
pub trait MergeReveal: Sized {
    // TODO: Take self by mut ref instead of consuming (will remove clones in
    //       Stash::consume operation).
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError>;
}

/*
pub trait MergeRevealContract: Sized {
    fn merge_reveal_contract(
        self,
        other: Self,
        contract_id: ContractId,
    ) -> Result<Self, MergeRevealError>;
}
 */

impl<State: ExposedState, Seal: ExposedSeal> MergeReveal for Assign<State, Seal> {
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        debug_assert_eq!(self.conceal(), other.conceal());
        match (self, other) {
            // Anything + Revealed = Revealed
            (_, state @ Assign::Revealed { .. }) | (state @ Assign::Revealed { .. }, _) => {
                Ok(state)
            }

            (state @ Assign::ConfidentialSeal { .. }, Assign::ConfidentialSeal { .. }) => Ok(state),
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
                Ok(TypedAssigns::Declarative(AssignVec::with(
                    Confined::try_from(result).expect("collection of the same size"),
                )))
            }

            (TypedAssigns::Fungible(first_vec), TypedAssigns::Fungible(second_vec)) => {
                let mut result = Vec::with_capacity(first_vec.len());
                for (first, second) in first_vec.into_iter().zip(second_vec.into_iter()) {
                    result.push(first.merge_reveal(second)?);
                }
                Ok(TypedAssigns::Fungible(AssignVec::with(
                    Confined::try_from(result).expect("collection of the same size"),
                )))
            }

            (TypedAssigns::Structured(first_vec), TypedAssigns::Structured(second_vec)) => {
                let mut result = Vec::with_capacity(first_vec.len());
                for (first, second) in first_vec.into_iter().zip(second_vec.into_iter()) {
                    result.push(first.merge_reveal(second)?);
                }
                Ok(TypedAssigns::Structured(AssignVec::with(
                    Confined::try_from(result).expect("collection of the same size"),
                )))
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
            debug_assert_eq!(first.0, second.0);
            result.insert(first.0, first.1.merge_reveal(second.1)?);
        }
        Ok(Assignments::from_inner(
            Confined::try_from(result).expect("collection of the same size"),
        ))
    }
}

impl MergeReveal for TransitionBundle {
    fn merge_reveal(mut self, other: Self) -> Result<Self, MergeRevealError> {
        debug_assert_eq!(self.bundle_id(), other.bundle_id());

        let mut self_transitions = self.known_transitions.release();
        for (opid, other_transition) in other.known_transitions {
            if let Some(mut transition) = self_transitions.remove(&opid) {
                transition = transition.merge_reveal(other_transition)?;
                self_transitions.insert(opid, transition);
            }
        }
        self.known_transitions = Confined::from_checked(self_transitions);

        if self.input_map.len() < self.known_transitions.len() {
            return Err(MergeRevealError::InsufficientInputs);
        }
        Ok(self)
    }
}

/*
impl MergeRevealContract for AnchoredBundle {
    fn merge_reveal_contract(
        self,
        other: Self,
        contract_id: ContractId,
    ) -> Result<Self, MergeRevealError> {
        let bundle_id = self.bundle_id();
        let anchor1 = self.anchor.into_merkle_block(contract_id, bundle_id)?;
        let anchor2 = other.anchor.into_merkle_block(contract_id, bundle_id)?;
        Ok(AnchoredBundle {
            anchor: anchor1
                .merge_reveal(anchor2)?
                .into_merkle_proof(contract_id)?,
            bundle: self.bundle.merge_reveal(other.bundle)?,
        })
    }
}
 */

impl MergeReveal for Genesis {
    fn merge_reveal(mut self, other: Self) -> Result<Self, MergeRevealError> {
        let self_id = self.id();
        let other_id = other.id();
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
        let self_id = self.id();
        let other_id = other.id();
        if self_id != other_id {
            return Err(MergeRevealError::OperationMismatch(self_id, other_id));
        }
        self.assignments = self.assignments.merge_reveal(other.assignments)?;
        let signature = match (self.signature, other.signature) {
            (None, None) => None,
            (Some(sig), None) => Some(sig),
            (None, Some(sig)) => Some(sig),
            (Some(sig1), Some(sig2)) if sig1 == sig2 => Some(sig1),
            _ => return Err(MergeRevealError::SignatureMismatch(self_id)),
        };
        self.signature = signature;
        Ok(self)
    }
}
