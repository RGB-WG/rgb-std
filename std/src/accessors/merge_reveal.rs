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

use bp::dbc::anchor::MergeError;
use commit_verify::{mpc, CommitmentId};
use rgb::Anchor;

use crate::containers::{Consignment, Contract};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MergeRevealError {
    /// two data structure which are merged with `merge_reveal` procedure have
    /// different commitment ids ({0}, {1}), meaning internal application
    /// business logic error (merging unrelated data structures). Please report
    /// this issue to your software vendor.
    CommitmentMismatch,

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
pub trait MergeReveal: Sized + CommitmentId
where Self::Id: Eq
{
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        let self_id = self.commitment_id();
        let other_id = other.commitment_id();
        if self_id != other_id {
            Err(MergeRevealError::CommitmentMismatch)
        } else {
            unsafe { self.merge_reveal_internal(other) }
        }
    }

    #[doc = hidden]
    unsafe fn merge_reveal_internal(self, other: Self) -> Result<Self, MergeRevealError>;
}

impl MergeReveal for Anchor<mpc::MerkleBlock> {
    unsafe fn merge_reveal_internal(self, other: Self) -> Result<Self, MergeRevealError> {
        self.merge_reveal(other).map_err(MergeRevealError::from)
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
