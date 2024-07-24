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

use std::cmp::Ordering;
use std::fmt::Debug;

use amplify::confinement::SmallVec;
use commit_verify::Conceal;
use invoice::Amount;
use rgb::vm::AssignmentWitness;
use rgb::{
    Assign, AssignAttach, AssignData, AssignFungible, AssignRights, AssignmentType, AttachState,
    DataState, ExposedSeal, ExposedState, OpId, Opout, RevealedAttach, RevealedData, RevealedValue,
    TypedAssigns, VoidState, XChain, XOutputSeal, XWitnessId,
};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::LIB_NAME_RGB_STD;

/// Trait used by contract state. Unlike [`ExposedState`] it doesn't allow
/// concealment of the state, i.e. may contain incomplete data without blinding
/// factors, asset tags etc.
pub trait KnownState: Debug + StrictDumb + StrictEncode + StrictDecode + Eq + Clone {}

impl KnownState for () {}
impl KnownState for VoidState {}
impl KnownState for DataState {}
impl KnownState for Amount {}
impl KnownState for AttachState {}
impl KnownState for RevealedValue {}
impl KnownState for RevealedData {}
impl KnownState for RevealedAttach {}

#[derive(Copy, Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct OutputAssignment<State: KnownState> {
    pub opout: Opout,
    pub seal: XOutputSeal,
    pub state: State,
    pub witness: AssignmentWitness,
}

impl<State: KnownState> PartialEq for OutputAssignment<State> {
    fn eq(&self, other: &Self) -> bool {
        if self.opout == other.opout &&
            (self.seal != other.seal ||
                self.witness != other.witness ||
                self.state != other.state)
        {
            panic!(
                "RGB was provided with an updated operation using different witness transaction. \
                 This may happen for instance when some ephemeral state (like a commitment or \
                 HTLC transactions in the lightning channels) is added to the stash.\nThis error \
                 means the software uses RGB stash in an invalid way and has business logic bug \
                 which has to be fixed.\nOperation in stash: {:?}\nNew operation: {:?}\n",
                self, other
            )
        }
        self.opout == other.opout
    }
}

impl<State: KnownState> PartialOrd for OutputAssignment<State> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<State: KnownState> Ord for OutputAssignment<State> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        self.opout.cmp(&other.opout)
    }
}

impl<State: KnownState> OutputAssignment<State> {
    /// # Panics
    ///
    /// If the processing is done on invalid stash data, the seal is
    /// witness-based and the anchor chain doesn't match the seal chain.
    pub fn with_witness<Seal: ExposedSeal>(
        seal: XChain<Seal>,
        witness_id: XWitnessId,
        state: State,
        opid: OpId,
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal.try_to_output_seal(witness_id).expect(
                "processing contract from unverified/invalid stash: witness seal chain doesn't \
                 match anchor's chain",
            ),
            state,
            witness: witness_id.into(),
        }
    }

    /// # Panics
    ///
    /// If the processing is done on invalid stash data, the seal is
    /// witness-based and the anchor chain doesn't match the seal chain.
    pub fn with_no_witness<Seal: ExposedSeal>(
        seal: XChain<Seal>,
        state: State,
        opid: OpId,
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal.to_output_seal().expect(
                "processing contract from unverified/invalid stash: seal must have txid \
                 information since it comes from genesis or extension",
            ),
            state,
            witness: AssignmentWitness::Absent,
        }
    }

    pub fn transmute<S: KnownState>(self) -> OutputAssignment<S>
    where S: From<State> {
        OutputAssignment {
            opout: self.opout,
            seal: self.seal,
            state: self.state.into(),
            witness: self.witness,
        }
    }

    pub fn check_witness(&self, filter: impl FnOnce(XWitnessId) -> bool) -> bool {
        match self.witness {
            AssignmentWitness::Absent => true,
            AssignmentWitness::Present(witness_id) => filter(witness_id),
        }
    }
}

pub trait TypedAssignsExt<Seal: ExposedSeal> {
    fn reveal_seal(&mut self, seal: XChain<Seal>);

    fn filter_revealed_seals(&self) -> Vec<XChain<Seal>>;
}

impl<Seal: ExposedSeal> TypedAssignsExt<Seal> for TypedAssigns<Seal> {
    fn reveal_seal(&mut self, seal: XChain<Seal>) {
        fn reveal<State: ExposedState, Seal: ExposedSeal>(
            vec: &mut SmallVec<Assign<State, Seal>>,
            revealed: XChain<Seal>,
        ) {
            for assign in vec.iter_mut() {
                match assign {
                    Assign::ConfidentialSeal { seal, state, lock }
                        if *seal == revealed.conceal() =>
                    {
                        *assign = Assign::Revealed {
                            seal: revealed,
                            state: state.clone(),
                            lock: *lock,
                        }
                    }
                    Assign::Confidential { seal, state, lock } if *seal == revealed.conceal() => {
                        *assign = Assign::ConfidentialState {
                            seal: revealed,
                            state: *state,
                            lock: *lock,
                        }
                    }
                    _ => {}
                }
            }
        }

        match self {
            TypedAssigns::Declarative(v) => reveal(v, seal),
            TypedAssigns::Fungible(v) => reveal(v, seal),
            TypedAssigns::Structured(v) => reveal(v, seal),
            TypedAssigns::Attachment(v) => reveal(v, seal),
        }
    }

    fn filter_revealed_seals(&self) -> Vec<XChain<Seal>> {
        match self {
            TypedAssigns::Declarative(s) => {
                s.iter().filter_map(AssignRights::revealed_seal).collect()
            }
            TypedAssigns::Fungible(s) => {
                s.iter().filter_map(AssignFungible::revealed_seal).collect()
            }
            TypedAssigns::Structured(s) => s.iter().filter_map(AssignData::revealed_seal).collect(),
            TypedAssigns::Attachment(s) => {
                s.iter().filter_map(AssignAttach::revealed_seal).collect()
            }
        }
    }
}
