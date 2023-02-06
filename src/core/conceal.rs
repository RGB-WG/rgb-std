// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2023 Dr Maxim Orlovsky. All rights reserved.
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

use core::cmp::Ord;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;

use amplify::confinement::{Collection, Confined};

use super::seal;

pub trait RevealSeals {
    /// Reveals previously known seal information (replacing blind UTXOs with
    /// unblind ones). Function is used when a peer receives consignments
    /// containing concealed seals for the outputs owned by the peer.
    ///
    /// # Returns
    ///
    /// Total number of seals revealed inside the data structure during the
    /// operation.
    fn reveal_seals(&mut self, known_seals: &[seal::Revealed]) -> usize;
}

/// Trait for types supporting conversion to a [`RevealedSeal`]
pub trait IntoRevealedSeal {
    /// Converts seal into [`RevealedSeal`] type.
    fn into_revealed_seal(self) -> RevealedSeal;
}

/// Trait which must be implemented by all data structures having seals in their
/// hierarchy.
pub trait ConcealSeals {
    /// Request to conceal all seals from a given subset of seals.
    ///
    /// # Returns
    ///
    /// Number of seals instances which were concealed.
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize;
}

/// Trait which must be implemented by all data structures having state data.
pub trait ConcealState {
    /// Request to conceal all state.
    ///
    /// # Returns
    ///
    /// Count of state atoms which were concealed.
    fn conceal_state(&mut self) -> usize { self.conceal_state_except(&[]) }

    /// Request to conceal all of the state except given subset.
    ///
    /// The function doesn't requires that the state from the subset should
    /// be a revealed state; if the state atom is concealed than it is just
    /// ignored.
    ///
    /// # Returns
    ///
    /// Count of state atoms which were concealed.
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize;
}

pub trait ConcealTransitions {
    fn conceal_transitions(&mut self) -> usize { self.conceal_transitions_except(&[]) }
    fn conceal_transitions_except(&mut self, node_ids: &[NodeId]) -> usize;
}

impl<T, const MIN: usize, const MAX: usize> ConcealSeals for Confined<Vec<T>, MIN, MAX>
where T: ConcealSeals
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.conceal_seals(seals))
    }
}

impl<T, const MIN: usize, const MAX: usize> ConcealSeals for Confined<BTreeSet<T>, MIN, MAX>
where T: ConcealSeals + Ord + Clone
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        let mut new_self = BTreeSet::<T>::with_capacity(self.len());
        for item in self.iter() {
            let mut new_item = item.clone();
            count += new_item.conceal_seals(seals);
            new_self.insert(new_item);
        }
        *self = Confined::try_from(new_self).expect("same size");
        count
    }
}

impl<K, V, const MIN: usize, const MAX: usize> ConcealSeals for Confined<BTreeMap<K, V>, MIN, MAX>
where
    K: Ord + Hash,
    V: ConcealSeals,
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        self.keyed_values_mut()
            .fold(0usize, |sum, item| sum + item.1.conceal_seals(seals))
    }
}

impl<T, const MIN: usize, const MAX: usize> ConcealState for Confined<Vec<T>, MIN, MAX>
where T: ConcealState
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.conceal_state_except(seals))
    }
}

impl<T, const MIN: usize, const MAX: usize> ConcealState for Confined<BTreeSet<T>, MIN, MAX>
where T: ConcealState + Ord + Clone
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        let mut new_self = BTreeSet::<T>::with_capacity(self.len());
        for item in self.iter() {
            let mut new_item = item.clone();
            count += new_item.conceal_state_except(seals);
            new_self.insert(new_item);
        }
        *self = Confined::try_from(new_self).expect("same size");
        count
    }
}

impl<K, V, const MIN: usize, const MAX: usize> ConcealState for Confined<BTreeMap<K, V>, MIN, MAX>
where
    K: Ord + Hash,
    V: ConcealState,
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        self.keyed_values_mut()
            .fold(0usize, |sum, item| sum + item.1.conceal_state_except(seals))
    }
}

impl<StateType> RevealSeals for Assignment<StateType>
where
    StateType: State,
    StateType::Revealed: Conceal,
    StateType::Confidential: PartialEq + Eq,
    <StateType as State>::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn reveal_seals(&mut self, known_seals: &[seal::Revealed]) -> usize {
        let known_seals: HashMap<seal::Confidential, seal::Revealed> = known_seals
            .iter()
            .map(|rev| (rev.conceal(), *rev))
            .collect();

        let mut counter = 0;
        match self {
            Assignment::Confidential { seal, state } => {
                if let Some(reveal) = known_seals.get(seal) {
                    *self = Assignment::ConfidentialState {
                        seal: *reveal,
                        state: state.clone(),
                    };
                    counter += 1;
                };
            }
            Assignment::ConfidentialSeal { seal, state } => {
                if let Some(reveal) = known_seals.get(seal) {
                    *self = Assignment::Revealed {
                        seal: *reveal,
                        state: state.clone(),
                    };
                    counter += 1;
                };
            }
            _ => {}
        }
        counter
    }
}

impl<StateType> ConcealSeals for Assignment<StateType>
where
    StateType: State,
    StateType::Revealed: Conceal,
    StateType::Confidential: PartialEq + Eq,
    <StateType as State>::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        match self {
            Assignment::Confidential { .. } | Assignment::ConfidentialSeal { .. } => 0,
            Assignment::ConfidentialState { seal, state } => {
                if seals.contains(&seal.conceal()) {
                    *self = Assignment::<StateType>::Confidential {
                        state: state.clone(),
                        seal: seal.conceal(),
                    };
                    1
                } else {
                    0
                }
            }
            Assignment::Revealed { seal, state } => {
                if seals.contains(&seal.conceal()) {
                    *self = Assignment::<StateType>::ConfidentialSeal {
                        state: state.clone(),
                        seal: seal.conceal(),
                    };
                    1
                } else {
                    0
                }
            }
        }
    }
}

impl<StateType> ConcealState for Assignment<StateType>
where
    StateType: State,
    StateType::Revealed: Conceal,
    StateType::Confidential: PartialEq + Eq,
    <StateType as State>::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        match self {
            Assignment::Confidential { .. } | Assignment::ConfidentialState { .. } => 0,
            Assignment::ConfidentialSeal { seal, state } => {
                if seals.contains(seal) {
                    0
                } else {
                    *self = Assignment::<StateType>::Confidential {
                        state: state.conceal().into(),
                        seal: *seal,
                    };
                    1
                }
            }
            Assignment::Revealed { seal, state } => {
                if seals.contains(&seal.conceal()) {
                    0
                } else {
                    *self = Assignment::<StateType>::ConfidentialState {
                        state: state.conceal().into(),
                        seal: *seal,
                    };
                    1
                }
            }
        }
    }
}

impl RevealSeals for TypedAssignments {
    fn reveal_seals(&mut self, known_seals: &[seal::Revealed]) -> usize {
        let mut counter = 0;
        match self {
            TypedAssignments::Void(_) => {}
            TypedAssignments::Value(set) => {
                *self = TypedAssignments::Value(
                    Confined::try_from_iter(set.iter().map(|assignment| {
                        let mut assignment = assignment.clone();
                        counter += assignment.reveal_seals(known_seals);
                        assignment
                    }))
                    .expect("same size"),
                );
            }
            TypedAssignments::Data(set) => {
                *self = TypedAssignments::Data(
                    Confined::try_from_iter(set.iter().map(|assignment| {
                        let mut assignment = assignment.clone();
                        counter += assignment.reveal_seals(known_seals);
                        assignment
                    }))
                    .expect("same size"),
                );
            }
            TypedAssignments::Attachment(set) => {
                *self = TypedAssignments::Attachment(
                    Confined::try_from_iter(set.iter().map(|assignment| {
                        let mut assignment = assignment.clone();
                        counter += assignment.reveal_seals(known_seals);
                        assignment
                    }))
                    .expect("same size"),
                );
            }
        }
        counter
    }
}

impl ConcealSeals for TypedAssignments {
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        match self {
            TypedAssignments::Void(data) => data as &mut dyn ConcealSeals,
            TypedAssignments::Value(data) => data as &mut dyn ConcealSeals,
            TypedAssignments::Data(data) => data as &mut dyn ConcealSeals,
            TypedAssignments::Attachment(data) => data as &mut dyn ConcealSeals,
        }
        .conceal_seals(seals)
    }
}

impl ConcealState for TypedAssignments {
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        match self {
            TypedAssignments::Void(data) => data as &mut dyn ConcealState,
            TypedAssignments::Value(data) => data as &mut dyn ConcealState,
            TypedAssignments::Data(data) => data as &mut dyn ConcealState,
            TypedAssignments::Attachment(data) => data as &mut dyn ConcealState,
        }
        .conceal_state_except(seals)
    }
}

impl ConcealState for Genesis {
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().keyed_values_mut() {
            count += assignment.conceal_state_except(seals);
        }
        count
    }
}

impl ConcealState for Extension {
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().keyed_values_mut() {
            count += assignment.conceal_state_except(seals);
        }
        count
    }
}

impl ConcealState for Transition {
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().keyed_values_mut() {
            count += assignment.conceal_state_except(seals);
        }
        count
    }
}

impl ConcealSeals for Genesis {
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().keyed_values_mut() {
            count += assignment.conceal_seals(seals);
        }
        count
    }
}

impl ConcealSeals for Transition {
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().keyed_values_mut() {
            count += assignment.conceal_seals(seals);
        }
        count
    }
}

impl ConcealSeals for Extension {
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().keyed_values_mut() {
            count += assignment.conceal_seals(seals);
        }
        count
    }
}

impl ConcealState for TransitionBundle {
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut counter = 0;
        self.revealed =
            Confined::try_from_iter(self.revealed.iter().map(|(transition, inputs)| {
                let mut transition = transition.clone();
                counter += transition.conceal_state_except(seals);
                (transition, inputs.clone())
            }))
            .expect("same size");
        counter
    }
}

impl ConcealSeals for TransitionBundle {
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut counter = 0;
        self.revealed =
            Confined::try_from_iter(self.revealed.iter().map(|(transition, inputs)| {
                let mut transition = transition.clone();
                counter += transition.conceal_seals(seals);
                (transition, inputs.clone())
            }))
            .expect("same size");
        counter
    }
}

impl RevealSeals for TransitionBundle {
    fn reveal_seals(&mut self, known_seals: &[seal::Revealed]) -> usize {
        let mut counter = 0;
        self.revealed =
            Confined::try_from_iter(self.revealed.iter().map(|(transition, inputs)| {
                let mut transition = transition.clone();
                for (_, assignment) in transition.owned_rights_mut().keyed_values_mut() {
                    counter += assignment.reveal_seals(known_seals);
                }
                (transition, inputs.clone())
            }))
            .expect("same size");
        counter
    }
}

impl ConcealTransitions for TransitionBundle {
    fn conceal_transitions_except(&mut self, node_ids: &[NodeId]) -> usize {
        let mut concealed = bmap! {};
        self.revealed =
            Confined::try_from_iter(self.revealed.iter().filter_map(|(transition, inputs)| {
                let node_id = transition.node_id();
                if !node_ids.contains(&node_id) {
                    concealed.insert(node_id, inputs.clone());
                    None
                } else {
                    Some((transition.clone(), inputs.clone()))
                }
            }))
            .expect("same size");
        let count = concealed.len();
        self.concealed.extend(concealed).expect("todo: issue #141");
        count
    }
}
