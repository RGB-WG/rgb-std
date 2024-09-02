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

use std::path::PathBuf;
use std::{fs, io};

use amplify::confinement::U32 as U32MAX;
use nonasync::persistence::{PersistenceError, PersistenceProvider};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::persistence::{MemIndex, MemStash, MemState};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct FsBinStore {
    pub stash: PathBuf,
    pub state: PathBuf,
    pub index: PathBuf,
}

impl FsBinStore {
    pub fn new(path: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&path)?;

        let mut stash = path.clone();
        stash.push("stash.dat");
        let mut state = path.clone();
        state.push("state.dat");
        let mut index = path.clone();
        index.push("index.dat");

        Ok(Self {
            stash,
            state,
            index,
        })
    }
}
impl PersistenceProvider<MemStash> for FsBinStore {
    fn load(&self) -> Result<MemStash, PersistenceError> {
        MemStash::strict_deserialize_from_file::<U32MAX>(&self.stash)
            .map_err(PersistenceError::with)
    }

    fn store(&self, object: &MemStash) -> Result<(), PersistenceError> {
        object
            .strict_serialize_to_file::<U32MAX>(&self.stash)
            .map_err(PersistenceError::with)
    }
}

impl PersistenceProvider<MemState> for FsBinStore {
    fn load(&self) -> Result<MemState, PersistenceError> {
        MemState::strict_deserialize_from_file::<U32MAX>(&self.state)
            .map_err(PersistenceError::with)
    }

    fn store(&self, object: &MemState) -> Result<(), PersistenceError> {
        object
            .strict_serialize_to_file::<U32MAX>(&self.state)
            .map_err(PersistenceError::with)
    }
}

impl PersistenceProvider<MemIndex> for FsBinStore {
    fn load(&self) -> Result<MemIndex, PersistenceError> {
        MemIndex::strict_deserialize_from_file::<U32MAX>(&self.index)
            .map_err(PersistenceError::with)
    }

    fn store(&self, object: &MemIndex) -> Result<(), PersistenceError> {
        object
            .strict_serialize_to_file::<U32MAX>(&self.index)
            .map_err(PersistenceError::with)
    }
}
