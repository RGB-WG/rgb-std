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

use std::path::{Path, PathBuf};

use amplify::confinement::U32;
use strict_encoding::{DeserializeError, SerializeError, StrictDeserialize, StrictSerialize};

use crate::persistence::{MemIndex, MemStash, MemState, Stock};

impl Stock {
    pub fn load(dir: impl Into<PathBuf>) -> Result<Self, DeserializeError> {
        let mut file = dir.into();
        file.push("stash.dat");
        let stash = MemStash::load(&file)?;

        file.pop();
        file.push("state.dat");
        let state = MemState::load(&file)?;

        file.pop();
        file.push("index.dat");
        let index = MemIndex::load(&file)?;

        Ok(Stock::with(stash, state, index))
    }

    pub fn store(&self, dir: impl Into<PathBuf>) -> Result<(), SerializeError> {
        let mut file = dir.into();
        file.push("stash.dat");
        self.as_stash_provider().store(&file)?;

        file.pop();
        file.push("state.dat");
        self.as_state_provider().store(&file)?;

        file.pop();
        file.push("index.dat");
        self.as_index_provider().store(&file)?;

        Ok(())
    }
}

impl MemStash {
    pub fn load(file: impl AsRef<Path>) -> Result<Self, DeserializeError> {
        Self::strict_deserialize_from_file::<U32>(file)
    }

    pub fn store(&self, file: impl AsRef<Path>) -> Result<(), SerializeError> {
        self.strict_serialize_to_file::<U32>(file)
    }
}

impl MemState {
    pub fn load(file: impl AsRef<Path>) -> Result<Self, DeserializeError> {
        Self::strict_deserialize_from_file::<U32>(file)
    }

    pub fn store(&self, file: impl AsRef<Path>) -> Result<(), SerializeError> {
        self.strict_serialize_to_file::<U32>(file)
    }
}

impl MemIndex {
    pub fn load(file: impl AsRef<Path>) -> Result<Self, DeserializeError> {
        Self::strict_deserialize_from_file::<U32>(file)
    }

    pub fn store(&self, file: impl AsRef<Path>) -> Result<(), SerializeError> {
        self.strict_serialize_to_file::<U32>(file)
    }
}
