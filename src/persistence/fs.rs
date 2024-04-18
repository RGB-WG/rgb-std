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

use std::path::Path;

use amplify::confinement::U32;
use strict_encoding::{DeserializeError, SerializeError, StrictDeserialize, StrictSerialize};

use crate::persistence::{
    IndexProvider, MemIndex, MemStash, MemState, StashProvider, StateProvider, Stock,
};

pub trait LoadFs: Sized {
    fn load(path: impl AsRef<Path>) -> Result<Self, DeserializeError>;
}

pub trait StoreFs {
    fn store(&self, path: impl AsRef<Path>) -> Result<(), SerializeError>;
}

impl<S: StashProvider, H: StateProvider, I: IndexProvider> LoadFs for Stock<S, H, I>
where
    S: LoadFs,
    H: LoadFs,
    I: LoadFs,
{
    fn load(path: impl AsRef<Path>) -> Result<Self, DeserializeError> {
        let path = path.as_ref();
        let stash = S::load(path)?;
        let state = H::load(path)?;
        let index = I::load(path)?;

        Ok(Stock::with(stash, state, index))
    }
}

impl<S: StashProvider, H: StateProvider, I: IndexProvider> StoreFs for Stock<S, H, I>
where
    S: StoreFs,
    H: StoreFs,
    I: StoreFs,
{
    fn store(&self, path: impl AsRef<Path>) -> Result<(), SerializeError> {
        let path = path.as_ref();
        self.as_stash_provider().store(path)?;
        self.as_state_provider().store(path)?;
        self.as_index_provider().store(path)?;

        Ok(())
    }
}

impl LoadFs for MemStash {
    fn load(path: impl AsRef<Path>) -> Result<Self, DeserializeError> {
        let mut file = path.as_ref().to_owned();
        file.push("stash.dat");
        Self::strict_deserialize_from_file::<U32>(file)
    }
}

impl StoreFs for MemStash {
    fn store(&self, path: impl AsRef<Path>) -> Result<(), SerializeError> {
        let mut file = path.as_ref().to_owned();
        file.push("stash.dat");
        self.strict_serialize_to_file::<U32>(file)
    }
}

impl LoadFs for MemState {
    fn load(path: impl AsRef<Path>) -> Result<Self, DeserializeError> {
        let mut file = path.as_ref().to_owned();
        file.push("state.dat");
        Self::strict_deserialize_from_file::<U32>(file)
    }
}

impl StoreFs for MemState {
    fn store(&self, path: impl AsRef<Path>) -> Result<(), SerializeError> {
        let mut file = path.as_ref().to_owned();
        file.push("state.dat");
        self.strict_serialize_to_file::<U32>(file)
    }
}

impl LoadFs for MemIndex {
    fn load(path: impl AsRef<Path>) -> Result<Self, DeserializeError> {
        let mut file = path.as_ref().to_owned();
        file.push("index.dat");
        Self::strict_deserialize_from_file::<U32>(file)
    }
}

impl StoreFs for MemIndex {
    fn store(&self, path: impl AsRef<Path>) -> Result<(), SerializeError> {
        let mut file = path.as_ref().to_owned();
        file.push("index.dat");
        self.strict_serialize_to_file::<U32>(file)
    }
}
