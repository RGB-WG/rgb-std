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

use std::error::Error;
use std::fmt::Debug;

use amplify::confinement;
use strict_encoding::{DeserializeError, SerializeError};

use crate::persistence::{IndexProvider, StashProvider, StateProvider, Stock};

#[derive(Debug, Display, Error)]
#[display(inner)]
pub struct StoreError(pub Box<dyn Error + Send>);

impl From<confinement::Error> for StoreError {
    fn from(err: confinement::Error) -> Self { Self(Box::new(err)) }
}

impl From<SerializeError> for StoreError {
    fn from(err: SerializeError) -> Self { Self(Box::new(err)) }
}

impl From<DeserializeError> for StoreError {
    fn from(err: DeserializeError) -> Self { Self(Box::new(err)) }
}

pub trait StockStoreProvider<S: StashProvider, H: StateProvider, I: IndexProvider>:
    StoreProvider<Stock<S, H, I>>
{
    fn make_stored(&self, stock: &mut Stock<S, H, I>) -> bool;
}

pub trait StoreProvider<T>: Send + Debug {
    fn load(&self) -> Result<T, StoreError>;
    fn store(&self, object: &T) -> Result<(), StoreError>;
}

pub trait Stored: Sized {
    fn new_stored(provider: impl StoreProvider<Self> + 'static, autosave: bool) -> Self;
    fn load(
        provider: impl StoreProvider<Self> + 'static,
        autosave: bool,
    ) -> Result<Self, StoreError>;

    fn is_dirty(&self) -> bool;
    fn autosave(&mut self);
    fn make_stored(&mut self, provider: impl StoreProvider<Self> + 'static) -> bool;

    fn store(&self) -> Result<(), StoreError>;
}

#[cfg(feature = "fs")]
mod fs {
    use std::path::PathBuf;

    use amplify::confinement::U32 as U32MAX;
    use strict_encoding::{StrictDeserialize, StrictSerialize};

    use super::*;
    use crate::persistence::{MemIndex, MemStash, MemState, Stock, Stored};

    impl StoreProvider<MemStash> for PathBuf {
        fn load(&self) -> Result<MemStash, StoreError> {
            Ok(MemStash::strict_deserialize_from_file::<U32MAX>(&self)?)
        }

        fn store(&self, object: &MemStash) -> Result<(), StoreError> {
            object.strict_serialize_to_file::<U32MAX>(&self)?;
            Ok(())
        }
    }

    impl StoreProvider<MemState> for PathBuf {
        fn load(&self) -> Result<MemState, StoreError> {
            Ok(MemState::strict_deserialize_from_file::<U32MAX>(&self)?)
        }

        fn store(&self, object: &MemState) -> Result<(), StoreError> {
            object.strict_serialize_to_file::<U32MAX>(&self)?;
            Ok(())
        }
    }

    impl StoreProvider<MemIndex> for PathBuf {
        fn load(&self) -> Result<MemIndex, StoreError> {
            Ok(MemIndex::strict_deserialize_from_file::<U32MAX>(&self)?)
        }

        fn store(&self, object: &MemIndex) -> Result<(), StoreError> {
            object.strict_serialize_to_file::<U32MAX>(&self)?;
            Ok(())
        }
    }

    impl StoreProvider<Stock> for PathBuf {
        fn load(&self) -> Result<Stock, StoreError> {
            let mut filename = self.to_owned();
            filename.push("stash.dat");
            let stash: MemStash = filename.load()?;

            let mut filename = self.to_owned();
            filename.push("state.dat");
            let state: MemState = filename.load()?;

            let mut filename = self.to_owned();
            filename.push("index.dat");
            let index: MemIndex = filename.load()?;

            Ok(Stock::with(stash, state, index))
        }

        fn store(&self, stock: &Stock) -> Result<(), StoreError> {
            // TODO: Revert files on failure

            let mut filename = self.to_owned();
            filename.push("stash.dat");
            filename.store(stock.as_stash_provider())?;

            let mut filename = self.to_owned();
            filename.push("state.dat");
            filename.store(stock.as_state_provider())?;

            let mut filename = self.to_owned();
            filename.push("index.dat");
            filename.store(stock.as_index_provider())?;

            Ok(())
        }
    }

    impl StockStoreProvider<MemStash, MemState, MemIndex> for PathBuf {
        fn make_stored(&self, stock: &mut Stock<MemStash, MemState, MemIndex>) -> bool {
            let mut filename = self.to_owned();
            filename.push("stash.dat");
            let _1 = stock.as_stash_provider_mut().make_stored(filename);

            let mut filename = self.to_owned();
            filename.push("state.dat");
            let _2 = stock.as_state_provider_mut().make_stored(filename);

            let mut filename = self.to_owned();
            filename.push("index.dat");
            let _3 = stock.as_index_provider_mut().make_stored(filename);

            assert_eq!(_1, _2);
            assert_eq!(_2, _3);
            _1
        }
    }
}
