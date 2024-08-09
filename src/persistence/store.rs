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

#[derive(Debug, Display, Error)]
#[display(inner)]
pub struct StoreError(pub Box<dyn Error + Send>);

impl From<confinement::Error> for StoreError {
    fn from(err: confinement::Error) -> Self { Self(Box::new(err)) }
}

pub trait StoreProvider: Send + Debug {
    type Object;

    fn load(&self) -> Result<Self::Object, StoreError>;
    fn store(&self, object: &Self::Object) -> Result<(), StoreError>;
}

pub trait Stored: Sized {
    fn new_stored(provider: impl StoreProvider<Object = Self> + 'static, autosave: bool) -> Self;
    fn load(
        provider: impl StoreProvider<Object = Self> + 'static,
        autosave: bool,
    ) -> Result<Self, StoreError>;

    fn is_dirty(&self) -> bool;
    fn autosave(&mut self);
    fn make_stored(&mut self, provider: impl StoreProvider<Object = Self> + 'static) -> bool;

    fn store(&self) -> Result<(), StoreError>;
}
