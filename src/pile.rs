// Standard Library for RGB smart contracts
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use hypersonic::aora::Aora;
use hypersonic::AuthToken;
use single_use_seals::SingleUseSeal;

pub trait Protocol: SingleUseSeal {
    type Id: Ord + From<[u8; 32]> + Into<[u8; 32]>;
    fn auth_token(&self) -> AuthToken;
}

pub trait Pile {
    type Seal: Protocol;
    type Hoard: Aora<Item = <Self::Seal as SingleUseSeal>::CliWitness>;
    type Cache: Aora<Item = <Self::Seal as SingleUseSeal>::PubWitness>;

    fn hoard(&self) -> &Self::Hoard;
    fn cache(&self) -> &Self::Cache;

    fn hoard_mut(&mut self) -> &mut Self::Hoard;
    fn cache_mut(&mut self) -> &mut Self::Cache;
}

#[cfg(feature = "fs")]
pub mod fs {
    use std::path::{Path, PathBuf};

    use hypersonic::aora::file::FileAora;
    use strict_encoding::{StrictDecode, StrictEncode};

    use super::*;

    pub struct FilePile<Seal: Protocol> {
        path: PathBuf,
        hoard: FileAora<Seal::Id, Seal::CliWitness>,
        cache: FileAora<Seal::Id, Seal::PubWitness>,
    }

    impl<Seal: Protocol> FilePile<Seal> {
        pub fn new(name: &str, path: impl AsRef<Path>) -> Self {
            let mut path = path.as_ref().to_path_buf();
            path.push(name);

            let hoard = FileAora::new(&path, "hoard");
            let cache = FileAora::new(&path, "cache");

            Self { path, hoard, cache }
        }

        pub fn open(path: impl AsRef<Path>) -> Self {
            let path = path.as_ref().to_path_buf();
            let hoard = FileAora::open(&path, "hoard");
            let cache = FileAora::open(&path, "cache");
            Self { path, hoard, cache }
        }
    }

    impl<Seal: Protocol> Pile for FilePile<Seal>
    where
        Seal::CliWitness: StrictEncode + StrictDecode,
        Seal::PubWitness: StrictEncode + StrictDecode,
    {
        type Seal = Seal;
        type Hoard = FileAora<Seal::Id, Seal::CliWitness>;
        type Cache = FileAora<Seal::Id, Seal::PubWitness>;

        fn hoard(&self) -> &Self::Hoard { &self.hoard }

        fn cache(&self) -> &Self::Cache { &self.cache }

        fn hoard_mut(&mut self) -> &mut Self::Hoard { &mut self.hoard }

        fn cache_mut(&mut self) -> &mut Self::Cache { &mut self.cache }
    }
}
