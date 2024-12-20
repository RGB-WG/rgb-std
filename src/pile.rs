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

use amplify::confinement::SmallVec;
use hypersonic::aora::Aora;
use hypersonic::Opid;
use rgb::SonicSeal;
use single_use_seals::{PublishedWitness, SealWitness, SingleUseSeal};

pub trait Index<K, V> {
    fn get(&self, key: K) -> impl ExactSizeIterator<Item = V>;
    fn add(&mut self, key: K, val: V);
}

pub trait Pile {
    type Seal: SonicSeal;
    type Hoard: Aora<
        Id = <<Self::Seal as SingleUseSeal>::PubWitness as PublishedWitness<Self::Seal>>::PubId,
        Item = <Self::Seal as SingleUseSeal>::CliWitness,
    >;
    type Cache: Aora<
        Id = <<Self::Seal as SingleUseSeal>::PubWitness as PublishedWitness<Self::Seal>>::PubId,
        Item = <Self::Seal as SingleUseSeal>::PubWitness,
    >;
    type Keep: Aora<Id = Opid, Item = SmallVec<Self::Seal>>;
    type Index: Index<
        Opid,
        <<Self::Seal as SingleUseSeal>::PubWitness as PublishedWitness<Self::Seal>>::PubId,
    >;

    fn hoard(&self) -> &Self::Hoard;
    fn cache(&self) -> &Self::Cache;
    fn keep(&self) -> &Self::Keep;
    fn index(&self) -> &Self::Index;

    fn hoard_mut(&mut self) -> &mut Self::Hoard;
    fn cache_mut(&mut self) -> &mut Self::Cache;
    fn keep_mut(&mut self) -> &mut Self::Keep;
    fn index_mut(&mut self) -> &mut Self::Index;

    fn retrieve(&mut self, opid: Opid) -> impl ExactSizeIterator<Item = SealWitness<Self::Seal>>;

    fn append(&mut self, opid: Opid, witness: &SealWitness<Self::Seal>) {
        let pubid = witness.published.pub_id();
        self.index_mut().add(opid, pubid);
        self.hoard_mut().append(pubid, &witness.client);
        self.cache_mut().append(pubid, &witness.published);
    }
}

#[cfg(feature = "fs")]
pub mod fs {
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    use hypersonic::aora::file::FileAora;
    use hypersonic::expect::Expect;
    use strict_encoding::{StrictDecode, StrictEncode};

    use super::*;

    #[derive(Clone, Debug, From)]
    pub struct MemIndex<Id>(BTreeMap<Opid, Vec<Id>>);
    impl<Id> Default for MemIndex<Id> {
        fn default() -> Self { Self(none!()) }
    }

    impl<V: Copy> Index<Opid, V> for MemIndex<V> {
        fn get(&self, key: Opid) -> impl ExactSizeIterator<Item = V> {
            self.0
                .get(&key)
                .expect("unknown operation ID requested from the index")
                .iter()
                .copied()
        }

        fn add(&mut self, key: Opid, val: V) { self.0.entry(key).or_default().push(val) }
    }

    pub struct FilePile<Seal: SonicSeal>
    where <Seal::PubWitness as PublishedWitness<Seal>>::PubId: Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        hoard: FileAora<<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Seal::CliWitness>,
        cache: FileAora<<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Seal::PubWitness>,
        keep: FileAora<Opid, SmallVec<Seal>>,
        index: MemIndex<<<Seal as SingleUseSeal>::PubWitness as PublishedWitness<Seal>>::PubId>,
    }

    impl<Seal: SonicSeal> FilePile<Seal>
    where <Seal::PubWitness as PublishedWitness<Seal>>::PubId: Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        pub fn new(name: &str, path: impl AsRef<Path>) -> Self {
            let mut path = path.as_ref().to_path_buf();
            path.push(name);
            path.set_extension("contract");

            let hoard = FileAora::new(&path, "hoard");
            let cache = FileAora::new(&path, "cache");
            let keep = FileAora::new(&path, "keep");
            File::create_new(path.join("index.dat"))
                .expect_or_else(|| format!("unable to create index file `{}`", path.display()));

            Self { hoard, cache, keep, index: empty!() }
        }
    }

    impl<Seal: SonicSeal> FilePile<Seal>
    where <Seal::PubWitness as PublishedWitness<Seal>>::PubId: Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        pub fn open(path: impl AsRef<Path>) -> Self {
            let path = path.as_ref().to_path_buf();
            let hoard = FileAora::open(&path, "hoard");
            let cache = FileAora::open(&path, "cache");
            let keep = FileAora::open(&path, "keep");

            let mut index = BTreeMap::new();
            let index_name = path.join("index.dat");
            let mut index_file = File::open(&index_name)
                .expect_or_else(|| format!("unable to open index file `{}`", index_name.display()));
            let mut buf = [0u8; 32];
            while index_file.read_exact(&mut buf).is_ok() {
                let opid = Opid::from(buf);
                let mut ids = Vec::new();
                let mut len = [0u8; 4];
                index_file
                    .read_exact(&mut len)
                    .expect("cannot read index file");
                let mut len = u32::from_le_bytes(len);
                while len > 0 {
                    index_file
                        .read_exact(&mut buf)
                        .expect("cannot read index file");
                    ids.push(buf.into());
                    len -= 1;
                }
                index.insert(opid, ids);
            }

            Self { hoard, cache, keep, index: index.into() }
        }
    }

    impl<Seal: SonicSeal> Pile for FilePile<Seal>
    where
        Seal::CliWitness: StrictEncode + StrictDecode,
        Seal::PubWitness: StrictEncode + StrictDecode,
        <Seal::PubWitness as PublishedWitness<Seal>>::PubId: Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        type Seal = Seal;
        type Hoard =
            FileAora<<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Seal::CliWitness>;
        type Cache =
            FileAora<<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Seal::PubWitness>;
        type Keep = FileAora<Opid, SmallVec<Seal>>;
        type Index =
            MemIndex<<<Seal as SingleUseSeal>::PubWitness as PublishedWitness<Seal>>::PubId>;

        fn hoard(&self) -> &Self::Hoard { &self.hoard }

        fn cache(&self) -> &Self::Cache { &self.cache }

        fn keep(&self) -> &Self::Keep { &self.keep }

        fn index(&self) -> &Self::Index { &self.index }

        fn hoard_mut(&mut self) -> &mut Self::Hoard { &mut self.hoard }

        fn cache_mut(&mut self) -> &mut Self::Cache { &mut self.cache }

        fn keep_mut(&mut self) -> &mut Self::Keep { &mut self.keep }

        fn index_mut(&mut self) -> &mut Self::Index { &mut self.index }

        fn retrieve(&mut self, opid: Opid) -> impl ExactSizeIterator<Item = SealWitness<Seal>> {
            self.index.get(opid).map(|pubid| {
                let client = self.hoard.read(pubid);
                let published = self.cache.read(pubid);
                SealWitness::new(published, client)
            })
        }
    }
}
