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

use core::fmt::Debug;

use amplify::confinement::SmallOrdMap;
use amplify::Bytes32;
use aora::Aora;
use hypersonic::Opid;
use rgb::{ClientSideWitness, RgbSeal};
use single_use_seals::{PublishedWitness, SealWitness};

use crate::LIB_NAME_RGB_STD;

pub trait Index<K, V> {
    fn keys(&self) -> impl Iterator<Item = K>;
    fn has(&self, key: K) -> bool;
    fn get(&self, key: K) -> impl ExactSizeIterator<Item = V>;
    fn add(&mut self, key: K, val: V);
}

pub trait Cru<K, V> {
    fn has(&self, key: &K) -> bool;
    fn read(&self, key: &K) -> V;
    fn create(&mut self, key: K, val: V);
    fn create_if_absent(&mut self, key: K, val: V) {
        if !self.has(&key) {
            self.create(key, val);
        }
    }
    fn update(&mut self, key: K, val: V);

    fn begin_transaction(&mut self);
    fn commit_transaction(&mut self) -> u64;
    fn transaction_keys(&self, no: u64) -> impl ExactSizeIterator<Item = K>;
    fn last_transaction_no(&self) -> u64;
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display("{mining_height}, {mining_id}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct WitnessStatus {
    pub mining_height: u64,
    pub mining_id: Bytes32,
}

pub trait Pile {
    type Seal: RgbSeal;

    type Hoard: Aora<
        Id = <Self::Seal as RgbSeal>::WitnessId,
        Item = <Self::Seal as RgbSeal>::Client,
    >;
    type Cache: Aora<
        Id = <Self::Seal as RgbSeal>::WitnessId,
        Item = <Self::Seal as RgbSeal>::Published,
    >;
    type Keep: Aora<Id = Opid, Item = SmallOrdMap<u16, <Self::Seal as RgbSeal>::Definiton>>;
    type Index: Index<Opid, <Self::Seal as RgbSeal>::WitnessId>;
    type Stand: Index<<Self::Seal as RgbSeal>::WitnessId, Opid>;
    type Mine: Cru<<Self::Seal as RgbSeal>::WitnessId, Option<WitnessStatus>>;

    fn hoard(&self) -> &Self::Hoard;
    fn cache(&self) -> &Self::Cache;
    fn keep(&self) -> &Self::Keep;
    fn index(&self) -> &Self::Index;
    fn stand(&self) -> &Self::Stand;
    fn mine(&self) -> &Self::Mine;

    fn hoard_mut(&mut self) -> &mut Self::Hoard;
    fn cache_mut(&mut self) -> &mut Self::Cache;
    fn keep_mut(&mut self) -> &mut Self::Keep;
    fn index_mut(&mut self) -> &mut Self::Index;
    fn stand_mut(&mut self) -> &mut Self::Stand;
    fn mine_mut(&mut self) -> &mut Self::Mine;

    fn retrieve(&mut self, opid: Opid) -> impl ExactSizeIterator<Item = SealWitness<Self::Seal>>;

    fn append(
        &mut self,
        opid: Opid,
        anchor: <Self::Seal as RgbSeal>::Client,
        published: &<Self::Seal as RgbSeal>::Published,
    ) {
        let pubid = published.pub_id();
        self.index_mut().add(opid, pubid);
        self.stand_mut().add(pubid, opid);
        if self.hoard_mut().has(&pubid) {
            let mut prev_anchor = self.hoard_mut().read(pubid);
            if prev_anchor != anchor {
                prev_anchor.merge(anchor).expect(
                    "existing anchor is not compatible with new one; this indicates either bug in \
                     RGB standard library or a compromised storage",
                );
                self.hoard_mut().append(pubid, &prev_anchor);
            }
        } else {
            self.hoard_mut().append(pubid, &anchor);
        }
        self.mine_mut().create_if_absent(pubid, None);
        self.cache_mut().append(pubid, published);
    }

    /// Get mining status for a given operation.
    fn since(&self, opid: Opid) -> Option<u64> {
        self.index()
            .get(opid)
            .map(|pubid| self.mine().read(&pubid).map(|status| status.mining_height))
            .max()
            .flatten()
    }
}

#[cfg(feature = "fs")]
pub mod fs {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::marker::PhantomData;
    use std::path::{Path, PathBuf};
    use std::{io, iter};

    use aora::file::FileAora;
    use strict_encoding::{StrictDecode, StrictEncode};

    use super::*;

    #[derive(Clone, Debug)]
    pub struct FileCru {
        path: PathBuf,
        // TODO: Add cache
    }

    impl FileCru {
        pub fn create(path: PathBuf) -> io::Result<Self> {
            File::create_new(&path)?;
            Ok(Self { path })
        }

        pub fn open(path: PathBuf) -> io::Result<Self> { Ok(Self { path }) }
    }

    /// Create-Read-Update database (with no delete operation).
    impl<K, V> Cru<K, V> for FileCru {
        fn has(&self, key: &K) -> bool { todo!() }

        fn read(&self, key: &K) -> V { todo!() }

        fn create(&mut self, key: K, val: V) { todo!() }

        fn update(&mut self, key: K, val: V) { todo!() }

        fn begin_transaction(&mut self) { todo!() }

        fn commit_transaction(&mut self) -> u64 { todo!() }

        fn transaction_keys(&self, no: u64) -> impl ExactSizeIterator<Item = K> {
            todo!();
            iter::empty()
        }

        fn last_transaction_no(&self) -> u64 { todo!() }
    }

    #[derive(Clone, Debug)]
    pub struct FileIndex<K, V>
    where
        K: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>,
        V: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        path: PathBuf,
        cache: BTreeMap<K, BTreeSet<V>>,
    }

    impl<K, V> FileIndex<K, V>
    where
        K: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>,
        V: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        pub fn create(path: PathBuf) -> io::Result<Self> {
            File::create_new(&path)?;
            Ok(Self { cache: none!(), path })
        }

        pub fn open(path: PathBuf) -> io::Result<Self> {
            let mut cache = BTreeMap::new();
            let mut file = File::open(&path)?;
            let mut buf = [0u8; 32];
            while file.read_exact(&mut buf).is_ok() {
                let opid = K::from(buf);
                let mut ids = BTreeSet::new();
                let mut len = [0u8; 4];
                file.read_exact(&mut len).expect("cannot read index file");
                let mut len = u32::from_le_bytes(len);
                while len > 0 {
                    file.read_exact(&mut buf).expect("cannot read index file");
                    let res = ids.insert(buf.into());
                    debug_assert!(res, "duplicate id in index file");
                    len -= 1;
                }
                cache.insert(opid, ids);
            }
            Ok(Self { path, cache })
        }

        pub fn save(&self) -> io::Result<()> {
            let mut index_file = File::create(&self.path)?;
            for (key, values) in &self.cache {
                index_file.write_all((*key).into().as_slice())?;
                let len = values.len() as u32;
                index_file.write_all(&len.to_le_bytes())?;
                for id in values {
                    index_file.write_all(&(*id).into())?;
                }
            }
            Ok(())
        }
    }

    impl<K, V> Index<K, V> for FileIndex<K, V>
    where
        K: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>,
        V: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        fn keys(&self) -> impl Iterator<Item = K> { self.cache.keys().copied() }

        fn has(&self, key: K) -> bool { self.cache.contains_key(&key) }

        fn get(&self, key: K) -> impl ExactSizeIterator<Item = V> {
            match self.cache.get(&key) {
                Some(ids) => ids.clone().into_iter(),
                None => bset![].into_iter(),
            }
        }

        fn add(&mut self, key: K, val: V) {
            self.cache.entry(key).or_default().insert(val);
            self.save().expect("Cannot save index file");
        }
    }

    pub struct FilePile<Seal: RgbSeal>
    where Seal::WitnessId: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        hoard: FileAora<Seal::WitnessId, Seal::Client>,
        cache: FileAora<Seal::WitnessId, Seal::Published>,
        keep: FileAora<Opid, SmallOrdMap<u16, Seal::Definiton>>,
        index: FileIndex<Opid, Seal::WitnessId>,
        stand: FileIndex<Seal::WitnessId, Opid>,
        mine: FileCru,
        _phantom: PhantomData<Seal>,
    }

    impl<Seal: RgbSeal> FilePile<Seal>
    where Seal::WitnessId: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        pub fn new(name: &str, path: impl AsRef<Path>) -> Self {
            let mut path = path.as_ref().to_path_buf();
            path.push(name);
            path.set_extension("contract");

            let hoard = FileAora::new(&path, "hoard");
            let cache = FileAora::new(&path, "cache");
            let keep = FileAora::new(&path, "keep");

            let index_file = path.join("index.dat");
            let index = FileIndex::create(index_file.clone()).unwrap_or_else(|_| {
                panic!("unable to create index file '{}'", index_file.display())
            });
            let stand_file = path.join("stand.dat");
            let stand = FileIndex::create(stand_file.clone()).unwrap_or_else(|_| {
                panic!("unable to create stand file '{}'", stand_file.display())
            });
            let mine_file = path.join("mine.dat");
            let mine = FileCru::create(mine_file.clone()).unwrap_or_else(|_| {
                panic!("unable to create mining info file '{}'", mine_file.display())
            });

            Self {
                hoard,
                cache,
                keep,
                index,
                stand,
                mine,
                _phantom: PhantomData,
            }
        }
    }

    impl<Seal: RgbSeal> FilePile<Seal>
    where Seal::WitnessId: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        pub fn open(path: impl AsRef<Path>) -> Self {
            let path = path.as_ref().to_path_buf();
            let hoard = FileAora::open(&path, "hoard");
            let cache = FileAora::open(&path, "cache");
            let keep = FileAora::open(&path, "keep");

            let index_file = path.join("index.dat");
            let index = FileIndex::open(index_file.clone())
                .unwrap_or_else(|_| panic!("unable to open index file '{}'", index_file.display()));
            let stand_file = path.join("stand.dat");
            let stand = FileIndex::open(stand_file.clone())
                .unwrap_or_else(|_| panic!("unable to open stand file '{}'", stand_file.display()));
            let mine_file = path.join("mine.dat");
            let mine = FileCru::open(mine_file.clone()).unwrap_or_else(|_| {
                panic!("unable to open mining info file '{}'", mine_file.display())
            });

            Self {
                hoard,
                cache,
                keep,
                index,
                stand,
                mine,
                _phantom: PhantomData,
            }
        }
    }

    impl<Seal: RgbSeal> Pile for FilePile<Seal>
    where
        Seal::Client: StrictEncode + StrictDecode,
        Seal::Published: Eq + StrictEncode + StrictDecode,
        Seal::WitnessId: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        type Seal = Seal;

        type Hoard = FileAora<Seal::WitnessId, Seal::Client>;
        type Cache = FileAora<Seal::WitnessId, Seal::Published>;
        type Keep = FileAora<Opid, SmallOrdMap<u16, Seal::Definiton>>;
        type Index = FileIndex<Opid, Seal::WitnessId>;
        type Stand = FileIndex<Seal::WitnessId, Opid>;
        type Mine = FileCru;

        fn hoard(&self) -> &Self::Hoard { &self.hoard }

        fn cache(&self) -> &Self::Cache { &self.cache }

        fn keep(&self) -> &Self::Keep { &self.keep }

        fn index(&self) -> &Self::Index { &self.index }

        fn stand(&self) -> &Self::Stand { &self.stand }

        fn mine(&self) -> &Self::Mine { &self.mine }

        fn hoard_mut(&mut self) -> &mut Self::Hoard { &mut self.hoard }

        fn cache_mut(&mut self) -> &mut Self::Cache { &mut self.cache }

        fn keep_mut(&mut self) -> &mut Self::Keep { &mut self.keep }

        fn index_mut(&mut self) -> &mut Self::Index { &mut self.index }

        fn stand_mut(&mut self) -> &mut Self::Stand { &mut self.stand }

        fn mine_mut(&mut self) -> &mut Self::Mine { &mut self.mine }

        fn retrieve(&mut self, opid: Opid) -> impl ExactSizeIterator<Item = SealWitness<Seal>> {
            self.index.get(opid).map(|pubid| {
                let client = self.hoard.read(pubid);
                let published = self.cache.read(pubid);
                SealWitness::new(published, client)
            })
        }
    }
}
