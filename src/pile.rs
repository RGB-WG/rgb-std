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

use core::fmt::{Debug, Display};

use amplify::confinement::SmallOrdMap;
use amplify::Bytes32;
use aora::Aora;
use hypersonic::Opid;
use rgb::{ClientSideWitness, RgbSealDef, RgbSealSrc};
use single_use_seals::{PublishedWitness, SealWitness};

use crate::LIB_NAME_RGB_STD;

pub trait Index<K, V> {
    fn keys(&self) -> impl Iterator<Item = K>;
    fn has(&self, key: K) -> bool;
    fn get(&self, key: K) -> impl ExactSizeIterator<Item = V>;
    fn add(&mut self, key: K, val: V);
}

pub trait Cru<K, V> {
    fn has(&self, key: K) -> bool;
    fn read(&self, key: K) -> Option<V>;
    fn create(&mut self, key: K, val: V);
    fn update(&mut self, key: K, val: V);
}

pub trait Seal: RgbSealSrc<PubWitness = Self::Published, CliWitness = Self::Client> {
    type Definiton: RgbSealDef<Src = Self>;
    type Published: PublishedWitness<Self, PubId = Self::WitnessId>;
    type Client: ClientSideWitness;
    type WitnessId: Copy + Ord + Debug + Display;
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display("{mining_height}, {mining_id}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct WitnessStatus {
    pub mining_height: u32,
    pub mining_id: Bytes32,
}

pub trait Pile {
    type Seal: Seal;

    type Hoard: Aora<Id = <Self::Seal as Seal>::WitnessId, Item = <Self::Seal as Seal>::Client>;
    type Cache: Aora<Id = <Self::Seal as Seal>::WitnessId, Item = <Self::Seal as Seal>::Published>;
    type Keep: Aora<Id = Opid, Item = SmallOrdMap<u16, <Self::Seal as Seal>::Definiton>>;
    type Index: Index<Opid, <Self::Seal as Seal>::WitnessId>;
    type Mine: Cru<<Self::Seal as Seal>::WitnessId, WitnessStatus>;

    fn hoard(&self) -> &Self::Hoard;
    fn cache(&self) -> &Self::Cache;
    fn keep(&self) -> &Self::Keep;
    fn index(&self) -> &Self::Index;

    fn hoard_mut(&mut self) -> &mut Self::Hoard;
    fn cache_mut(&mut self) -> &mut Self::Cache;
    fn keep_mut(&mut self) -> &mut Self::Keep;
    fn index_mut(&mut self) -> &mut Self::Index;

    fn retrieve(&mut self, opid: Opid) -> impl ExactSizeIterator<Item = SealWitness<Self::Seal>>;

    fn append(
        &mut self,
        opid: Opid,
        anchor: <Self::Seal as Seal>::Client,
        published: &<Self::Seal as Seal>::Published,
    ) {
        let pubid = published.pub_id();
        self.index_mut().add(opid, pubid);
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
        self.cache_mut().append(pubid, published);
    }
}

#[cfg(feature = "fs")]
pub mod fs {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::File;
    use std::io;
    use std::io::{Read, Write};
    use std::marker::PhantomData;
    use std::path::{Path, PathBuf};

    use aora::file::FileAora;
    use strict_encoding::{StrictDecode, StrictEncode};

    use super::*;

    pub struct FileCru;

    impl<K, V> Cru<K, V> for FileCru {
        fn has(&self, key: K) -> bool { todo!() }

        fn read(&self, key: K) -> Option<V> { todo!() }

        fn create(&mut self, key: K, val: V) { todo!() }

        fn update(&mut self, key: K, val: V) { todo!() }
    }

    #[derive(Clone, Debug, From)]
    pub struct FileIndex<Id>
    where Id: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        path: PathBuf,
        cache: BTreeMap<Opid, BTreeSet<Id>>,
    }

    impl<Id> FileIndex<Id>
    where Id: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        pub fn create(path: PathBuf) -> io::Result<Self> {
            File::create_new(&path)?;
            Ok(Self { cache: none!(), path })
        }

        pub fn new(path: PathBuf) -> io::Result<Self> {
            let mut cache = BTreeMap::new();
            let mut index_file = File::open(&path)?;
            let mut buf = [0u8; 32];
            while index_file.read_exact(&mut buf).is_ok() {
                let opid = Opid::from(buf);
                let mut ids = BTreeSet::new();
                let mut len = [0u8; 4];
                index_file
                    .read_exact(&mut len)
                    .expect("cannot read index file");
                let mut len = u32::from_le_bytes(len);
                while len > 0 {
                    index_file
                        .read_exact(&mut buf)
                        .expect("cannot read index file");
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
            for (opid, ids) in &self.cache {
                index_file.write_all(opid.as_slice())?;
                let len = ids.len() as u32;
                index_file.write_all(&len.to_le_bytes())?;
                for id in ids {
                    index_file.write_all(&(*id).into())?;
                }
            }
            Ok(())
        }
    }

    impl<Id: Copy> Index<Opid, Id> for FileIndex<Id>
    where Id: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        fn keys(&self) -> impl Iterator<Item = Opid> { self.cache.keys().copied() }

        fn has(&self, key: Opid) -> bool { self.cache.contains_key(&key) }

        fn get(&self, key: Opid) -> impl ExactSizeIterator<Item = Id> {
            match self.cache.get(&key) {
                Some(ids) => ids.clone().into_iter(),
                None => bset![].into_iter(),
            }
        }

        fn add(&mut self, key: Opid, val: Id) {
            self.cache.entry(key).or_default().insert(val);
            self.save().expect("Cannot save index file");
        }
    }

    pub struct FilePile<SealSrc: Seal>
    where SealSrc::WitnessId: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        hoard: FileAora<SealSrc::WitnessId, SealSrc::Client>,
        cache: FileAora<SealSrc::WitnessId, SealSrc::Published>,
        keep: FileAora<Opid, SmallOrdMap<u16, SealSrc::Definiton>>,
        index: FileIndex<SealSrc::WitnessId>,
        _phantom: PhantomData<SealSrc>,
    }

    impl<SealSrc: Seal> FilePile<SealSrc>
    where SealSrc::WitnessId: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        pub fn new(name: &str, path: impl AsRef<Path>) -> Self {
            let mut path = path.as_ref().to_path_buf();
            path.push(name);
            path.set_extension("contract");

            let hoard = FileAora::new(&path, "hoard");
            let cache = FileAora::new(&path, "cache");
            let keep = FileAora::new(&path, "keep");
            let index = FileIndex::create(path.join("index.dat"))
                .unwrap_or_else(|_| panic!("unable to create index file `{}`", path.display()));

            Self { hoard, cache, keep, index, _phantom: PhantomData }
        }
    }

    impl<SealSrc: Seal> FilePile<SealSrc>
    where SealSrc::WitnessId: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>
    {
        pub fn open(path: impl AsRef<Path>) -> Self {
            let path = path.as_ref().to_path_buf();
            let hoard = FileAora::open(&path, "hoard");
            let cache = FileAora::open(&path, "cache");
            let keep = FileAora::open(&path, "keep");

            let index_name = path.join("index.dat");
            let index = FileIndex::new(index_name.clone())
                .unwrap_or_else(|_| panic!("unable to open index file `{}`", index_name.display()));

            Self { hoard, cache, keep, index, _phantom: PhantomData }
        }
    }

    impl<SealSrc: Seal> Pile for FilePile<SealSrc>
    where
        SealSrc::Client: StrictEncode + StrictDecode,
        SealSrc::Published: Eq + StrictEncode + StrictDecode,
        SealSrc::WitnessId: Copy + Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        type Seal = SealSrc;

        type Hoard = FileAora<SealSrc::WitnessId, SealSrc::Client>;
        type Cache = FileAora<SealSrc::WitnessId, SealSrc::Published>;
        type Keep = FileAora<Opid, SmallOrdMap<u16, SealSrc::Definiton>>;
        type Index = FileIndex<SealSrc::WitnessId>;
        type Mine = FileCru;

        fn hoard(&self) -> &Self::Hoard { &self.hoard }

        fn cache(&self) -> &Self::Cache { &self.cache }

        fn keep(&self) -> &Self::Keep { &self.keep }

        fn index(&self) -> &Self::Index { &self.index }

        fn hoard_mut(&mut self) -> &mut Self::Hoard { &mut self.hoard }

        fn cache_mut(&mut self) -> &mut Self::Cache { &mut self.cache }

        fn keep_mut(&mut self) -> &mut Self::Keep { &mut self.keep }

        fn index_mut(&mut self) -> &mut Self::Index { &mut self.index }

        fn retrieve(&mut self, opid: Opid) -> impl ExactSizeIterator<Item = SealWitness<SealSrc>> {
            self.index.get(opid).map(|pubid| {
                let client = self.hoard.read(pubid);
                let published = self.cache.read(pubid);
                SealWitness::new(published, client)
            })
        }
    }
}
