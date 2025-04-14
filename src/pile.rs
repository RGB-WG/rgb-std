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
use aora::{AoraIndex, AoraMap, AuraMap, TransactionalMap};
use hypersonic::Opid;
use rgb::{ClientSideWitness, RgbSeal};
use single_use_seals::{PublishedWitness, SealWitness};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MiningInfo {
    height: u64,
    id: Bytes32,
}

impl Default for MiningInfo {
    fn default() -> Self { Self::unmined() }
}

impl MiningInfo {
    pub fn mined(height: u64, id: Bytes32) -> Self {
        assert_ne!(height, u64::MAX);
        assert_ne!(id, Bytes32::with_fill(0xFF));
        Self { height, id }
    }

    pub fn unmined() -> Self { Self { height: u64::MAX, id: Bytes32::with_fill(0xFF) } }
    pub fn is_mined(&self) -> bool {
        self.height != u64::MAX && self.id != Bytes32::with_fill(0xFF)
    }
    pub fn height(&self) -> Option<u64> {
        if self.is_mined() {
            Some(self.height)
        } else {
            None
        }
    }
    pub fn mining_id(&self) -> Option<Bytes32> {
        if self.is_mined() {
            Some(self.id)
        } else {
            None
        }
    }
}

// We use big-endian encoding in order to allow lexicographic sorting
impl From<[u8; 40]> for MiningInfo {
    fn from(mut value: [u8; 40]) -> Self {
        let mut buf1 = [0u8; 8];
        buf1.copy_from_slice(&value[0..8]);
        let height = u64::from_be_bytes(buf1);

        let mut buf2 = [0u8; 32];
        let rev = &mut value[8..];
        rev.reverse();
        buf2.copy_from_slice(rev);
        let id = Bytes32::from_byte_array(buf2);

        MiningInfo { height, id }
    }
}

// We use big-endian encoding in order to allow lexicographic sorting
impl From<MiningInfo> for [u8; 40] {
    fn from(mut value: MiningInfo) -> Self {
        let mut buf = [0u8; 40];
        buf[..8].copy_from_slice(&value.height.to_be_bytes());

        let rev = value.id.as_slice_mut();
        rev.reverse();
        buf[8..].copy_from_slice(rev);

        buf
    }
}

pub trait Pile
where <Self::Seal as RgbSeal>::WitnessId: From<[u8; 32]> + Into<[u8; 32]>
{
    type Seal: RgbSeal;

    type Hoard: AoraMap<<Self::Seal as RgbSeal>::WitnessId, <Self::Seal as RgbSeal>::Client>;
    type Cache: AoraMap<<Self::Seal as RgbSeal>::WitnessId, <Self::Seal as RgbSeal>::Published>;
    type Keep: AoraMap<Opid, SmallOrdMap<u16, <Self::Seal as RgbSeal>::Definiton>>;
    type Index: AoraIndex<Opid, <Self::Seal as RgbSeal>::WitnessId>;
    type Stand: AoraIndex<<Self::Seal as RgbSeal>::WitnessId, Opid>;
    type Mine: AuraMap<<Self::Seal as RgbSeal>::WitnessId, MiningInfo, 32, 40>
        + TransactionalMap<<Self::Seal as RgbSeal>::WitnessId>;

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
        self.index_mut().push(opid, pubid);
        self.stand_mut().push(pubid, opid);
        if self.hoard_mut().contains_key(pubid) {
            let mut prev_anchor = self.hoard_mut().get_expect(pubid);
            if prev_anchor != anchor {
                prev_anchor.merge(anchor).expect(
                    "existing anchor is not compatible with new one; this indicates either bug in \
                     RGB standard library or a compromised storage",
                );
                self.hoard_mut().insert(pubid, &prev_anchor);
            }
        } else {
            self.hoard_mut().insert(pubid, &anchor);
        }
        self.mine_mut().insert_only(pubid, MiningInfo::unmined());
        self.cache_mut().insert(pubid, published);
    }

    /// Get mining status for a given operation.
    fn since(&self, opid: Opid) -> Option<u64> {
        self.index()
            .get(opid)
            .flat_map(|pubid| self.mine().get_expect(pubid).height())
            .max()
    }
}

#[cfg(feature = "fs")]
pub mod fs {
    use std::marker::PhantomData;
    use std::path::Path;

    use aora::file::{FileAoraIndex, FileAoraMap, FileAuraMap};
    use strict_encoding::{StrictDecode, StrictEncode};

    use super::*;

    pub struct FilePile<Seal: RgbSeal>
    where Seal::WitnessId: From<[u8; 32]> + Into<[u8; 32]>
    {
        hoard: FileAoraMap<Seal::WitnessId, Seal::Client>,
        cache: FileAoraMap<Seal::WitnessId, Seal::Published>,
        keep: FileAoraMap<Opid, SmallOrdMap<u16, Seal::Definiton>>,
        index: FileAoraIndex<Opid, Seal::WitnessId>,
        stand: FileAoraIndex<Seal::WitnessId, Opid>,
        mine: FileAuraMap<Seal::WitnessId, MiningInfo, 32, 40>,
        _phantom: PhantomData<Seal>,
    }

    impl<Seal: RgbSeal> FilePile<Seal>
    where Seal::WitnessId: From<[u8; 32]> + Into<[u8; 32]>
    {
        pub fn new(name: &str, path: impl AsRef<Path>) -> Self {
            let mut path = path.as_ref().to_path_buf();
            path.push(name);
            path.set_extension("contract");

            let hoard = FileAoraMap::new(&path, "hoard");
            let cache = FileAoraMap::new(&path, "cache");
            let keep = FileAoraMap::new(&path, "keep");

            let index_file = path.join("index.dat");
            let index = FileAoraIndex::create(index_file.clone()).unwrap_or_else(|_| {
                panic!("unable to create index file '{}'", index_file.display())
            });
            let stand_file = path.join("stand.dat");
            let stand = FileAoraIndex::create(stand_file.clone()).unwrap_or_else(|_| {
                panic!("unable to create stand file '{}'", stand_file.display())
            });
            let mine_file = path.join("mine.dat");
            let mine = FileAuraMap::create(mine_file.clone()).unwrap_or_else(|_| {
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
    where Seal::WitnessId: From<[u8; 32]> + Into<[u8; 32]>
    {
        pub fn open(path: impl AsRef<Path>) -> Self {
            let path = path.as_ref().to_path_buf();
            let hoard = FileAoraMap::open(&path, "hoard");
            let cache = FileAoraMap::open(&path, "cache");
            let keep = FileAoraMap::open(&path, "keep");

            let index_file = path.join("index.dat");
            let index = FileAoraIndex::open(index_file.clone())
                .unwrap_or_else(|_| panic!("unable to open index file '{}'", index_file.display()));
            let stand_file = path.join("stand.dat");
            let stand = FileAoraIndex::open(stand_file.clone())
                .unwrap_or_else(|_| panic!("unable to open stand file '{}'", stand_file.display()));
            let mine_file = path.join("mine.dat");
            let mine = FileAuraMap::open(mine_file.clone()).unwrap_or_else(|_| {
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
        Seal::WitnessId: From<[u8; 32]> + Into<[u8; 32]>,
    {
        type Seal = Seal;

        type Hoard = FileAoraMap<Seal::WitnessId, Seal::Client>;
        type Cache = FileAoraMap<Seal::WitnessId, Seal::Published>;
        type Keep = FileAoraMap<Opid, SmallOrdMap<u16, Seal::Definiton>>;
        type Index = FileAoraIndex<Opid, Seal::WitnessId>;
        type Stand = FileAoraIndex<Seal::WitnessId, Opid>;
        type Mine = FileAuraMap<Seal::WitnessId, MiningInfo, 32, 40>;

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
                let client = self.hoard.get_expect(pubid);
                let published = self.cache.get_expect(pubid);
                SealWitness::new(published, client)
            })
        }
    }
}
