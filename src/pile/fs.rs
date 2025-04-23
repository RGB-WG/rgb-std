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

use std::io;
use std::marker::PhantomData;
use std::path::PathBuf;

use amplify::confinement::SmallOrdMap;
use aora::file::{FileAoraIndex, FileAoraMap, FileAuraMap};
use aora::{AoraIndex, AoraMap, AuraMap, TransactionalMap};
use rgb::RgbSeal;
use strict_encoding::{StrictDecode, StrictEncode};

use crate::{OpRels, Opid, Pile, Witness, WitnessStatus};

const HOARD_MAGIC: u64 = u64::from_be_bytes(*b"RGBHOARD");
const CACHE_MAGIC: u64 = u64::from_be_bytes(*b"RGBCACHE");
const KEEP_MAGIC: u64 = u64::from_be_bytes(*b"RGBKEEPS");
const INDEX_MAGIC: u64 = u64::from_be_bytes(*b"RGBINDEX");
const STAND_MAGIC: u64 = u64::from_be_bytes(*b"RGBSTAND");
const MINE_MAGIC: u64 = u64::from_be_bytes(*b"RGBMINES");

pub struct PileFs<Seal: RgbSeal>
where Seal::WitnessId: From<[u8; 32]> + Into<[u8; 32]>
{
    hoard: FileAoraMap<Seal::WitnessId, Seal::Client, HOARD_MAGIC, 1>,
    cache: FileAoraMap<Seal::WitnessId, Seal::Published, CACHE_MAGIC, 1>,
    keep: FileAoraMap<Opid, SmallOrdMap<u16, Seal::Definiton>, KEEP_MAGIC, 1>,
    index: FileAoraIndex<Opid, Seal::WitnessId, INDEX_MAGIC, 1>,
    stand: FileAoraIndex<Seal::WitnessId, Opid, STAND_MAGIC, 1>,
    mine: FileAuraMap<Seal::WitnessId, WitnessStatus, MINE_MAGIC, 1, 32, 8>,
    _phantom: PhantomData<Seal>,
}

impl<Seal: RgbSeal> Pile for PileFs<Seal>
where
    Seal::Client: StrictEncode + StrictDecode,
    Seal::Published: Eq + StrictEncode + StrictDecode,
    Seal::WitnessId: From<[u8; 32]> + Into<[u8; 32]>,
{
    type Seal = Seal;
    type Conf = PathBuf;
    type Error = io::Error;

    fn new(path: Self::Conf) -> Result<Self, io::Error>
    where Self: Sized {
        let hoard = FileAoraMap::create_new(&path, "hoard")?;
        let cache = FileAoraMap::create_new(&path, "cache")?;
        let keep = FileAoraMap::create_new(&path, "keep")?;

        let index = FileAoraIndex::create_new(&path, "index.dat")?;
        let stand = FileAoraIndex::create_new(&path, "stand.dat")?;
        let mine = FileAuraMap::create_new(&path, "mine.dat")?;

        Ok(Self {
            hoard,
            cache,
            keep,
            index,
            stand,
            mine,
            _phantom: PhantomData,
        })
    }

    fn load(path: Self::Conf) -> Result<Self, io::Error>
    where Self: Sized {
        let hoard = FileAoraMap::open(&path, "hoard")?;
        let cache = FileAoraMap::open(&path, "cache")?;
        let keep = FileAoraMap::open(&path, "keep")?;

        let index = FileAoraIndex::open(&path, "index.dat")?;
        let stand = FileAoraIndex::open(&path, "stand.dat")?;
        let mine = FileAuraMap::open(&path, "mine.dat")?;

        Ok(Self {
            hoard,
            cache,
            keep,
            index,
            stand,
            mine,
            _phantom: PhantomData,
        })
    }

    fn has_witness(&self, wid: Seal::WitnessId) -> bool { self.hoard.contains_key(wid) }

    fn pub_witness(&self, wid: Seal::WitnessId) -> Seal::Published { self.cache.get_expect(wid) }

    fn cli_witness(&self, wid: Seal::WitnessId) -> Seal::Client { self.hoard.get_expect(wid) }

    fn witness_status(&self, wid: Seal::WitnessId) -> WitnessStatus { self.mine.get_expect(wid) }

    fn witness_ids(&self) -> impl Iterator<Item = <Self::Seal as RgbSeal>::WitnessId> {
        self.stand.keys()
    }

    fn op_witness_ids(&self, opid: Opid) -> impl ExactSizeIterator<Item = Seal::WitnessId> {
        self.index.get(opid)
    }

    fn ops_by_witness_id(&self, wid: Seal::WitnessId) -> impl ExactSizeIterator<Item = Opid> {
        self.stand.get(wid)
    }

    fn op_seals(&self, opid: Opid) -> SmallOrdMap<u16, Seal::Definiton> {
        self.keep.get_expect(opid)
    }

    fn witnesses_since(
        &self,
        transaction_no: u64,
    ) -> impl Iterator<Item = <Seal as RgbSeal>::WitnessId> {
        struct WitnessIter<'pile, Id, M>
        where
            Id: From<[u8; 32]> + Into<[u8; 32]>,
            M: AuraMap<Id, WitnessStatus, 32, 8>,
        {
            curr: u64,
            max: u64,
            mine: &'pile M,
            iter: Option<Box<dyn Iterator<Item = Id> + 'pile>>,
            _phantom: PhantomData<Id>,
        }
        impl<'pile, Id: 'pile, M> Iterator for WitnessIter<'pile, Id, M>
        where
            Id: From<[u8; 32]> + Into<[u8; 32]>,
            M: AuraMap<Id, WitnessStatus, 32, 8> + TransactionalMap<Id>,
        {
            type Item = Id;
            fn next(&mut self) -> Option<Self::Item> {
                loop {
                    match self.iter.as_mut()?.next() {
                        None => {
                            self.curr += 1;
                            if self.curr >= self.max {
                                return None;
                            }
                            self.iter = Some(Box::new(self.mine.transaction_keys(self.curr)));
                        }
                        Some(el) => return Some(el),
                    }
                }
            }
        }

        let to = self.mine.transaction_count();

        let mine = &self.mine;
        WitnessIter {
            curr: transaction_no + 1,
            max: to,
            mine,
            iter: Some(Box::new(mine.transaction_keys(transaction_no))),
            _phantom: PhantomData,
        }
    }

    fn add_witness(
        &mut self,
        opid: Opid,
        wid: <Self::Seal as RgbSeal>::WitnessId,
        published: &<Self::Seal as RgbSeal>::Published,
        anchor: &<Self::Seal as RgbSeal>::Client,
    ) {
        self.index.push(opid, wid);
        self.stand.push(wid, opid);
        // TODO: For now there is no merge for Bitcoin or Prime anchors. However other systems
        //       may be different. Add merge and update procedure here.
        self.hoard.insert(wid, anchor);
        self.cache.insert(wid, published);
        if !self.mine.contains_key(wid) {
            self.mine.insert_only(wid, WitnessStatus::Archived);
        }
    }

    fn add_seals(
        &mut self,
        opid: Opid,
        seals: SmallOrdMap<u16, <Self::Seal as RgbSeal>::Definiton>,
    ) {
        self.keep.insert(opid, &seals)
    }

    fn update_witness_status(
        &mut self,
        wid: <Self::Seal as RgbSeal>::WitnessId,
        status: WitnessStatus,
    ) {
        self.mine.update_only(wid, status);
    }

    fn commit_transaction(&mut self) { self.mine.commit_transaction(); }

    fn witnesses(&self) -> impl Iterator<Item = Witness<Self::Seal>> {
        self.hoard.iter().map(|(wid, client)| {
            let published = self.cache.get_expect(wid);
            let status = self.mine.get_expect(wid);
            let opids = self.stand.get(wid).collect();
            Witness { id: wid, published, client, status, opids }
        })
    }

    fn op_relations(&self) -> impl Iterator<Item = OpRels<Self::Seal>> {
        self.keep.iter().map(|(opid, seals)| {
            let witness_ids = self.index.get(opid).collect();
            OpRels { opid, witness_ids, defines: seals, _phantom: PhantomData }
        })
    }
}
