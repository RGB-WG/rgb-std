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

// TODO: Complete implementation
#![allow(dead_code)]

use alloc::collections::{BTreeMap, BTreeSet};
use core::hash::Hash;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use hypersonic::persistance::StockFs;
use rgb::RgbSeal;
use strict_encoding::{StrictDecode, StrictEncode};

use crate::{CodexId, Consensus, Contract, ContractId, PileFs, Schema};

struct CacheHashMap<K, V> {
    limit: usize,
    freq: BTreeMap<u64, BTreeSet<K>>,
    cache: HashMap<K, (V, u64)>,
}

impl<K, V> CacheHashMap<K, V>
where K: Ord + Hash + Clone
{
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            freq: BTreeMap::new(),
            cache: HashMap::with_capacity(limit),
        }
    }

    pub fn len(&self) -> usize { self.cache.len() }
    pub fn limit(&self) -> usize { self.limit }

    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.cache.get_mut(key).map(|(v, freq)| {
            self.freq.get_mut(freq).expect("inconsistency").remove(key);
            *freq = freq.saturating_add(1);
            self.freq.entry(*freq).or_default().insert(key.clone());
            &*v
        })
    }

    pub fn insert(&mut self, key: K, value: V) {
        if let Some((old, freq)) = self.cache.get_mut(&key) {
            *old = value;
            self.freq.get_mut(freq).expect("inconsistency").remove(&key);
            *freq = freq.saturating_add(1);
            self.freq.entry(*freq).or_default().insert(key);
        } else if self.cache.len() == self.limit {
            let (freq, mut keys) = self.freq.pop_first().expect("cache has a positive length");
            let removed_key = keys
                .pop_first()
                .expect("frequency entries must have a positive length");
            self.cache.remove(&removed_key);
            if !keys.is_empty() {
                self.freq.insert(freq, keys);
            }
        } else {
            self.freq.entry(1).or_default().insert(key.clone());
            self.cache.insert(key, (value, 1));
        }
    }
}

/// Directory-based memory-efficient collection of RGB smart contracts and contract issuers.
///
/// Unlike [`crate::ContractsInmem`], which can also be read from a directory, doesn't maintain all
/// contracts in memory and loads/unloads them from/to disk dynamically.
#[derive(Getters)]
pub struct ContractsCache<Seal: RgbSeal>
where
    Seal::Client: StrictEncode + StrictDecode,
    Seal::Published: Eq + StrictEncode + StrictDecode,
    Seal::WitnessId: Ord + From<[u8; 32]> + Into<[u8; 32]>,
{
    path: PathBuf,
    #[getter(as_copy)]
    consensus: Consensus,
    #[getter(as_copy)]
    testnet: bool,
    codex_ids: HashSet<CodexId>,
    contract_ids: HashSet<ContractId>,
    #[getter(skip)]
    schema_cache: CacheHashMap<CodexId, Schema>,
    #[getter(skip)]
    contract_cache: CacheHashMap<ContractId, Contract<StockFs, PileFs<Seal>>>,
}
impl<Seal: RgbSeal> ContractsCache<Seal>
where
    Seal::Client: StrictEncode + StrictDecode,
    Seal::Published: Eq + StrictEncode + StrictDecode,
    Seal::WitnessId: Ord + From<[u8; 32]> + Into<[u8; 32]>,
{
    pub fn open(
        consensus: Consensus,
        testnet: bool,
        path: PathBuf,
        schema_cache_size: usize,
        contract_cache_size: usize,
    ) -> Self {
        Self {
            path,
            consensus,
            testnet,
            codex_ids: HashSet::new(),
            contract_ids: HashSet::new(),
            schema_cache: CacheHashMap::new(schema_cache_size),
            contract_cache: CacheHashMap::new(contract_cache_size),
        }
    }
}
