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

use alloc::collections::BTreeMap;
use core::borrow::Borrow;
use std::io;

use amplify::hex::ToHex;
use amplify::Bytes16;
use commit_verify::ReservedBytes;
use hypersonic::{AuthToken, CellAddr, CodexId, ContractId, Opid, Schema, Supply};
use rgb::RgbSeal;
use single_use_seals::{PublishedWitness, SingleUseSeal};
use strict_encoding::{
    ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter, WriteRaw,
};

use crate::{ConsumeError, ContractInfo, CreateParams, Pile, StateCell, Stockpile, StockpileApi};

pub const MAGIC_BYTES_CONSIGNMENT: [u8; 16] = *b"RGB CONSIGNMENT\0";

pub trait Excavate<S: Supply<CAPS>, P: Pile, const CAPS: u32> {
    fn contracts(&mut self) -> impl Iterator<Item = (ContractId, Stockpile<S, P, CAPS>)>;
}

/// Mound API trait.
///
/// Mound API may be implemented for mounds which are homogenuous on contract capabilities -- or
/// heterogenous (i.e. "multi-mounds").
pub trait MoundApi {
    /// Issue a new contract using a sub-mound with a provided seal types and capabilities.
    ///
    /// # Panics
    ///
    /// If seal type doesn't match capabilities, or a mound doesn't support the provided
    /// capabilities.
    fn issue<Seal: RgbSeal, const CAPS: u32>(
        &mut self,
        params: CreateParams<Seal>,
        supply: impl Supply<CAPS>,
        pile: impl Pile<Seal = Seal>,
    ) -> ContractId;

    fn contracts_mut(&self) -> impl Iterator<Item = (ContractId, &mut impl StockpileApi)>;

    fn contract_mut(&self, contract_id: ContractId) -> &mut impl StockpileApi;
}

/// Mound is a collection of smart contracts which have homogenous capabilities.
pub struct Mound<S: Supply<CAPS>, P: Pile, X: Excavate<S, P, CAPS>, const CAPS: u32> {
    contracts: BTreeMap<ContractId, Stockpile<S, P, CAPS>>,
    /// Persistence does loading of a stockpiles and their storage when a new contract is added.
    persistence: X,
}

impl<S: Supply<CAPS>, P: Pile, X: Excavate<S, P, CAPS> + Default, const CAPS: u32> Default
    for Mound<S, P, X, CAPS>
{
    fn default() -> Self { Self { contracts: BTreeMap::new(), persistence: default!() } }
}

impl<S: Supply<CAPS>, P: Pile, X: Excavate<S, P, CAPS> + Default, const CAPS: u32>
    Mound<S, P, X, CAPS>
{
    pub fn new() -> Self { Self { contracts: BTreeMap::new(), persistence: default!() } }
}

impl<S: Supply<CAPS>, P: Pile, X: Excavate<S, P, CAPS>, const CAPS: u32> Mound<S, P, X, CAPS> {
    pub fn with(persistence: X) -> Self { Self { contracts: BTreeMap::new(), persistence } }

    pub fn open(mut persistance: X) -> Self {
        Self {
            contracts: persistance.contracts().collect(),
            persistence: persistance,
        }
    }

    pub fn issue(&mut self, params: CreateParams<P::Seal>, supply: S, pile: P) -> ContractId {
        let schema = self
            .schema(params.codex_id)
            .expect_or_else(|| format!("Unknown codex `{}`", params.codex_id));
        let stockpile = Stockpile::issue(schema.clone(), params, supply, pile);
        let id = stockpile.contract_id();
        self.contracts.insert(id, stockpile);
        id
    }

    pub fn contract_ids(&self) -> impl Iterator<Item = ContractId> + use<'_, S, P, X, CAPS> {
        self.contracts.keys().copied()
    }

    pub fn contracts(&self) -> impl Iterator<Item = (ContractId, &Stockpile<S, P, CAPS>)> {
        self.contracts.iter().map(|(id, stock)| (*id, stock))
    }

    pub fn contracts_info(&self) -> impl Iterator<Item = ContractInfo> + use<'_, S, P, X, CAPS> {
        self.contracts
            .iter()
            .map(|(id, stockpile)| ContractInfo::new(*id, stockpile.stock().articles()))
    }

    pub fn contracts_mut(
        &mut self,
    ) -> impl Iterator<Item = (ContractId, &mut Stockpile<S, P, CAPS>)> {
        self.contracts.iter_mut().map(|(id, stock)| (*id, stock))
    }

    pub fn has_contract(&self, id: ContractId) -> bool { self.contracts.contains_key(&id) }

    pub fn contract(&self, id: ContractId) -> &Stockpile<S, P, CAPS> {
        self.contracts
            .get(&id)
            .unwrap_or_else(|| panic!("unknown contract {id}"))
    }

    pub fn contract_mut(&mut self, id: ContractId) -> &mut Stockpile<S, P, CAPS> {
        self.contracts
            .get_mut(&id)
            .unwrap_or_else(|| panic!("unknown contract {id}"))
    }

    pub fn attest(
        &mut self,
        pub_witness: &<P::Seal as SingleUseSeal>::PubWitness,
        anchors: impl IntoIterator<Item = (ContractId, Opid, <P::Seal as SingleUseSeal>::CliWitness)>,
    ) {
        for (contract_id, opid, anchor) in anchors {
            self.contract_mut(contract_id)
                .attest(opid, anchor, pub_witness);
        }
    }

    pub fn consign(
        &mut self,
        contract_id: ContractId,
        terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        mut writer: StrictWriter<impl WriteRaw>,
    ) -> io::Result<()>
    where
        <P::Seal as SingleUseSeal>::CliWitness: StrictDumb + StrictEncode,
        <P::Seal as SingleUseSeal>::PubWitness: StrictDumb + StrictEncode,
        <<P::Seal as SingleUseSeal>::PubWitness as PublishedWitness<P::Seal>>::PubId: StrictEncode,
    {
        writer = MAGIC_BYTES_CONSIGNMENT.strict_encode(writer)?;
        // Version
        writer = 0x00u16.strict_encode(writer)?;
        writer = contract_id.strict_encode(writer)?;
        self.contract_mut(contract_id).consign(terminals, writer)
    }

    pub fn consume(
        &mut self,
        reader: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(&[StateCell]) -> Vec<P::Seal>,
    ) -> Result<(), ConsumeError<P::Seal>>
    where
        <P::Seal as SingleUseSeal>::CliWitness: StrictDecode,
        <P::Seal as SingleUseSeal>::PubWitness: StrictDecode,
        <<P::Seal as SingleUseSeal>::PubWitness as PublishedWitness<P::Seal>>::PubId: StrictDecode,
    {
        let magic_bytes = Bytes16::strict_decode(reader)?;
        if magic_bytes.to_byte_array() != MAGIC_BYTES_CONSIGNMENT {
            return Err(ConsumeError::UnrecognizedMagic(magic_bytes.to_hex()));
        }
        // Version
        ReservedBytes::<2>::strict_decode(reader)?;
        let contract_id = ContractId::strict_decode(reader)?;
        let contract = if self.has_contract(contract_id) {
            self.contract_mut(contract_id)
        } else {
            // TODO: Create new contract
            todo!()
        };
        contract.consume(reader, seal_resolver)
    }
}

#[cfg(feature = "fs")]
pub mod file {
    use std::ffi::OsStr;
    use std::fs;
    use std::fs::{File, FileType};
    use std::marker::PhantomData;
    use std::path::{Path, PathBuf};

    use hypersonic::expect::Expect;
    use hypersonic::FileSupply;
    use rgb::RgbSeal;
    use single_use_seals::PublishedWitness;
    use strict_encoding::{StreamWriter, StrictDecode, StrictEncode};

    use super::*;
    use crate::FilePile;

    pub struct DirExcavator<Seal: RgbSeal, const CAPS: u32> {
        dir: PathBuf,
        _phantom: PhantomData<Seal>,
    }

    impl<Seal: RgbSeal, const CAPS: u32> DirExcavator<Seal, CAPS> {
        pub fn new(dir: PathBuf) -> Self { Self { dir, _phantom: PhantomData } }

        fn contents(&mut self) -> impl Iterator<Item = (FileType, PathBuf)> {
            fs::read_dir(&self.dir)
                .expect_or_else(|| format!("unable to read directory `{}`", self.dir.display()))
                .map(|entry| {
                    let entry = entry.expect("unable to read directory");
                    let ty = entry.file_type().expect("unable to read file type");
                    (ty, entry.path())
                })
        }
    }

    impl<Seal: RgbSeal, const CAPS: u32> Excavate<FileSupply, FilePile<Seal>, CAPS>
        for DirExcavator<Seal, CAPS>
    where
        Seal::CliWitness: StrictEncode + StrictDecode,
        Seal::PubWitness: StrictEncode + StrictDecode,
        <Seal::PubWitness as PublishedWitness<Seal>>::PubId: Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        fn schemata(&mut self) -> impl Iterator<Item = (CodexId, Schema)> {
            self.contents().filter_map(|(ty, path)| {
                if ty.is_file() && path.extension().and_then(OsStr::to_str) == Some("issuer") {
                    Schema::load(path)
                        .ok()
                        .map(|schema| (schema.codex.codex_id(), schema))
                } else if ty.is_dir()
                    && path.extension().and_then(OsStr::to_str) == Some("contract")
                {
                    let contract = Stockpile::<FileSupply, FilePile<Seal>, CAPS>::load(path);
                    let schema = contract.schema().clone();
                    Some((schema.codex.codex_id(), schema))
                } else {
                    None
                }
            })
        }

        fn contracts(
            &mut self,
        ) -> impl Iterator<Item = (ContractId, Stockpile<FileSupply, FilePile<Seal>, CAPS>)>
        {
            self.contents().filter_map(|(ty, path)| {
                if ty.is_dir() && path.extension().and_then(OsStr::to_str) == Some("contract") {
                    let contract = Stockpile::load(path);
                    Some((contract.contract_id(), contract))
                } else {
                    None
                }
            })
        }
    }

    pub type FileMound<Seal, const CAPS: u32> =
        Mound<FileSupply, FilePile<Seal>, DirExcavator<Seal, CAPS>, CAPS>;

    impl<Seal: RgbSeal, const CAPS: u32> FileMound<Seal, CAPS>
    where
        Seal::CliWitness: StrictEncode + StrictDecode,
        Seal::PubWitness: StrictEncode + StrictDecode,
        <Seal::PubWitness as PublishedWitness<Seal>>::PubId: Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        pub fn load(path: impl AsRef<Path>) -> Self {
            let path = path.as_ref();
            let excavator = DirExcavator::new(path.to_owned());
            Self::open(excavator)
        }

        pub fn issue_to_file(&mut self, params: CreateParams<Seal>) -> ContractId {
            let supply = FileSupply::new(params.name.as_str(), &self.persistence.dir);
            let pile = FilePile::<Seal>::new(params.name.as_str(), &self.persistence.dir);
            self.issue(params, supply, pile)
        }

        pub fn path(&self) -> &Path { &self.persistence.dir }

        pub fn consign_to_file(
            &mut self,
            contract_id: ContractId,
            terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
            path: impl AsRef<Path>,
        ) -> io::Result<()>
        where
            Seal::CliWitness: StrictDumb,
            Seal::PubWitness: StrictDumb,
            <Seal::PubWitness as PublishedWitness<Seal>>::PubId: StrictEncode,
        {
            let file = File::create_new(path)?;
            let writer = StrictWriter::with(StreamWriter::new::<{ usize::MAX }>(file));
            self.consign(contract_id, terminals, writer)
        }
    }
}
