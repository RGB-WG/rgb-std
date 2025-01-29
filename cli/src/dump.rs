// RGB command-line toolbox utility
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

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::{fs, io};

use amplify::confinement::SmallVec;
use amplify::hex::ToHex;
use amplify::Bytes16;
use commit_verify::ReservedBytes;
use hypersonic::aora::Aora;
use hypersonic::{Articles, ContractId, FileSupply, Operation};
use rgb::{
    FilePile, Index, MoundConsumeError, Pile, PublishedWitness, RgbSeal, SealWitness, Stockpile,
    MAGIC_BYTES_CONSIGNMENT,
};
use serde::{Deserialize, Serialize};
use strict_encoding::{DecodeError, StreamReader, StrictDecode, StrictEncode, StrictReader};

pub fn dump_stockpile<Seal>(src: &Path, dst: impl AsRef<Path>) -> anyhow::Result<()>
where
    Seal: RgbSeal + Serialize + for<'de> Deserialize<'de>,
    Seal::CliWitness: Serialize + StrictEncode + StrictDecode,
    Seal::PubWitness: Serialize + StrictEncode + StrictDecode,
    <Seal::PubWitness as PublishedWitness<Seal>>::PubId:
        Ord + From<[u8; 32]> + Into<[u8; 32]> + Serialize,
{
    let dst = dst.as_ref();
    fs::create_dir_all(dst)?;

    print!("Reading contract stockpile from '{}' ... ", src.display());
    let mut stockpile = Stockpile::<FileSupply, FilePile<Seal>>::load(src);
    println!("success reading {}", stockpile.contract_id());

    print!("Processing contract articles ... ");
    let out = File::create_new(dst.join("articles.yaml"))?;
    serde_yaml::to_writer(&out, stockpile.stock().articles())?;
    println!("success");

    print!("Processing operations ... none found");
    for (no, (opid, op)) in stockpile.stock_mut().operations().enumerate() {
        let out = File::create_new(dst.join(format!("{:04}-{opid}.op.yaml", no + 1)))?;
        serde_yaml::to_writer(&out, &op)?;
        print!("\rProcessing operations ... {} processed", no + 1);
    }
    println!();

    print!("Processing trace ... none state transitions found");
    for (no, (opid, st)) in stockpile.stock_mut().trace().enumerate() {
        let out = File::create_new(dst.join(format!("{:04}-{opid}.st.yaml", no + 1)))?;
        serde_yaml::to_writer(&out, &st)?;
        print!("\rProcessing trace ... {} state transition processed", no + 1);
    }
    println!();

    print!("Processing state ... ");
    let out = File::create_new(dst.join("state.yaml"))?;
    serde_yaml::to_writer(&out, &stockpile.state())?;
    let out = File::create_new(dst.join("state-raw.yaml"))?;
    serde_yaml::to_writer(&out, &stockpile.stock().state().raw)?;
    let out = File::create_new(dst.join("state-main.yaml"))?;
    serde_yaml::to_writer(&out, &stockpile.stock().state().main)?;
    for (name, state) in &stockpile.stock().state().aux {
        let out = File::create_new(dst.join(format!("state-{name}.yaml")))?;
        serde_yaml::to_writer(&out, state)?;
    }
    println!("success");

    print!("Processing anchors ... none found");
    for (no, (txid, anchor)) in stockpile.pile_mut().hoard_mut().iter().enumerate() {
        let out = File::create_new(dst.join(format!("{txid}.anchor.yaml")))?;
        serde_yaml::to_writer(&out, &anchor)?;
        print!("\rProcessing anchors ... {} processed", no + 1);
    }
    println!();

    print!("Processing witness transactions ... none found");
    for (no, (txid, tx)) in stockpile.pile_mut().cache_mut().iter().enumerate() {
        let out = File::create_new(dst.join(format!("{txid}.yaml")))?;
        serde_yaml::to_writer(&out, &tx)?;
        print!("\rProcessing witness transactions ... {} processed", no + 1);
    }
    println!();

    print!("Processing seal definitions ... none found");
    let mut seal_count = 0;
    for (no, (opid, seals)) in stockpile.pile_mut().keep_mut().iter().enumerate() {
        let out = File::create_new(dst.join(format!("{no:04}-{opid}.seals.yaml")))?;
        serde_yaml::to_writer(&out, &seals)?;
        seal_count += seals.len();
        print!("\rProcessing seal definitions ... {seal_count} processed");
    }
    println!();

    print!("Processing index ... ");
    let index = stockpile.pile().index();
    let index = index
        .keys()
        .map(|opid| (opid, index.get(opid).collect::<Vec<_>>()))
        .collect::<BTreeMap<_, _>>();
    let mut out = File::create_new(dst.join("index.toml"))?;
    out.write_all(toml::to_string(&index)?.as_bytes())?;
    println!("success");

    Ok(())
}

pub fn dump_consignment<Seal>(src: &Path, dst: impl AsRef<Path>) -> anyhow::Result<()>
where
    Seal: RgbSeal + Serialize,
    Seal::CliWitness: Serialize + for<'de> Deserialize<'de> + StrictEncode + StrictDecode,
    Seal::PubWitness: Serialize + for<'de> Deserialize<'de> + StrictEncode + StrictDecode,
    <Seal::PubWitness as PublishedWitness<Seal>>::PubId:
        Ord + From<[u8; 32]> + Into<[u8; 32]> + Serialize,
{
    let dst = dst.as_ref();
    fs::create_dir_all(dst)?;

    let file = File::open(src)?;
    let mut stream = StrictReader::with(StreamReader::new::<{ usize::MAX }>(file));

    let magic_bytes = Bytes16::strict_decode(&mut stream)?;
    if magic_bytes.to_byte_array() != MAGIC_BYTES_CONSIGNMENT {
        return Err(anyhow!(
            MoundConsumeError::<Seal>::UnrecognizedMagic(magic_bytes.to_hex()).to_string()
        ));
    }
    // Version
    ReservedBytes::<2>::strict_decode(&mut stream)?;

    let contract_id = ContractId::strict_decode(&mut stream)?;
    println!("Dumping consignment for {} into '{}'", contract_id, dst.display());

    let mut op_count = 1;
    let mut seal_count = 0;
    let mut witness_count = 0;

    print!("Processing contract articles ... ");
    let articles = Articles::strict_decode(&mut stream)?;
    let out = File::create_new(
        dst.join(format!("0000-genesis.{}.yaml", articles.contract.genesis_opid())),
    )?;
    serde_yaml::to_writer(&out, &articles.contract.genesis)?;
    let out =
        File::create_new(dst.join(format!("codex.{}.yaml", articles.schema.codex.codex_id())))?;
    serde_yaml::to_writer(&out, &articles.schema.codex)?;
    let out = File::create_new(dst.join("schema.yaml"))?;
    serde_yaml::to_writer(&out, &articles.schema)?;

    let out = File::create_new(dst.join("0000-seals.yml"))?;
    let defined_seals =
        SmallVec::<Seal>::strict_decode(&mut stream).expect("Failed to read consignment stream");
    serde_yaml::to_writer(&out, &defined_seals)?;
    seal_count += defined_seals.len();

    let count = u64::strict_decode(&mut stream)?;
    if count != 0 {
        println!("error");
        return Err(anyhow!(
            "consignment stream has {count} witnesses, but 0 witnesses are expected",
        ));
    }
    println!("success");

    println!();
    loop {
        match Operation::strict_decode(&mut stream) {
            Ok(operation) => {
                let opid = operation.opid();

                let out = File::create_new(dst.join(format!("{op_count:04}-op.{opid}.yaml")))?;
                serde_yaml::to_writer(&out, &operation)?;

                let out = File::create_new(dst.join(format!("{op_count:04}-seals.yml")))?;
                let defined_seals = SmallVec::<Seal>::strict_decode(&mut stream)
                    .expect("Failed to read consignment stream");
                serde_yaml::to_writer(&out, &defined_seals)?;
                seal_count += defined_seals.len();

                let len = u64::strict_decode(&mut stream)?;
                for no in 0..len {
                    let out = File::create_new(
                        dst.join(format!("{op_count:04}-witness-{:02}.yaml", no + 1)),
                    )?;
                    let witness = SealWitness::<Seal>::strict_decode(&mut stream)?;
                    serde_yaml::to_writer(&out, &witness)?;
                }

                witness_count += len as usize;
                op_count += 1;
            }
            Err(DecodeError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(anyhow!("Failed to read consignment stream: {}", e)),
        }
        print!(
            "\rParsing stream ... {op_count} operations, {seal_count} seals, {witness_count} \
             witnesses processed",
        );
    }
    println!();
    Ok(())
}
