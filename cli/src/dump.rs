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

use std::fs::File;
use std::path::Path;
use std::{fs, io};

use amplify::confinement::SmallOrdMap;
use anyhow::Context;
use hypersonic::persistance::StockFs;
use hypersonic::{Articles, Operation};
use rgb::{Contract, PileFs, PublishedWitness, RgbSeal, RgbSealDef, SealWitness, SingleUseSeal};
use serde::{Deserialize, Serialize};
use strict_encoding::{DecodeError, StreamReader, StrictDecode, StrictEncode, StrictReader};

pub fn dump_stockpile<Seal>(src: &Path, dst: impl AsRef<Path>) -> anyhow::Result<()>
where
    Seal: RgbSeal + Serialize + for<'de> Deserialize<'de>,
    Seal::Definition: Serialize + for<'de> Deserialize<'de>,
    Seal::Client: Serialize + StrictEncode + StrictDecode,
    Seal::Published: Eq + Serialize + StrictEncode + StrictDecode,
    Seal::WitnessId: Ord + From<[u8; 32]> + Into<[u8; 32]> + Serialize,
{
    let dst = dst.as_ref();
    fs::create_dir_all(dst)?;

    print!("Reading contract contract from '{}' ... ", src.display());
    let path = src.to_path_buf();
    let contract = Contract::<StockFs, PileFs<Seal>>::load(path.clone(), path)?;
    println!("success reading {}", contract.contract_id());

    print!("Processing contract articles ... ");
    let out = File::create_new(dst.join("articles.yaml"))
        .context("can't create contract articles file; try to use the `--force` flag")?;
    serde_yaml::to_writer(&out, contract.articles())?;
    println!("success");

    print!("Processing operations ... none found");
    for (no, (opid, op, rels)) in contract.operations().enumerate() {
        let out = File::create_new(dst.join(format!("{:04}-{opid}.op.yaml", no + 1)))?;
        serde_yaml::to_writer(&out, &op)?;
        let out = File::create_new(dst.join(format!("{:04}-{}.pile.yaml", no + 1, opid)))?;
        serde_yaml::to_writer(&out, &rels)?;
        print!("\rProcessing operations ... {} processed", no + 1);
    }
    println!();

    print!("Processing trace ... none state transitions found");
    for (no, (opid, st)) in contract.trace().enumerate() {
        let out = File::create_new(dst.join(format!("{:04}-{opid}.st.yaml", no + 1)))?;
        serde_yaml::to_writer(&out, &st)?;
        print!("\rProcessing trace ... {} state transition processed", no + 1);
    }
    println!();

    print!("Processing state ... ");
    let out = File::create_new(dst.join("state.yaml"))?;
    serde_yaml::to_writer(&out, &contract.state())?;

    let state = contract.state_all();
    let out = File::create_new(dst.join("state-raw.yaml"))?;
    serde_yaml::to_writer(&out, &state.raw)?;
    let out = File::create_new(dst.join("state-main.yaml"))?;
    serde_yaml::to_writer(&out, &state.main)?;
    for (name, state) in &state.aux {
        let out = File::create_new(dst.join(format!("state-{name}.yaml")))?;
        serde_yaml::to_writer(&out, state)?;
    }
    println!("success");

    print!("Processing witnesses ... none found");
    for (no, witness) in contract.witnesses().enumerate() {
        let out = File::create_new(dst.join(format!("witness-{}.yaml", witness.id)))?;
        serde_yaml::to_writer(&out, &witness)?;
        print!("\rProcessing witnesses ... {} processed", no + 1);
    }
    println!();

    Ok(())
}

pub fn dump_consignment<SealDef>(src: &Path, dst: impl AsRef<Path>) -> anyhow::Result<()>
where
    SealDef: RgbSealDef + Serialize,
    SealDef::Src: Serialize,
    <SealDef::Src as SingleUseSeal>::CliWitness:
        Serialize + for<'de> Deserialize<'de> + StrictEncode + StrictDecode,
    <SealDef::Src as SingleUseSeal>::PubWitness:
        Eq + Serialize + for<'de> Deserialize<'de> + StrictEncode + StrictDecode,
    <<SealDef::Src as SingleUseSeal>::PubWitness as PublishedWitness<SealDef::Src>>::PubId:
        Ord + From<[u8; 32]> + Into<[u8; 32]> + Serialize,
{
    let dst = dst.as_ref();
    fs::create_dir_all(dst)?;

    let file = File::open(src)?;
    let mut stream = StrictReader::with(StreamReader::new::<{ usize::MAX }>(file));

    let contract_id = Contract::<StockFs, PileFs<SealDef::Src>>::parse_consignment(&mut stream)
        .map_err(|e| anyhow!(e.to_string()))?;
    println!("Dumping consignment for {} into '{}'", contract_id, dst.display());

    let mut op_count = 1;
    let mut seal_count = 0;
    let mut witness_count = 0;

    print!("Processing contract articles ... ");
    let articles = Articles::strict_decode(&mut stream)?;
    let out =
        File::create_new(dst.join(format!("0000-genesis.{}.yaml", articles.issue.genesis_opid())))?;
    serde_yaml::to_writer(&out, &articles.issue.genesis)?;
    let out =
        File::create_new(dst.join(format!("codex.{}.yaml", articles.schema.codex.codex_id())))?;
    serde_yaml::to_writer(&out, &articles.schema.codex)?;
    let out = File::create_new(dst.join("schema.yaml"))?;
    serde_yaml::to_writer(&out, &articles.schema)?;

    let out = File::create_new(dst.join("0000-seals.yml"))?;
    let defined_seals = SmallOrdMap::<u16, SealDef>::strict_decode(&mut stream)
        .expect("Failed to read consignment stream");
    serde_yaml::to_writer(&out, &defined_seals)?;
    seal_count += defined_seals.len();

    let count = u64::strict_decode(&mut stream)?;
    if count != 0 {
        println!("error");
        bail!("Consignment stream has {count} witnesses, but 0 witnesses are expected",);
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
                let defined_seals = SmallOrdMap::<u16, SealDef>::strict_decode(&mut stream)
                    .expect("Failed to read consignment stream");
                serde_yaml::to_writer(&out, &defined_seals)?;
                seal_count += defined_seals.len();

                let len = u64::strict_decode(&mut stream)?;
                for no in 0..len {
                    let out = File::create_new(
                        dst.join(format!("{op_count:04}-witness-{:02}.yaml", no + 1)),
                    )?;
                    let witness = SealWitness::<SealDef::Src>::strict_decode(&mut stream)?;
                    serde_yaml::to_writer(&out, &witness)?;
                }

                witness_count += len as usize;
                op_count += 1;
            }
            Err(DecodeError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => bail!("Failed to read consignment stream: {}", e),
        }
        print!(
            "\rParsing stream ... {op_count} operations, {seal_count} seals, {witness_count} \
             witnesses processed",
        );
    }
    println!();
    Ok(())
}
