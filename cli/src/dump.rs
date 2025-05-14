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
use hypersonic::persistance::StockFs;
use hypersonic::{Articles, Operation};
use rgb::{Contract, PileFs, PublishedWitness, RgbSeal, RgbSealDef, SealWitness, SingleUseSeal};
use serde::{Deserialize, Serialize};
use sonix::{dump_articles, dump_ledger};
use strict_encoding::{DecodeError, StreamReader, StrictDecode, StrictEncode, StrictReader};

pub fn dump_stockpile<Seal>(
    src: impl AsRef<Path>,
    dst: impl AsRef<Path>,
    force: bool,
) -> anyhow::Result<()>
where
    Seal: RgbSeal + Serialize + for<'de> Deserialize<'de>,
    Seal::Definition: Serialize + for<'de> Deserialize<'de>,
    Seal::Client: Serialize + StrictEncode + StrictDecode,
    Seal::Published: Eq + Serialize + StrictEncode + StrictDecode,
    Seal::WitnessId: Ord + From<[u8; 32]> + Into<[u8; 32]> + Serialize,
{
    let src = src.as_ref();
    let dst = dst.as_ref();
    dump_ledger(src, dst, force)?;

    print!("Reading contract pile from '{}' ... ", src.display());
    let path = src.to_path_buf();
    let contract = Contract::<StockFs, PileFs<Seal>>::load(path.clone(), path)?;
    println!("success reading {}", contract.contract_id());

    print!("Processing genesis seals ... ");
    let articles = contract.articles();
    let genesis_opid = articles.issue.genesis_opid();
    let out = File::create_new(dst.join(format!("0000-seals-{genesis_opid}.yaml")))?;
    serde_yaml::to_writer(
        &out,
        &contract.op_seals(genesis_opid, articles.issue.genesis.destructible.len_u16()),
    )?;
    println!("success");

    print!("Processing operations ... none found");
    for (no, (opid, _, rels)) in contract.operations().enumerate() {
        let out = File::create_new(dst.join(format!("{:04}-seals-{opid}.yaml", no + 1)))?;
        serde_yaml::to_writer(&out, &rels)?;
        print!("\rProcessing operations ... {} processed", no + 1);
    }
    println!();

    print!("Processing state ... ");
    let out = File::create_new(dst.join("state.yaml"))?;
    serde_yaml::to_writer(&out, &contract.state())?;

    print!("Processing witnesses ... none found");
    for (no, witness) in contract.witnesses().enumerate() {
        let out = File::create_new(dst.join(format!("witness-{}.yaml", witness.id)))?;
        serde_yaml::to_writer(&out, &witness)?;
        print!("\rProcessing witnesses ... {} processed", no + 1);
    }
    println!();

    Ok(())
}

pub fn dump_consignment<SealDef>(
    src: impl AsRef<Path>,
    dst: impl AsRef<Path>,
    force: bool,
) -> anyhow::Result<()>
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
    let src = src.as_ref();
    let dst = dst.as_ref();
    if force {
        let _ = fs::remove_dir_all(dst);
    }
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
    let genesis_opid = dump_articles(&articles, dst)?;
    let out = File::create_new(dst.join(format!("0000-seals-{genesis_opid}.yml")))?;
    let defined_seals = SmallOrdMap::<u16, SealDef>::strict_decode(&mut stream)
        .expect("Failed to read the consignment stream");
    serde_yaml::to_writer(&out, &defined_seals)?;
    seal_count += defined_seals.len();

    let count = bool::strict_decode(&mut stream)?;
    if count {
        println!("error");
        bail!(
            "Consignment stream has {count} witnesses for genesis, but zero witnesses are expected",
        );
    }
    println!("success");

    println!();
    loop {
        match Operation::strict_decode(&mut stream) {
            Ok(operation) => {
                let opid = operation.opid();

                let out = File::create_new(dst.join(format!("{op_count:04}-op-{opid}.yaml")))?;
                serde_yaml::to_writer(&out, &operation)?;

                let out = File::create_new(dst.join(format!("{op_count:04}-seals-{opid}.yml")))?;
                let defined_seals = SmallOrdMap::<u16, SealDef>::strict_decode(&mut stream)
                    .expect("Failed to read the consignment stream");
                serde_yaml::to_writer(&out, &defined_seals)?;
                seal_count += defined_seals.len();

                let witness = bool::strict_decode(&mut stream)?;
                if witness {
                    let witness = SealWitness::<SealDef::Src>::strict_decode(&mut stream)?;
                    let out = File::create_new(dst.join(format!(
                        "{op_count:04}-witness-{}.yaml",
                        witness.published.pub_id()
                    )))?;
                    serde_yaml::to_writer(&out, &witness)?;
                    witness_count += 1;
                }

                op_count += 1;
            }
            Err(DecodeError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => bail!("Failed to read the consignment stream: {}", e),
        }
        print!(
            "\rParsing stream ... {op_count} operations, {seal_count} seals, {witness_count} \
             witnesses processed",
        );
    }
    println!();
    Ok(())
}
