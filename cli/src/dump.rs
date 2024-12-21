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
use std::io::Write;
use std::path::Path;
use std::{fs, io};

use amplify::confinement::SmallVec;
use hypersonic::{Articles, ContractId, Operation};
use rgb::bitcoin::{OpretSeal, TapretSeal};
use rgb::{
    SealType, SealWitness, BITCOIN_OPRET, BITCOIN_TAPRET, LIQUID_OPRET, LIQUID_TAPRET, PRIME_SEALS,
};
use strict_encoding::{DecodeError, StreamReader, StrictDecode, StrictReader};

pub fn dumb_consignment(seal: SealType, src: &Path, dst: impl AsRef<Path>) -> anyhow::Result<()> {
    let dst = dst.as_ref();
    fs::create_dir_all(dst)?;

    let file = File::open(src)?;
    let mut stream = StrictReader::with(StreamReader::new::<{ usize::MAX }>(file));

    let cointract_id = ContractId::strict_decode(&mut stream)?;
    println!("Dumping consignment for {} into '{}'", cointract_id, dst.display());

    print!("Processing contract articles ... ");
    let out = File::create_new(dst.join("0-articles.yaml"))?;
    match seal {
        #[cfg(feature = "bitcoin")]
        SealType::BitcoinOpret => {
            let articles = Articles::<BITCOIN_OPRET>::strict_decode(&mut stream)?;
            serde_yaml::to_writer(&out, &articles)?;
        }
        #[cfg(feature = "bitcoin")]
        SealType::BitcoinTapret => {
            let articles = Articles::<BITCOIN_TAPRET>::strict_decode(&mut stream)?;
            serde_yaml::to_writer(&out, &articles)?;
        }
        #[cfg(feature = "liquid")]
        SealType::LiquidOpret => {
            let articles = Articles::<LIQUID_OPRET>::strict_decode(&mut stream)?;
            serde_yaml::to_writer(&out, &articles)?;
        }
        #[cfg(feature = "liquid")]
        SealType::LiquidTapret => {
            let articles = Articles::<LIQUID_TAPRET>::strict_decode(&mut stream)?;
            serde_yaml::to_writer(&out, &articles)?;
        }
        #[cfg(feature = "prime")]
        SealType::Prime => {
            let articles = Articles::<PRIME_SEALS>::strict_decode(&mut stream)?;
            serde_yaml::to_writer(&out, &articles)?;
        }
    }
    println!("success");

    let mut op_count = 1;
    let mut seal_count = 0;
    let mut witness_count = 0;
    loop {
        match Operation::strict_decode(&mut stream) {
            Ok(operation) => {
                let opid = operation.opid();

                let out = File::create_new(dst.join(format!("{op_count:04}-op.{opid}.yaml")))?;
                serde_yaml::to_writer(&out, &operation)?;

                let mut out = File::create_new(dst.join(format!("{op_count:04}-seals.toml")))?;
                // Seal definition is not distinct between tapret and opret, so we save on match
                // here
                let defined_seals = SmallVec::<OpretSeal>::strict_decode(&mut stream)
                    .expect("Failed to read consignment stream");
                out.write_all(toml::to_string(&defined_seals)?.as_bytes())?;
                seal_count += defined_seals.len();

                let len = u64::strict_decode(&mut stream)?;
                for no in 0..len {
                    let out = File::create_new(
                        dst.join(format!("{op_count:04}-witness-{:02}.toml", no + 1)),
                    )?;
                    match seal {
                        #[cfg(feature = "bitcoin")]
                        SealType::BitcoinOpret => {
                            let witness = SealWitness::<OpretSeal>::strict_decode(&mut stream)?;
                            serde_yaml::to_writer(&out, &witness)?;
                        }
                        #[cfg(feature = "bitcoin")]
                        SealType::BitcoinTapret => {
                            let witness = SealWitness::<TapretSeal>::strict_decode(&mut stream)?;
                            serde_yaml::to_writer(&out, &witness)?;
                        }
                        #[cfg(feature = "liquid")]
                        SealType::LiquidOpret => {
                            let witness = SealWitness::<OpretSeal>::strict_decode(&mut stream)?;
                            serde_yaml::to_writer(&out, &witness)?;
                        }
                        #[cfg(feature = "liquid")]
                        SealType::LiquidTapret => {
                            let witness = SealWitness::<TapretSeal>::strict_decode(&mut stream)?;
                            serde_yaml::to_writer(&out, &witness)?;
                        }
                        #[cfg(feature = "prime")]
                        SealType::Prime => {
                            todo!()
                        }
                    }
                }

                witness_count += len as usize;
                op_count += 1;
            }
            Err(DecodeError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(anyhow!("Failed to read consignment stream: {}", e)),
        }
        print!(
            "Processing: {op_count} operations, {seal_count} seals, {witness_count} witnesses ... \
             \r"
        );
    }
    println!("complete");
    Ok(())
}
