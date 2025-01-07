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

use std::fs;
use std::io::stdout;

use rgb::bitcoin::{OpretSeal, TapretSeal};
use rgb::popls::bp::PrefabBundle;
use rgb::{Schema, SealType, BITCOIN_OPRET, BITCOIN_TAPRET, LIQUID_OPRET, LIQUID_TAPRET};
use strict_encoding::StrictDeserialize;

use crate::cmd::{Args, Cmd};
use crate::dump::{dump_consignment, dump_stockpile};

impl Args {
    pub fn exec(&self) -> anyhow::Result<()> {
        match &self.command {
            Cmd::Info { file } => match file.extension() {
                Some(ext) if ext == "issuer" => {
                    let issuer = Schema::load(file)?;
                    eprintln!("File type: Issuer (contract schema)");
                    eprintln!("Codex Id: {}", issuer.codex.codex_id());
                    eprintln!("Default API Id: {}", issuer.default_api.api_id());
                }
                Some(_) => {
                    return Err(anyhow!(
                        "Unknown file type for '{}': the extension is not recognized",
                        file.display()
                    ))
                }
                None => {
                    return Err(anyhow!(
                        "The file '{}' has no extension; unable to detect the file type",
                        file.display()
                    ))
                }
            },

            Cmd::Inspect { file } => match file.extension() {
                Some(ext) if ext == "pfab" => {
                    let pfab = PrefabBundle::strict_deserialize_from_file::<{ usize::MAX }>(file)?;
                    serde_yaml::to_writer(stdout(), &pfab)?;
                }
                Some(ext) if ext == "issuer" => {
                    let issuer = Schema::load(file)?;
                    serde_yaml::to_writer(stdout(), &issuer)?;
                }
                Some(_) => {
                    return Err(anyhow!(
                        "Unknown file type for '{}': the extension is not recognized",
                        file.display()
                    ))
                }
                None => {
                    return Err(anyhow!(
                        "The file '{}' has no extension; unable to detect the file type",
                        file.display()
                    ))
                }
            },
            Cmd::Dump { force, seal, src, dst } => match src.extension() {
                Some(ext) if ext == "rgb" => {
                    let dst = dst
                        .as_ref()
                        .map(|p| p.to_owned())
                        .or_else(|| src.parent().map(|path| path.join("dump")))
                        .ok_or(anyhow!("Can't detect destination path for '{}'", src.display()))?;
                    if *force {
                        fs::remove_dir_all(&dst).or_else(|e| {
                            if e.kind() == std::io::ErrorKind::NotFound {
                                Ok(())
                            } else {
                                Err(e)
                            }
                        })?;
                    }
                    match seal {
                        #[cfg(feature = "bitcoin")]
                        SealType::BitcoinOpret => {
                            dump_consignment::<OpretSeal, BITCOIN_OPRET>(src, dst)
                        }
                        #[cfg(feature = "bitcoin")]
                        SealType::BitcoinTapret => {
                            dump_consignment::<TapretSeal, BITCOIN_TAPRET>(src, dst)
                        }
                        #[cfg(feature = "liquid")]
                        SealType::LiquidOpret => {
                            dump_consignment::<OpretSeal, LIQUID_OPRET>(src, dst)
                        }
                        #[cfg(feature = "liquid")]
                        SealType::LiquidTapret => {
                            dump_consignment::<TapretSeal, LIQUID_TAPRET>(src, dst)
                        }
                        #[cfg(feature = "prime")]
                        SealType::Prime => {
                            todo!()
                        }
                    }?;
                }
                Some(ext) if ext == "contract" => {
                    let dst = dst
                        .as_ref()
                        .map(|p| p.to_owned())
                        .unwrap_or_else(|| src.join("dump"));
                    if *force {
                        fs::remove_dir_all(&dst).or_else(|e| {
                            if e.kind() == std::io::ErrorKind::NotFound {
                                Ok(())
                            } else {
                                Err(e)
                            }
                        })?;
                    }
                    match seal {
                        #[cfg(feature = "bitcoin")]
                        SealType::BitcoinOpret => {
                            dump_stockpile::<OpretSeal, BITCOIN_OPRET>(src, dst)
                        }
                        #[cfg(feature = "bitcoin")]
                        SealType::BitcoinTapret => {
                            dump_stockpile::<TapretSeal, BITCOIN_TAPRET>(src, dst)
                        }
                        #[cfg(feature = "liquid")]
                        SealType::LiquidOpret => {
                            dump_stockpile::<OpretSeal, LIQUID_OPRET>(src, dst)
                        }
                        #[cfg(feature = "liquid")]
                        SealType::LiquidTapret => {
                            dump_stockpile::<TapretSeal, LIQUID_TAPRET>(src, dst)
                        }
                        #[cfg(feature = "prime")]
                        SealType::Prime => {
                            todo!()
                        }
                    }?;
                }
                Some(_) => {
                    return Err(anyhow!(
                        "Can't detect type for '{}': the extension is not recognized",
                        src.display()
                    ))
                }
                None => {
                    return Err(anyhow!(
                        "The path '{}' can't be recognized as a known data",
                        src.display()
                    ))
                }
            },
        }
        Ok(())
    }
}
