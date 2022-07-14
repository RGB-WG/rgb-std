// RGB Standard Library: high-level API to RGB smart contracts.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

#[macro_use]
extern crate clap;
#[macro_use]
extern crate amplify;
extern crate serde_crate as serde;

use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::str::FromStr;

use amplify::hex::{FromHex, ToHex};
use bitcoin::psbt::serialize::{Deserialize, Serialize};
use bitcoin::OutPoint;
use bp::seals::txout::CloseMethod;
use clap::Parser;
use colored::Colorize;
use commit_verify::ConsensusCommit;
use electrum_client::Client as ElectrumClient;
use lnpbp::chain::Chain;
use rgb::fungible::asset::Asset;
use rgb::psbt::RgbExt;
use rgb::{
    fungible::allocation::{AllocatedValue, OutpointValue, UtxobValue},
    util::ticker_validator,
    Consignment, Contract, Disclosure, Extension, IntoRevealedSeal, Schema, StateTransfer,
    Transition,
};
use rgb_core::{seal, Node, Validator};
use stens::AsciiString;
use strict_encoding::{StrictDecode, StrictEncode};
use wallet::psbt::Psbt;

#[derive(Parser, Clone, Debug)]
#[clap(
    name = "rgb",
    bin_name = "rgb",
    author,
    version,
    about = "Command-line tool for working with RGB smart contracts"
)]
pub struct Opts {
    /// Bitcoin network to use
    #[clap(short, long, default_value = "signet", env = "RGB_NETWORK")]
    pub network: Chain,

    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Command {
    /// Generate blinded UTXO value
    Blind {
        /// Method for seal closing ('tapret1st' or 'opret1st'; defaults to 'tapret1st')
        #[clap(short, long, default_value = "tapret1st")]
        method: CloseMethod,

        /// Unspent transaction output to define as a blinded seal
        utxo: OutPoint,
    },

    /// Issue asset
    Issue {
        /// Asset ticker (up to 8 characters, always converted to uppercase)
        #[clap(validator = ticker_validator)]
        ticker: AsciiString,

        /// Asset name (up to 32 characters)
        name: AsciiString,

        /// Precision, i.e. number of digits reserved for fractional part
        #[clap(short, long, default_value = "8")]
        precision: u8,

        /// Asset allocation, in form of <amount>@<txid>:<vout>
        allocation: Vec<OutpointValue>,

        /// Outputs controlling inflation (secondary issue);
        /// in form of <amount>@<txid>:<vout>
        #[clap(short, long)]
        inflation: Vec<OutpointValue>,

        /// Enable renomination procedure; parameter takes argument in form of
        /// <txid>:<vout> specifying output controlling renomination right
        #[clap(short, long)]
        renomination: Option<OutPoint>,

        /// Enable epoch-based burn & replacement procedure; parameter takes
        /// argument in form of <txid>:<vout> specifying output controlling the
        /// right of opening the first epoch
        #[clap(short, long)]
        epoch: Option<OutPoint>,
    },

    /// Prepares state transition for assets transfer.
    Transfer {
        /// File with state transfer consignment, which endpoints will act as
        /// inputs.
        consignment: PathBuf,

        /// Bitcoin transaction UTXOs which will be spent by the transfer
        #[clap(short = 'u', long = "utxo", required = true)]
        outpoints: Vec<OutPoint>,

        /// List of transfer beneficiaries
        #[clap(required = true)]
        beneficiaries: Vec<UtxobValue>,

        /// Change output; one per schema state type.
        #[clap(short, long)]
        change: Vec<AllocatedValue>,

        /// File to store state transition transferring assets to the
        /// beneficiaries and onto change outputs.
        output: PathBuf,
    },

    /// Commands for working with consignments
    Consignment {
        #[clap(subcommand)]
        subcommand: ConsignmentCommand,
    },

    /// Commands for working with disclosures
    Disclosure {
        #[clap(subcommand)]
        subcommand: DisclosureCommand,
    },

    /// Commands for working with schemata
    Schema {
        #[clap(subcommand)]
        subcommand: SchemaCommand,
    },

    /// Commands for working with state extensions
    Extension {
        #[clap(subcommand)]
        subcommand: ExtensionCommand,
    },

    /// Commands for working with state transitions
    Transition {
        #[clap(subcommand)]
        subcommand: TransitionCommand,
    },

    /// Commands working with RGB-specific PSBT information
    Psbt {
        #[clap(subcommand)]
        subcommand: PsbtCommand,
    },
}

#[derive(Subcommand, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ConsignmentCommand {
    /// Inspects the consignment structure by printing it out.
    Inspect {
        /// Formatting for the output
        #[clap(short, long, default_value = "yaml")]
        format: Format,

        /// File with consignment data
        consignment: PathBuf,
    },

    Validate {
        /// File with consignment data
        consignment: String,

        /// Address for Electrum server
        #[clap(default_value = "pandora.network:60001")]
        electrum: String,
    },
}

#[derive(Subcommand, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum DisclosureCommand {
    Convert {
        /// Consignment data; if none are given reads from STDIN
        disclosure: Option<String>,

        /// Formatting of the input data
        #[clap(short, long, default_value = "bech32")]
        input: Format,

        /// Formatting for the output
        #[clap(short, long, default_value = "yaml")]
        output: Format,
    },
}

#[derive(Subcommand, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum SchemaCommand {
    Convert {
        /// Schema data; if none are given reads from STDIN
        schema: Option<String>,

        /// Formatting of the input data
        #[clap(short, long, default_value = "bech32")]
        input: Format,

        /// Formatting for the output
        #[clap(short, long, default_value = "yaml")]
        output: Format,
    },
}

#[derive(Subcommand, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ExtensionCommand {
    Convert {
        /// State extension data; if none are given reads from STDIN
        extension: Option<String>,

        /// Formatting of the input data
        #[clap(short, long, default_value = "bech32")]
        input: Format,

        /// Formatting for the output
        #[clap(short, long, default_value = "yaml")]
        output: Format,
    },
}

#[derive(Subcommand, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum TransitionCommand {
    Convert {
        /// State transition data; if none are given reads from STDIN
        transition: Option<String>,

        /// Formatting of the input data
        #[clap(short, long, default_value = "bech32")]
        input: Format,

        /// Formatting for the output
        #[clap(short, long, default_value = "yaml")]
        output: Format,
    },
}

#[derive(Subcommand, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum PsbtCommand {
    /// Finalize RGB bundle information in PSBT file.
    Bundle {
        /// Input file containing PSBT of the transfer witness transaction.
        psbt_in: PathBuf,

        /// Output file to save the PSBT updated with state transition(s)
        /// information. If not given, the source PSBT file is overwritten.
        psbt_out: Option<PathBuf>,
    },

    /// Analyze PSBT file and print out all RGB-related information from it
    Analyze {
        /// File to analyze
        psbt: PathBuf,
    },
}

#[derive(ArgEnum, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum Format {
    /// Format according to the rust debug rules
    #[display("debug")]
    Debug,

    /// Format according to default display formatting
    #[display("bech32")]
    Bech32,

    /// Format as YAML
    #[display("yaml")]
    Yaml,

    /// Format as JSON
    #[display("json")]
    Json,

    /// Format according to the strict encoding rules
    #[display("hex")]
    Hexadecimal,

    /// Format as a rust array (using hexadecimal byte values)
    #[display("rust")]
    Rust,

    /// Produce binary (raw) output
    #[display("raw")]
    Binary,

    /// Produce client-validated commitment
    #[display("commitment")]
    Commitment,
}

impl FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_lowercase().as_str() {
            "debug" => Format::Debug,
            "bech32" => Format::Bech32,
            "yaml" => Format::Yaml,
            "json" => Format::Json,
            "hex" => Format::Hexadecimal,
            "raw" | "bin" | "binary" => Format::Binary,
            "rust" => Format::Rust,
            "commitment" => Format::Commitment,
            other => Err(format!("Unknown format: {}", other))?,
        })
    }
}

fn input_read<T>(data: Option<String>, format: Format) -> Result<T, Error>
where
    T: StrictDecode + for<'de> serde::Deserialize<'de>,
{
    // TODO: Refactor with microservices cli
    let data = data
        .map(|d| d.as_bytes().to_vec())
        .ok_or_else(String::new)
        .or_else(|_| -> Result<Vec<u8>, Error> {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        })?;
    Ok(match format {
        Format::Yaml => serde_yaml::from_str(&String::from_utf8_lossy(&data))?,
        Format::Json => serde_json::from_str(&String::from_utf8_lossy(&data))?,
        Format::Hexadecimal => {
            T::strict_deserialize(Vec::<u8>::from_hex(&String::from_utf8_lossy(&data))?)?
        }
        Format::Binary => T::strict_deserialize(&data)?,
        _ => panic!("Can't read data from {} format", format),
    })
}

fn output_print<T>(data: T, format: Format) -> Result<(), Error>
where
    T: Debug + serde::Serialize + StrictEncode + ConsensusCommit,
    <T as ConsensusCommit>::Commitment: Display,
{
    match format {
        Format::Debug => println!("{:#?}", data),
        Format::Yaml => println!("{}", serde_yaml::to_string(&data)?),
        Format::Json => println!("{}", serde_json::to_string(&data)?),
        Format::Hexadecimal => {
            println!("{}", data.strict_serialize()?.to_hex())
        }
        Format::Rust => println!("{:#04X?}", data.strict_serialize()?),
        Format::Binary => {
            data.strict_encode(io::stdout())?;
        }
        Format::Commitment => {
            println!("{}", data.consensus_commit())
        }
        format => panic!("Can't read data in {} format", format),
    }
    Ok(())
}

#[derive(Debug, Display)]
#[display(inner)]
pub struct Error(Box<dyn std::error::Error>);

impl<E> From<E> for Error
where
    E: std::error::Error + 'static,
{
    fn from(e: E) -> Self {
        Error(Box::new(e))
    }
}

fn main() -> Result<(), Error> {
    let opts = Opts::parse();

    match opts.command {
        Command::Blind { utxo, method } => {
            let seal = seal::Revealed::new(method, utxo);
            println!("{}", seal.to_concealed_seal());
            println!("Blinding factor: {}", seal.blinding);
        }

        Command::Issue {
            ticker,
            name,
            precision,
            allocation,
            inflation,
            renomination,
            epoch,
        } => {
            let inflation = inflation.into_iter().fold(
                BTreeMap::new(),
                |mut map, OutpointValue { value, outpoint }| {
                    // We may have only a single secondary issuance right per
                    // outpoint, so folding all outpoints
                    map.entry(outpoint)
                        .and_modify(|amount| *amount += value)
                        .or_insert(value);
                    map
                },
            );
            let contract = Contract::create_rgb20(
                opts.network,
                ticker,
                name,
                precision,
                allocation,
                inflation,
                renomination,
                epoch,
            );

            let _asset =
                Asset::try_from(&contract).expect("create_rgb20 does not match RGB20 schema");

            eprintln!(
                "{} {}\n",
                "Contract ID:".bright_green(),
                contract.contract_id().to_string().bright_yellow()
            );

            eprintln!("{}", "Contract YAML:".bright_green());
            eprintln!("{}", serde_yaml::to_string(contract.genesis()).unwrap());

            eprintln!("{}", "Contract JSON:".bright_green());
            println!("{}\n", serde_json::to_string(contract.genesis()).unwrap());

            eprintln!("{}", "Contract source:".bright_green());
            println!("{}\n", contract);

            // eprintln!("{}", "Asset details:".bright_green());
            // eprintln!("{}\n", serde_yaml::to_string(&asset).unwrap());
        }

        Command::Transfer {
            consignment,
            outpoints,
            beneficiaries,
            change,
            output,
        } => {
            let transfer = StateTransfer::strict_file_load(consignment).unwrap();

            let asset = Asset::try_from(&transfer).unwrap();

            let beneficiaries = beneficiaries
                .into_iter()
                .map(|v| (v.seal_confidential.into(), v.value))
                .collect();
            let change = change
                .into_iter()
                .map(|v| (v.into_revealed_seal(), v.value))
                .collect();
            let outpoints = outpoints.into_iter().collect();
            let transition = asset.transfer(outpoints, beneficiaries, change).unwrap();

            transition.strict_file_save(output).unwrap();
            //consignment.strict_file_save(output).unwrap();

            println!("{}", serde_yaml::to_string(&transition).unwrap());
            println!("{}", "Success".bold().bright_green());
        }

        Command::Consignment { subcommand } => match subcommand {
            ConsignmentCommand::Inspect {
                format,
                consignment,
            } => {
                let transfer = StateTransfer::strict_file_load(consignment)?;
                output_print(transfer, format)?;
            }
            ConsignmentCommand::Validate {
                consignment,
                electrum,
            } => {
                let transfer = StateTransfer::strict_file_load(consignment)?;

                let electrum = ElectrumClient::new(&electrum)?;
                let status = Validator::validate(&transfer, &electrum);

                println!("{}", serde_yaml::to_string(&status)?);
            }
        },
        Command::Disclosure { subcommand } => match subcommand {
            DisclosureCommand::Convert {
                disclosure,
                input,
                output,
            } => {
                let disclosure: Disclosure = input_read(disclosure, input)?;
                output_print(disclosure, output)?;
            }
        },
        Command::Schema { subcommand } => match subcommand {
            SchemaCommand::Convert {
                schema,
                input,
                output,
            } => {
                let schema: Schema = input_read(schema, input)?;
                output_print(schema, output)?;
            }
        },
        Command::Extension { subcommand } => match subcommand {
            ExtensionCommand::Convert {
                extension,
                input,
                output,
            } => {
                let extension: Extension = input_read(extension, input)?;
                output_print(extension, output)?;
            }
        },
        Command::Transition { subcommand } => match subcommand {
            TransitionCommand::Convert {
                transition,
                input,
                output,
            } => {
                let transition: Transition = input_read(transition, input)?;
                output_print(transition, output)?;
            }
        },
        Command::Psbt { subcommand } => match subcommand {
            PsbtCommand::Bundle { psbt_in, psbt_out } => {
                let psbt_bytes = fs::read(&psbt_in)?;
                let mut psbt = Psbt::deserialize(&psbt_bytes)?;

                let count = psbt.rgb_bundle_to_lnpbp4()?;
                println!("Total {} bundles converted", count);

                let psbt_bytes = psbt.serialize();
                fs::write(psbt_out.unwrap_or(psbt_in), psbt_bytes)?;
            }
            PsbtCommand::Analyze { psbt } => {
                let psbt_bytes = fs::read(&psbt)?;
                let psbt = Psbt::deserialize(&psbt_bytes)?;

                println!("contracts:");
                for contract_id in psbt.rgb_contract_ids() {
                    println!("- contract_id: {}", contract_id);
                    if let Some(contract) = psbt.rgb_contract(contract_id)? {
                        println!("  - source: {}", contract);
                    } else {
                        println!("  - warning: contract source is absent");
                    }
                    println!("  - transitions:");
                    for node_id in psbt.rgb_node_ids(contract_id) {
                        if let Some(transition) = psbt.rgb_transition(node_id)? {
                            println!("    - {}", transition.strict_serialize()?.to_hex());
                        } else {
                            println!("    - warning: transition is absent");
                        }
                    }
                    println!("  - used in:");
                    for (node_id, vin) in psbt.rgb_contract_consumers(contract_id)? {
                        println!("    - input: {}", vin);
                        println!("      node_id: {}", node_id);
                    }
                }

                println!("bundles:");
                for (contract_id, bundle) in psbt.rgb_bundles()? {
                    println!("- contract_id: {}", contract_id);
                    println!("  bundle_id: {}", bundle.bundle_id());
                    println!("    - revealed: # nodes");
                    for transition in bundle.known_transitions() {
                        println!(
                            "      - {}: {}",
                            transition.node_id(),
                            transition.strict_serialize()?.to_hex()
                        );
                    }
                    println!("    - concealed: # nodes and inputs");
                    for (node_id, vins) in bundle.concealed_iter() {
                        println!("      - {}: {:?}", node_id, vins);
                    }
                }

                println!("proprietary: # all proprietary keys");
                println!("- global:");
                for (key, value) in psbt.proprietary {
                    let prefix = String::from_utf8(key.prefix.clone())
                        .unwrap_or_else(|_| key.prefix.to_hex());
                    println!(
                        "  - {}/{:#04x}/{}: {}",
                        prefix,
                        u8::from(key.subtype),
                        key.key.to_hex(),
                        value.to_hex()
                    );
                }
                println!("- inputs:");
                for (no, input) in psbt.inputs.iter().enumerate() {
                    println!("  - {}:", no);
                    for (key, value) in &input.proprietary {
                        let prefix = String::from_utf8(key.prefix.clone())
                            .unwrap_or_else(|_| key.prefix.to_hex());
                        println!(
                            "    - {}/{:#04x}/{}: {}",
                            prefix,
                            u8::from(key.subtype),
                            key.key.to_hex(),
                            value.to_hex()
                        );
                    }
                }
                println!("- outputs:");
                for (no, output) in psbt.outputs.iter().enumerate() {
                    println!("  - {}:", no);
                    for (key, value) in &output.proprietary {
                        let prefix = String::from_utf8(key.prefix.clone())
                            .unwrap_or_else(|_| key.prefix.to_hex());
                        println!(
                            "    - {}/{:#04x}/{}: {}",
                            prefix,
                            u8::from(key.subtype),
                            key.key.to_hex(),
                            value.to_hex()
                        );
                    }
                }
            }
        },
    }

    Ok(())
}
