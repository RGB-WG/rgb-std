// RGB wallet library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::num::ParseIntError;
use std::str::FromStr;

use baid58::ToBaid58;
use bitcoin::{Address, Network};
use bp::Chain;
use fluent_uri::Uri;
use indexmap::IndexMap;
use rgb::{AttachId, ContractId, SecretSeal};
use rgbstd::interface::TypedState;
use strict_encoding::{InvalidIdent, TypeName};

const ANY: char = '~';

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
pub enum RgbTransport {
    #[display("rgb-rpc{tls}://host/")]
    JsonRpc { tls: bool, host: String },
    #[display("rgb+http{tls}://host/")]
    RestHttp { tls: bool, host: String },
    #[display("rgb+ws{tls}://host/")]
    WebSockets { tls: bool, host: String },
    #[display("rgb+storm://_/")]
    Storm {/* todo */},
    #[display("rgb:")]
    UnspecifiedMeans,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
pub enum InvoiceState {
    #[display("")]
    Void,
    #[display("{0}.{1}")]
    Fungible(u64, u64),
    #[display("...")] // TODO
    Data(Vec<u8> /* StrictVal */),
    #[display(inner)]
    Attach(AttachId),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, From)]
#[display(inner)]
pub enum Beneficiary {
    #[from]
    BlindedSeal(SecretSeal),
    #[from]
    WitnessUtxo(Address),
    // TODO: add BifrostNode(),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RgbInvoice {
    pub transport: RgbTransport,
    pub contract: Option<ContractId>,
    pub iface: Option<TypeName>,
    pub operation: Option<TypeName>,
    pub assignment: Option<TypeName>,
    pub beneficiary: Beneficiary,
    pub owned_state: TypedState,
    pub chain: Option<Chain>,
    pub unknown_query: IndexMap<String, String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum InvoiceParseError {
    #[from]
    Uri(fluent_uri::ParseError),

    #[display(doc_comments)]
    /// invalid invoice.
    Invalid,

    #[display(doc_comments)]
    /// invalid invoice: contract ID with but no iface
    ContractIdNoIface,

    #[display(doc_comments)]
    /// invalid contract ID.
    InvalidContractId(String),

    #[display(doc_comments)]
    /// invalid interface
    InvalidIface(String),

    #[from]
    Id(baid58::Baid58ParseError),

    #[display(doc_comments)]
    /// can't recognize beneficiary "": it should be either a bitcoin address or
    /// a blinded UTXO seal.
    Beneficiary(String),

    #[display(doc_comments)]
    /// network {0} is not supported.
    UnsupportedNetwork(Network),

    #[from]
    Num(ParseIntError),

    #[from]
    #[display(doc_comments)]
    /// invalid interface name.
    IfaceName(InvalidIdent),
}

impl std::fmt::Display for RgbInvoice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let amt = self.owned_state.to_string();
        write!(f, "{}", self.transport)?;
        if let Some(contract) = self.contract {
            write!(f, "{}/", contract.to_baid58())?;
        } else {
            write!(f, "{ANY}/")?;
        }
        if let Some(iface) = self.iface.clone() {
            write!(f, "{}/", iface)?;
        } else {
            write!(f, "{ANY}/")?;
        }
        if let Some(ref op) = self.operation {
            write!(f, "{op}/")?;
        }
        if let Some(ref assignment_name) = self.assignment {
            write!(f, "{assignment_name}/")?;
        }
        if !amt.is_empty() {
            write!(f, "{amt}+")?;
        }
        write!(f, "{}", self.beneficiary)?;
        if !self.unknown_query.is_empty() {
            f.write_str("?")?;
        }
        for (key, val) in self.unknown_query.iter().take(1) {
            // TODO: URLEncode
            write!(f, "{key}={val}")?;
        }
        for (key, val) in self.unknown_query.iter().skip(1) {
            // TODO: URLEncode
            write!(f, "&{key}={val}")?;
        }
        Ok(())
    }
}

impl FromStr for RgbInvoice {
    type Err = InvoiceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = Uri::parse(s)?;

        let path = uri
            .path()
            .segments()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();

        let mut chain = None;

        let mut next_path_index = 0;

        let contract_id_str = &path[next_path_index];
        let contract = match ContractId::from_str(contract_id_str) {
            Ok(cid) => Some(cid),
            Err(_) if contract_id_str == &ANY.to_string() => None,
            Err(_) => return Err(InvoiceParseError::InvalidContractId(contract_id_str.clone())),
        };
        next_path_index += 1;

        let iface_str = &path[next_path_index];
        let iface = match TypeName::try_from(iface_str.clone()) {
            Ok(i) => Some(i),
            Err(_) if iface_str == &ANY.to_string() => None,
            Err(_) => return Err(InvoiceParseError::InvalidIface(iface_str.clone())),
        };
        next_path_index += 1;
        if contract.is_some() && iface.is_none() {
            return Err(InvoiceParseError::ContractIdNoIface);
        }

        let mut assignment = path[next_path_index].split('+');
        // TODO: support other state types
        let (beneficiary_str, value) = match (assignment.next(), assignment.next()) {
            (Some(a), Some(b)) => (b, TypedState::Amount(a.parse::<u64>()?)),
            (Some(b), None) => (b, TypedState::Void),
            _ => return Err(InvoiceParseError::Invalid),
        };

        let beneficiary =
            match (SecretSeal::from_str(beneficiary_str), Address::from_str(beneficiary_str)) {
                (Ok(seal), Err(_)) => Beneficiary::BlindedSeal(seal),
                (Err(_), Ok(addr)) => {
                    chain = Some(match addr.network {
                        Network::Bitcoin => Chain::Bitcoin,
                        Network::Testnet => Chain::Testnet3,
                        Network::Signet => Chain::Signet,
                        Network::Regtest => Chain::Regtest,
                        unknown => return Err(InvoiceParseError::UnsupportedNetwork(unknown)),
                    });
                    Beneficiary::WitnessUtxo(addr.assume_checked())
                }
                (Err(_), Err(_)) => {
                    return Err(InvoiceParseError::Beneficiary(beneficiary_str.to_owned()));
                }
                (Ok(_), Ok(_)) => {
                    panic!("found a string which is both valid bitcoin address and UTXO blind seal")
                }
            };

        Ok(RgbInvoice {
            transport: RgbTransport::UnspecifiedMeans,
            contract,
            iface,
            operation: None,
            assignment: None,
            beneficiary,
            owned_state: value,
            chain,
            unknown_query: Default::default(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse() {
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        let invoice_str = "rgb:~/RGB20/6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        let invoice_str = "rgb:~/~/6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/~/\
                           6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::ContractIdNoIface)));

        let invalid_contract_id = "invalid";
        let invoice_str =
            format!("rgb:{invalid_contract_id}/RGB20/6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve");
        let result = RgbInvoice::from_str(&invoice_str);
        assert!(
            matches!(result, Err(InvoiceParseError::InvalidContractId(c)) if c == invalid_contract_id)
        );
    }
}
