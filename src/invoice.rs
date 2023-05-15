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
use fluent_uri::enc::EStr;
use fluent_uri::Uri;
use indexmap::IndexMap;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rgb::{AttachId, ContractId, SecretSeal};
use rgbstd::interface::TypedState;
use strict_encoding::{FieldName, InvalidIdent, TypeName};

const OMITTED: char = '~';
const EXPIRY: &str = "expiry";
const ENDPOINTS: &str = "endpoints";
const TRANSPORT_SEP: char = ',';
const TRANSPORT_HOST_SEP: &str = "://";
const QUERY_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b']')
    .add(b'&')
    .add(b'=');

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum RgbTransport {
    JsonRpc { tls: bool, host: String },
    RestHttp { tls: bool, host: String },
    WebSockets { tls: bool, host: String },
    Storm {/* todo */},
    UnspecifiedMeans,
}

impl std::fmt::Display for RgbTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RgbTransport::JsonRpc { tls, host } => {
                let s = if *tls { "s" } else { "" };
                write!(f, "rpc{s}{TRANSPORT_HOST_SEP}{}", host)?;
            }
            RgbTransport::RestHttp { tls, host } => {
                let s = if *tls { "s" } else { "" };
                write!(f, "http{s}{TRANSPORT_HOST_SEP}{}", host)?;
            }
            RgbTransport::WebSockets { tls, host } => {
                let s = if *tls { "s" } else { "" };
                write!(f, "ws{s}{TRANSPORT_HOST_SEP}{}", host)?;
            }
            RgbTransport::Storm {} => {
                write!(f, "storm{TRANSPORT_HOST_SEP}_/")?;
            }
            RgbTransport::UnspecifiedMeans => {}
        };
        Ok(())
    }
}

impl FromStr for RgbTransport {
    type Err = TransportParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tokens = s.split_once(TRANSPORT_HOST_SEP);
        if tokens.is_none() {
            return Err(TransportParseError::InvalidTransport(s.to_string()));
        }
        let (trans_type, host) = tokens.unwrap();
        if host.is_empty() {
            return Err(TransportParseError::InvalidTransportHost(host.to_string()));
        }
        let host = host.to_string();
        let transport = match trans_type {
            "rpc" => RgbTransport::JsonRpc { tls: false, host },
            "rpcs" => RgbTransport::JsonRpc { tls: true, host },
            "http" => RgbTransport::RestHttp { tls: false, host },
            "https" => RgbTransport::RestHttp { tls: true, host },
            "ws" => RgbTransport::WebSockets { tls: false, host },
            "wss" => RgbTransport::WebSockets { tls: true, host },
            "storm" => RgbTransport::Storm {},
            _ => return Err(TransportParseError::InvalidTransport(s.to_string())),
        };
        Ok(transport)
    }
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
    pub transports: Vec<RgbTransport>,
    pub contract: Option<ContractId>,
    pub iface: Option<TypeName>,
    pub operation: Option<TypeName>,
    pub assignment: Option<FieldName>,
    pub beneficiary: Beneficiary,
    pub owned_state: TypedState,
    pub chain: Option<Chain>,
    /// UTC unix timestamp
    pub expiry: Option<i64>,
    pub unknown_query: IndexMap<String, String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum TransportParseError {
    #[display(doc_comments)]
    /// invalid transport {0}.
    InvalidTransport(String),

    #[display(doc_comments)]
    /// invalid transport host {0}.
    InvalidTransportHost(String),
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
    /// invalid invoice scheme {0}.
    InvalidScheme(String),

    #[display(doc_comments)]
    /// no invoice transport has been provided.
    NoTransport,

    #[display(doc_comments)]
    /// invalid invoice: contract ID present but no contract interface provided.
    ContractIdNoIface,

    #[display(doc_comments)]
    /// invalid contract ID.
    InvalidContractId(String),

    #[display(doc_comments)]
    /// invalid interface {0}.
    InvalidIface(String),

    #[display(doc_comments)]
    /// invalid expiration timestamp {0}.
    InvalidExpiration(String),

    #[display(doc_comments)]
    /// invalid query parameter {0}.
    InvalidQueryParam(String),

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

fn percent_decode(estr: &EStr) -> Result<String, InvoiceParseError> {
    Ok(estr
        .decode()
        .into_string()
        .map_err(|e| InvoiceParseError::InvalidQueryParam(e.to_string()))?
        .to_string())
}

fn map_query_params(uri: &Uri<&str>) -> Result<IndexMap<String, String>, InvoiceParseError> {
    let mut map: IndexMap<String, String> = IndexMap::new();
    if let Some(q) = uri.query() {
        let params = q.split('&');
        for p in params {
            if let Some((k, v)) = p.split_once('=') {
                map.insert(percent_decode(k)?, percent_decode(v)?);
            } else {
                return Err(InvoiceParseError::InvalidQueryParam(p.to_string()));
            }
        }
    }
    Ok(map)
}

impl RgbInvoice {
    fn has_params(&self) -> bool {
        self.expiry.is_some() ||
            self.transports != vec![RgbTransport::UnspecifiedMeans] ||
            !self.unknown_query.is_empty()
    }

    fn query_params(&self) -> IndexMap<String, String> {
        let mut query_params: IndexMap<String, String> = IndexMap::new();
        if let Some(expiry) = self.expiry {
            query_params.insert(EXPIRY.to_string(), expiry.to_string());
        }
        if self.transports != vec![RgbTransport::UnspecifiedMeans] {
            let mut transports: Vec<String> = vec![];
            for transport in self.transports.clone() {
                transports.push(transport.to_string());
            }
            query_params.insert(ENDPOINTS.to_string(), transports.join(&TRANSPORT_SEP.to_string()));
        }
        query_params.extend(self.unknown_query.clone());
        query_params
    }
}

impl std::fmt::Display for RgbInvoice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let amt = self.owned_state.to_string();
        write!(f, "rgb:")?;
        if let Some(contract) = self.contract {
            write!(f, "{}/", contract.to_baid58())?;
        } else {
            write!(f, "{OMITTED}/")?;
        }
        if let Some(iface) = self.iface.clone() {
            write!(f, "{iface}/")?;
        } else {
            write!(f, "{OMITTED}/")?;
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
        if self.has_params() {
            f.write_str("?")?;
        }
        let query_params = self.query_params();
        for (key, val) in query_params.iter().take(1) {
            write!(
                f,
                "{}={}",
                utf8_percent_encode(key, QUERY_ENCODE),
                utf8_percent_encode(val, QUERY_ENCODE)
            )?;
        }
        for (key, val) in query_params.iter().skip(1) {
            write!(
                f,
                "&{}={}",
                utf8_percent_encode(key, QUERY_ENCODE),
                utf8_percent_encode(val, QUERY_ENCODE)
            )?;
        }
        Ok(())
    }
}

impl FromStr for RgbInvoice {
    type Err = InvoiceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = Uri::parse(s)?;

        let scheme = uri.scheme().ok_or(InvoiceParseError::Invalid)?.to_string();
        if scheme != "rgb" {
            return Err(InvoiceParseError::InvalidScheme(scheme));
        }

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
            Err(_) if contract_id_str == &OMITTED.to_string() => None,
            Err(_) => return Err(InvoiceParseError::InvalidContractId(contract_id_str.clone())),
        };
        next_path_index += 1;

        let iface_str = &path[next_path_index];
        let iface = match TypeName::try_from(iface_str.clone()) {
            Ok(i) => Some(i),
            Err(_) if iface_str == &OMITTED.to_string() => None,
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

        let mut query_params = map_query_params(&uri)?;

        let transports = if let Some(endpoints) = query_params.remove(ENDPOINTS) {
            let tokens: Vec<&str> = endpoints.split(TRANSPORT_SEP).collect();
            let mut transport_vec: Vec<RgbTransport> = vec![];
            for token in tokens {
                transport_vec.push(
                    RgbTransport::from_str(token)
                        .map_err(|e| InvoiceParseError::InvalidQueryParam(e.to_string()))?,
                );
            }
            transport_vec
        } else {
            vec![RgbTransport::UnspecifiedMeans]
        };

        let mut expiry = None;
        if let Some(exp) = query_params.remove(EXPIRY) {
            let timestamp = exp
                .parse::<i64>()
                .map_err(|e| InvoiceParseError::InvalidExpiration(e.to_string()))?;
            expiry = Some(timestamp);
        }

        Ok(RgbInvoice {
            transports,
            contract,
            iface,
            operation: None,
            assignment: None,
            beneficiary,
            owned_state: value,
            chain,
            expiry,
            unknown_query: query_params,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse() {
        // all path parameters
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // no amount
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // no contract ID
        let invoice_str = "rgb:~/RGB20/6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // no contract ID nor iface
        let invoice_str = "rgb:~/~/6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // contract ID provided but no iface
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/~/\
                           6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::ContractIdNoIface)));

        // invalid contract ID
        let invalid_contract_id = "invalid";
        let invoice_str =
            format!("rgb:{invalid_contract_id}/RGB20/6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve");
        let result = RgbInvoice::from_str(&invoice_str);
        assert!(matches!(result,
                Err(InvoiceParseError::InvalidContractId(c)) if c == invalid_contract_id));

        // with expiration
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?expiry=1682086371";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // bad expiration
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?expiry=six";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidExpiration(_))));

        // with bad query parameter
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?expiry";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // with an unknown query parameter
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?unknown=new";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // with two unknown query parameters
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?unknown=new&\
                           another=new";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // with expiration and an unknown query parameter
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?expiry=1682086371&\
                           unknown=new";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // with an unknown query parameter containing percent-encoded text
        let invoice_base = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                            100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?";
        let query_key_encoded = ":@-%20%23";
        let query_key_decoded = ":@- #";
        let query_val_encoded = "?/.%26%3D";
        let query_val_decoded = "?/.&=";
        let invoice =
            RgbInvoice::from_str(&format!("{invoice_base}{query_key_encoded}={query_val_encoded}"))
                .unwrap();
        let query_params = invoice.query_params();
        assert_eq!(query_params[query_key_decoded], query_val_decoded);
        assert_eq!(
            invoice.to_string(),
            format!("{invoice_base}{query_key_encoded}={query_val_encoded}")
        );

        // no scheme
        let invoice_str = "EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/~/\
                           6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::Invalid)));

        // invalid scheme
        let invoice_str = "bad:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/~/\
                           6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidScheme(_))));

        // empty transport endpoint specification
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // invalid transport endpoint specification
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=bad";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // invalid transport variant
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=rpca://host.\
                           example.com";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // rgb-rpc variant
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=rpc://host.\
                           example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.transports, vec![RgbTransport::JsonRpc {
            tls: false,
            host: "host.example.com".to_string()
        }]);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb-rpc variant, host containing authentication, "-" characters and port
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=rpcs://user:\
                           pass@host-1.ex-ample.com:1234";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.transports, vec![RgbTransport::JsonRpc {
            tls: true,
            host: "user:pass@host-1.ex-ample.com:1234".to_string()
        }]);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb-rpc variant, IPv6 host
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=rpcs://%\
                           5B2001:db8::1%5D:1234";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.transports, vec![RgbTransport::JsonRpc {
            tls: true,
            host: "[2001:db8::1]:1234".to_string()
        }]);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb-rpc variant with missing host
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=rpc://";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // rgb-rpc variant with invalid separator
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=rpc/host.\
                           example.com";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // rgb-rpc variant with invalid transport host specification
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=rpc://ho]t";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::Uri(_))));

        // rgb+http variant
        let invoice_str = "rgb:\
                           EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=https://\
                           host.example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        let transports = vec![RgbTransport::RestHttp {
            tls: true,
            host: "host.example.com".to_string(),
        }];
        assert_eq!(invoice.transports, transports);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb+ws variant
        let invoice_str = "rgb:EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=wss://host.\
                           example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        let transports = vec![RgbTransport::WebSockets {
            tls: true,
            host: "host.example.com".to_string(),
        }];
        assert_eq!(invoice.transports, transports);
        assert_eq!(invoice.to_string(), invoice_str);

        // TODO: rgb+storm variant

        // multiple transports
        let invoice_str = "rgb:\
                           EKkb7TMfbPxzn7UhvXqhoCutzdZkSZCNYxVAVjsA67fW/RGB20/\
                           100+6kzbKKffP6xftkxn9UP8gWqiC41W16wYKE5CYaVhmEve?endpoints=rpcs://\
                           host1.example.com,http://host2.example.com,ws://host3.example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        let transports = vec![
            RgbTransport::JsonRpc {
                tls: true,
                host: "host1.example.com".to_string(),
            },
            RgbTransport::RestHttp {
                tls: false,
                host: "host2.example.com".to_string(),
            },
            RgbTransport::WebSockets {
                tls: false,
                host: "host3.example.com".to_string(),
            },
        ];
        assert_eq!(invoice.transports, transports);
        assert_eq!(invoice.to_string(), invoice_str);

        // empty transport parse error
        let result = RgbTransport::from_str("");
        assert!(matches!(result, Err(TransportParseError::InvalidTransport(_))));

        // invalid transport parse error
        let result = RgbTransport::from_str("bad");
        assert!(matches!(result, Err(TransportParseError::InvalidTransport(_))));

        // invalid transport variant parse error
        let result = RgbTransport::from_str("rpca://host.example.com");
        assert!(matches!(result, Err(TransportParseError::InvalidTransport(_))));

        // rgb-rpc variant with missing host parse error
        let result = RgbTransport::from_str("rpc://");
        assert!(matches!(result, Err(TransportParseError::InvalidTransportHost(_))));

        // rgb-rpc variant with invalid separator parse error
        let result = RgbTransport::from_str("rpc/host.example.com");
        assert!(matches!(result, Err(TransportParseError::InvalidTransport(_))));
    }
}
