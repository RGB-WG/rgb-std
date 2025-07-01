// RGB wallet library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
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

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{Cursor, Write};
use std::num::ParseIntError;
use std::str::FromStr;

use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use bp::InternalPk;
use fluent_uri::encoding::encoder::Query;
use fluent_uri::encoding::EStr;
use fluent_uri::Uri;
use indexmap::IndexMap;
use invoice::{AddressPayload, UnknownNetwork};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rgb::{ChainNet, ContractId, SchemaId, SecretSeal};
use strict_types::FieldName;

use crate::invoice::{Beneficiary, InvoiceState, Pay2Vout, RgbInvoice, RgbTransport, XChainNet};

const OMITTED: &str = "~";
const ASSIGNMENT: &str = "assignment_name";
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

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum InvoiceParseError {
    /// invalid invoice.
    Invalid,

    /// RGB invoice must not contain any URI authority data, including empty
    /// one.
    Authority,

    /// contract id is missing from the invoice.
    ContractMissing,

    /// schema information is missing from the invoice.
    SchemaMissing,

    /// assignment state is missing from the invoice.
    AssignmentStateMissing,

    /// beneficiary is missing from the invoice.
    BeneficiaryMissing,

    /// invalid invoice scheme {0}.
    InvalidScheme(String),

    /// no invoice transport has been provided.
    NoTransport,

    /// invalid contract ID.
    InvalidContractId(String),

    /// invalid schema {0}.
    InvalidSchemaId(String),

    /// invalid assignment state {0}.
    InvalidAssignmentState(String),

    /// invalid assignment name {0}.
    InvalidAssignmentName(String),

    /// invalid expiration timestamp {0}.
    InvalidExpiration(String),

    #[display(inner)]
    #[from]
    InvalidNetwork(UnknownNetwork),

    /// invalid query parameter {0}.
    InvalidQueryParam(String),

    /// can't recognize beneficiary "{0}": it should be either a bitcoin address
    /// or a blinded UTXO seal.
    Beneficiary(String),

    #[from]
    #[display(inner)]
    Num(ParseIntError),

    /// can't recognize amount "{0}": it should be valid allocation data.
    Data(String),
}

impl RgbInvoice {
    fn has_params(&self) -> bool {
        self.expiry.is_some()
            || self.assignment_name.is_some()
            || self.transports != vec![RgbTransport::UnspecifiedMeans]
            || !self.unknown_query.is_empty()
    }

    fn query_params(&self) -> IndexMap<String, String> {
        let mut query_params: IndexMap<String, String> = IndexMap::new();
        if let Some(ref assignment) = self.assignment_name {
            query_params.insert(ASSIGNMENT.to_string(), assignment.to_string());
        }
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

impl Display for RgbTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RgbTransport::JsonRpc { tls, host } => {
                let s = if *tls { "s" } else { "" };
                write!(f, "rpc{s}{TRANSPORT_HOST_SEP}{host}")?;
            }
            RgbTransport::RestHttp { tls, host } => {
                let s = if *tls { "s" } else { "" };
                write!(f, "http{s}{TRANSPORT_HOST_SEP}{host}")?;
            }
            RgbTransport::WebSockets { tls, host } => {
                let s = if *tls { "s" } else { "" };
                write!(f, "ws{s}{TRANSPORT_HOST_SEP}{host}")?;
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

impl Display for XChainNet<Beneficiary> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.chain_network().prefix())?;
        match self.into_inner() {
            Beneficiary::BlindedSeal(seal) => Display::fmt(&seal, f),
            Beneficiary::WitnessVout(pay2vout, internal_pk) => {
                write!(
                    f,
                    "{}{}",
                    pay2vout.to_baid64_string(),
                    if let Some(ipk) = internal_pk { format!("+{ipk}") } else { s!("") }
                )
            }
        }
    }
}

impl DisplayBaid64<33> for Pay2Vout {
    const HRI: &'static str = "wvout";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = true;
    const MNEMONIC: bool = false;

    fn to_baid64_payload(&self) -> [u8; 33] {
        let mut payload = [0u8; 33];
        // tmp stack array to store the tr payload to resolve lifetime issue
        let schnorr_pk: [u8; 32];
        let (addr_type, spk) = match &**self {
            AddressPayload::Pkh(pkh) => (Self::P2PKH, pkh.as_ref()),
            AddressPayload::Sh(sh) => (Self::P2SH, sh.as_ref()),
            AddressPayload::Wpkh(wpkh) => (Self::P2WPKH, wpkh.as_ref()),
            AddressPayload::Wsh(wsh) => (Self::P2WSH, wsh.as_ref()),
            AddressPayload::Tr(tr) => {
                schnorr_pk = tr.to_byte_array();
                (Self::P2TR, &schnorr_pk[..])
            }
        };
        payload[0] = addr_type;
        Cursor::new(&mut payload[1..])
            .write_all(spk)
            .expect("address payload always less than 32 bytes");
        payload
    }
}

impl Display for Pay2Vout {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}
impl FromBaid64Str<33> for Pay2Vout {}
impl FromStr for Pay2Vout {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}

impl FromStr for XChainNet<Beneficiary> {
    type Err = InvoiceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((cn, beneficiary)) = s.split_once(':') else {
            return Err(InvoiceParseError::Beneficiary(s!("missing beneficiary HRI")));
        };
        let cn =
            ChainNet::from_str(cn).map_err(|e| InvoiceParseError::Beneficiary(e.to_string()))?;
        if let Ok(seal) = SecretSeal::from_str(beneficiary) {
            return Ok(XChainNet::with(cn, Beneficiary::BlindedSeal(seal)));
        }

        let (pay2vout, internal_pk) = beneficiary
            .split_once("+")
            .map(|(p, i)| (p, Some(i)))
            .unwrap_or((beneficiary, None));

        let pay2vout = Pay2Vout::from_str(pay2vout)
            .map_err(|e| InvoiceParseError::Beneficiary(e.to_string()))?;

        let internal_pk = match internal_pk {
            None => None,
            Some(i) => {
                if i.is_empty() {
                    return Err(InvoiceParseError::Beneficiary(s!("missing internal pk")));
                }
                Some(
                    InternalPk::from_str(i)
                        .map_err(|_| InvoiceParseError::Beneficiary(s!("invalid internal pk")))?,
                )
            }
        };

        Ok(XChainNet::with(cn, Beneficiary::WitnessVout(pay2vout, internal_pk)))
    }
}

impl Display for RgbInvoice {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if let Some(contract) = self.contract {
            let id = if f.alternate() {
                contract.to_string().replace('-', "")
            } else {
                contract.to_string()
            };
            write!(f, "{id}/")?;
        } else {
            write!(f, "rgb:{OMITTED}/")?;
        }
        if let Some(schema) = self.schema {
            let schema_str = format!("{schema:-#}");
            let id = if f.alternate() { schema_str.replace('-', "") } else { schema_str };
            write!(f, "{id}/")?;
        } else {
            write!(f, "{OMITTED}/")?;
        }
        if let Some(ref assignment_state) = self.assignment_state {
            write!(f, "{assignment_state}/")?;
        } else {
            write!(f, "{OMITTED}/")?;
        }
        let beneficiary = if f.alternate() {
            self.beneficiary.to_string().replace('-', "")
        } else {
            self.beneficiary.to_string()
        };
        f.write_str(&beneficiary)?;
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
        let uri = Uri::parse(s).map_err(|_| InvoiceParseError::Invalid)?;

        let scheme = uri.scheme();
        if scheme.as_str() != "rgb" {
            return Err(InvoiceParseError::InvalidScheme(scheme.to_string()));
        }

        let path = uri.path();
        if path.is_absolute() || uri.authority().is_some() {
            return Err(InvoiceParseError::Authority);
        }

        let mut path = path.split('/');

        let Some(contract_id_str) = path.next() else {
            return Err(InvoiceParseError::ContractMissing);
        };
        let contract = match ContractId::from_str(contract_id_str.as_str()) {
            Ok(cid) => Some(cid),
            Err(_) if contract_id_str.as_str() == OMITTED => None,
            Err(_) => {
                return Err(InvoiceParseError::InvalidContractId(contract_id_str.to_string()));
            }
        };

        let Some(schema_str) = path.next() else {
            return Err(InvoiceParseError::SchemaMissing);
        };
        let schema = match SchemaId::from_str(schema_str.as_ref()) {
            Ok(i) => Some(i),
            Err(_) if schema_str.as_str() == OMITTED => None,
            Err(_) => return Err(InvoiceParseError::InvalidSchemaId(schema_str.to_string())),
        };

        let Some(assignment_str) = path.next() else {
            return Err(InvoiceParseError::AssignmentStateMissing);
        };
        let assignment_state = match InvoiceState::from_str(assignment_str.as_ref()) {
            Ok(i) => Some(i),
            Err(_) if assignment_str.as_str() == OMITTED => None,
            Err(_) => {
                return Err(InvoiceParseError::InvalidAssignmentState(assignment_str.to_string()))
            }
        };

        let Some(beneficiary_str) = path.next() else {
            return Err(InvoiceParseError::BeneficiaryMissing);
        };
        let beneficiary = XChainNet::<Beneficiary>::from_str(beneficiary_str.as_ref())?;
        let mut query_params = map_query_params(&uri)?;

        let transports = if let Some(endpoints) = query_params.shift_remove(ENDPOINTS) {
            let tokens = endpoints.split(TRANSPORT_SEP);
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

        let mut assignment_name = None;
        if let Some(assignment) = query_params.shift_remove(ASSIGNMENT) {
            let name = FieldName::try_from(assignment.clone())
                .map_err(|_| InvoiceParseError::InvalidAssignmentName(assignment))?;
            assignment_name = Some(name);
        }

        let mut expiry = None;
        if let Some(exp) = query_params.shift_remove(EXPIRY) {
            let timestamp = exp
                .parse::<i64>()
                .map_err(|e| InvoiceParseError::InvalidExpiration(e.to_string()))?;
            expiry = Some(timestamp);
        }

        Ok(RgbInvoice {
            transports,
            contract,
            schema,
            assignment_name,
            beneficiary,
            assignment_state,
            expiry,
            unknown_query: query_params,
        })
    }
}

fn percent_decode(estr: &EStr<Query>) -> Result<String, InvoiceParseError> {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Allocation, Amount, NonFungible};

    #[test]
    fn parse() {
        // nia parameters
        let invoice_str = "rgb:eIbQx5Am-XRDjj01-RM~5eo7-rv2nluD-OnBJRAy-S9~Yfts/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.assignment_state, Some(InvoiceState::Amount(Amount::from(100u64))));
        assert_eq!(invoice.to_string(), invoice_str);
        assert_eq!(format!("{invoice:#}"), invoice_str.replace('-', ""));

        // uda parameters
        let invoice_str = "rgb:tx8NOyGe-NkPZex~-U0J_1om-CfrOeoO-7di9xZb-vT3nxyo/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/1@0/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(
            invoice.assignment_state,
            Some(InvoiceState::Data(NonFungible::FractionedToken(Allocation::with(0, 1))))
        );
        assert_eq!(invoice.to_string(), invoice_str);
        assert_eq!(format!("{invoice:#}"), invoice_str.replace('-', ""));

        // witness vout without internal pk
        let invoice_str = "rgb:eIbQx5Am-XRDjj01-RM~5eo7-rv2nluD-OnBJRAy-S9~Yfts/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/Sa/bc:wvout:\
                           A8cJ7Ww3-NIzADo3-Tzp_5aD-7CTBWmA-AAAAAAA-AAAAAAA-ALSQkcw";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // witness vout with internal pk
        let invoice_str = "rgb:eIbQx5Am-XRDjj01-RM~5eo7-rv2nluD-OnBJRAy-S9~Yfts/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/Sa/bc:wvout:\
                           A8cJ7Ww3-NIzADo3-Tzp_5aD-7CTBWmA-AAAAAAA-AAAAAAA-ALSQkcw\
                           +750f58bcca0fdb11891e7979d829b8c56e0963dba08c44f54a256cf7dbc09caf";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // no amount
        let invoice_str = "rgb:eIbQx5Am-XRDjj01-RM~5eo7-rv2nluD-OnBJRAy-S9~Yfts/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/~/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.assignment_state, None);
        assert_eq!(invoice.to_string(), invoice_str);

        // no allocation
        let invoice_str = "rgb:eIbQx5Am-XRDjj01-RM~5eo7-rv2nluD-OnBJRAy-S9~Yfts/\
                           V8ujLLtH2k2QSmaDpZI3o06ACIm2UNT0TZl11FiqRuY/~/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.assignment_state, None);
        assert_eq!(invoice.to_string(), invoice_str);

        // no contract ID
        let invoice_str = "rgb:~/XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/~/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // no contract ID nor schema
        let invoice_str =
            "rgb:~/~/~/bc:utxob:4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // contract ID provided but no schema
        let invoice_str = "rgb:eIbQx5Am-XRDjj01-RM~5eo7-rv2nluD-OnBJRAy-S9~Yfts/~/~/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // invalid contract ID
        let invalid_contract_id = "invalid";
        let invoice_str = format!(
            "rgb:{invalid_contract_id}/XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/bc:utxob:\
             4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa"
        );
        let result = RgbInvoice::from_str(&invoice_str);
        assert!(matches!(result,
                Err(InvoiceParseError::InvalidContractId(c)) if c == invalid_contract_id));

        // with assignment name
        let assignment_name = "assetOwner";
        let invoice_str = format!(
            "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
             XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
             4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?{ASSIGNMENT}={assignment_name}"
        );
        let invoice = RgbInvoice::from_str(&invoice_str).unwrap();
        assert_eq!(invoice.assignment_name, Some(FieldName::from(assignment_name)));
        assert_eq!(invoice.to_string(), invoice_str);

        // bad assignment_name
        let assignment_name = "";
        let invoice_str = format!(
            "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
             XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
             4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?{ASSIGNMENT}={assignment_name}"
        );
        let result = RgbInvoice::from_str(&invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidAssignmentName(_))));

        // with expiration
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?\
                           expiry=1682086371";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // bad expiration
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?expiry=six";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidExpiration(_))));

        // with bad query parameter
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?expiry";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // with an unknown query parameter
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?unknown=new";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // with two unknown query parameters
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?unknown=new&\
                           another=new";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // with expiration and an unknown query parameter
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?\
                           expiry=1682086371&unknown=new";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // with an unknown query parameter containing percent-encoded text
        let invoice_base = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                            XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                            4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?";
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
        let invoice_str = "eIbQx5Am-XRDjj01-RM~5eo7-rv2nluD-OnBJRAy-S9~Yfts/~/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::Invalid)));

        // invalid scheme
        let invoice_str = "bad:2WBcas9-yjzEvGufY-9GEgnyMj7-beMNMWA8r-sPHtV1nPU-TMsGMQX/~/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidScheme(_))));

        // empty transport endpoint specification
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // invalid transport endpoint specification
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=bad";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // invalid transport variant
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=rpca:/\
                           /host.example.com";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // rgb-rpc variant
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=rpc://\
                           host.example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.transports, vec![RgbTransport::JsonRpc {
            tls: false,
            host: "host.example.com".to_string()
        }]);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb-rpc variant, host containing authentication, "-" characters and port
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=rpcs:/\
                           /user:pass@host-1.ex-ample.com:1234";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.transports, vec![RgbTransport::JsonRpc {
            tls: true,
            host: "user:pass@host-1.ex-ample.com:1234".to_string()
        }]);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb-rpc variant, IPv6 host
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=rpcs:/\
                           /%5B2001:db8::1%5D:1234";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.transports, vec![RgbTransport::JsonRpc {
            tls: true,
            host: "[2001:db8::1]:1234".to_string()
        }]);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb-rpc variant with missing host
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=rpc://";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // rgb-rpc variant with invalid separator
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=rpc/\
                           host.example.com";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // rgb-rpc variant with invalid transport host specification
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=rpc://\
                           ho]t";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::Invalid)));

        // rgb+http variant
        let invoice_str = "rgb:\
                           3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/\
                           BF/bc:utxob:4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=https://\
                           host.example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        let transports = vec![RgbTransport::RestHttp {
            tls: true,
            host: "host.example.com".to_string(),
        }];
        assert_eq!(invoice.transports, transports);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb+ws variant
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=wss://\
                           host.example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        let transports = vec![RgbTransport::WebSockets {
            tls: true,
            host: "host.example.com".to_string(),
        }];
        assert_eq!(invoice.transports, transports);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb+storm variant
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=storm:\
                           //_/";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        let transports = vec![RgbTransport::Storm {}];
        assert_eq!(invoice.transports, transports);
        assert_eq!(invoice.to_string(), invoice_str);

        // multiple transports
        let invoice_str = "rgb:\
                           3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/\
                           BF/bc:utxob:4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?endpoints=rpcs://\
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

        // invalid witness vout: invalid length of identifier wvout
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:wvout:\
                           +750f58bcca0fdb11891e7979d829b8c56e0963dba08c44f54a256cf7dbc09caf";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::Beneficiary(_))));

        // invalid witness vout: missing beneficiary HRI
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/\
                           750f58bcca0fdb11891e7979d829b8c56e0963dba08c44f54a256cf7dbc09caf";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::Beneficiary(_))));

        // invalid witness vout: invalid chain-network pair
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/:\
                           +750f58bcca0fdb11891e7979d829b8c56e0963dba08c44f54a256cf7dbc09caf";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::Beneficiary(_))));

        // invalid witness vout: invalid internal pk
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:wvout:\
                           BYWmQlmL-$i5Co3j-LtTvxSr-53!\
                           Brv7-fc7ZntC-ha988ci-jqKOj4Q+750f58bcca0fdb11891e7979";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::Beneficiary(_))));

        // invalid witness vout: missing internal pk
        let invoice_str = "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:wvout:\
                           BYWmQlmL-$i5Co3j-LtTvxSr-53!Brv7-fc7ZntC-ha988ci-jqKOj4Q+";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::Beneficiary(_))));
    }

    #[test]
    fn pay2vout_parse() {
        let p = Pay2Vout::new(AddressPayload::Pkh([0xff; 20].into()));
        assert_eq!(Pay2Vout::from_str(&p.to_string()).unwrap(), p);

        let p = Pay2Vout::new(AddressPayload::Sh([0xff; 20].into()));
        assert_eq!(Pay2Vout::from_str(&p.to_string()).unwrap(), p);

        let p = Pay2Vout::new(AddressPayload::Wpkh([0xff; 20].into()));
        assert_eq!(Pay2Vout::from_str(&p.to_string()).unwrap(), p);

        let p = Pay2Vout::new(AddressPayload::Wsh([0xff; 32].into()));
        assert_eq!(Pay2Vout::from_str(&p.to_string()).unwrap(), p);

        let p = Pay2Vout::new(AddressPayload::Tr(
            bp::OutputPk::from_byte_array([
                0x85, 0xa6, 0x42, 0x59, 0x8b, 0xfe, 0x2e, 0x42, 0xa3, 0x78, 0xcb, 0xb5, 0x3b, 0xf1,
                0x4a, 0xbe, 0x77, 0xf8, 0x1a, 0xef, 0xed, 0xf7, 0x3b, 0x66, 0x7b, 0x42, 0x85, 0xaf,
                0x7c, 0xf1, 0xc8, 0xa3,
            ])
            .unwrap(),
        ));
        assert_eq!(Pay2Vout::from_str(&p.to_string()).unwrap(), p);
    }
}
