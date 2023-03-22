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

use indexmap::IndexMap;
use rgb::{AttachId, ContractId, SecretSeal};
use strict_encoding::TypeName;

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

#[derive(Clone, Eq, PartialEq, Debug, Display)]
// TODO: Change to custom display impl providing support for optionals & query
#[display("{transport}{contract}/{iface}/{value}@{seal}")]
pub struct RgbInvoice {
    pub transport: RgbTransport,
    pub contract: ContractId,
    pub iface: TypeName,
    pub operation: Option<TypeName>,
    pub assignment: Option<TypeName>,
    pub owned_state: Option<String>,
    pub seal: SecretSeal,
    pub value: u64, // TODO: Change to TypedState
    pub unknown_query: IndexMap<String, String>,
}
