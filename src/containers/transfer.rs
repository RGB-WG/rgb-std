// RGB standard library for working with smart contracts on Bitcoin & Lightning
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

use std::io;
use std::str::FromStr;

use amplify::confinement::SmallOrdSet;
use amplify::{ByteArray, Bytes32};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use commit_verify::{CommitEncode, CommitmentId, Conceal};
use strict_encoding::{StrictEncode, StrictWriter};

use crate::containers::{TerminalSeal, Transfer};
use crate::LIB_NAME_RGB_STD;

/// Transfer identifier.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_baid58_string)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct TransferId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl ToBaid58<32> for TransferId {
    const HRI: &'static str = "consign";
    const CHUNKING: Option<Chunking> = CHUNKING_32;
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_byte_array() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for TransferId {}
impl FromStr for TransferId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid58_chunked_str(s, ':', '#') }
}
#[allow(clippy::wrong_self_convention)] // We need the method that takes self by ref in order to have simpler APIs in iterators
impl TransferId {
    pub fn to_baid58_string(&self) -> String { format!("{::<#.2}", self.to_baid58()) }
    pub fn to_mnemonic(&self) -> String { self.to_baid58().mnemonic() }
}

impl CommitEncode for Transfer {
    fn commit_encode(&self, e: &mut impl io::Write) {
        let write = || -> Result<_, io::Error> {
            let mut writer = StrictWriter::with(usize::MAX, e);
            writer = self.transfer.strict_encode(writer)?;
            writer = self.contract_id().strict_encode(writer)?;
            for (bundle_id, terminal) in &self.terminals {
                writer = bundle_id.strict_encode(writer)?;
                let seals = SmallOrdSet::try_from_iter(
                    terminal
                        .as_reduced_unsafe()
                        .seals
                        .iter()
                        .map(TerminalSeal::conceal),
                )
                .expect("same size iterator");
                writer = seals.strict_encode(writer)?;
            }
            for attach_id in self.attachments.keys() {
                writer = attach_id.strict_encode(writer)?;
            }
            self.signatures.strict_encode(writer)?;
            Ok(())
        };
        write().expect("hashers do not error");
    }
}

impl CommitmentId for Transfer {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:transfer:v01#2303A";
    type Id = TransferId;
}

impl Transfer {
    #[inline]
    pub fn transfer_id(&self) -> TransferId { self.commitment_id() }
}
