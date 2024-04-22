// RGB standard library for working with smart contracts on Bitcoin & Lightning
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

use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use amplify::confinement::{SmallBlob, TinyOrdMap, TinyString};
use amplify::{ByteArray, Bytes32};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use commit_verify::{CommitId, CommitmentId, DigestExt, Sha256};
use rgb::{impl_serde_baid58, AssignmentType, ContractId, GlobalStateType};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::value;

use crate::LIB_NAME_RGB_STD;

/// Contract supplement identifier.
///
/// Contract supplement identifier commits to all of the supplement data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct SupplId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for SupplId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for SupplId {
    const TAG: &'static str = "urn:lnp-bp:rgb:suppl#2024-03-11";
}

impl ToBaid58<32> for SupplId {
    const HRI: &'static str = "suppl";
    const CHUNKING: Option<Chunking> = CHUNKING_32;
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_byte_array() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for SupplId {}
impl Display for SupplId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("urn:lnp-bp:suppl:")?;
        }
        if f.sign_minus() {
            write!(f, "{:.2}", self.to_baid58())
        } else {
            write!(f, "{:#.2}", self.to_baid58())
        }
    }
}
impl FromStr for SupplId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_baid58_maybe_chunked_str(s.trim_start_matches("urn:lnp-bp:"), ':', '#')
    }
}
impl SupplId {
    pub const fn from_array(id: [u8; 32]) -> Self { Self(Bytes32::from_array(id)) }
    pub fn to_mnemonic(&self) -> String { self.to_baid58().mnemonic() }
}

impl_serde_baid58!(SupplId);

/// Contract supplement, providing non-consensus information about standard
/// way of working with the contract data. Each contract can have only a single
/// valid supplement; the supplement is attached to the contract via trusted
/// provider signature (providers are ordered by the priority).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = SupplId)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractSuppl {
    pub contract_id: ContractId,
    pub ticker: TickerSuppl,
    /// Media kit is a URL string which provides JSON information on media files
    /// and colors that should be used for UI,
    pub media_kit: TinyString,
    pub global_state: TinyOrdMap<AssignmentType, OwnedStateSuppl>,
    pub owned_state: TinyOrdMap<AssignmentType, OwnedStateSuppl>,
    /// TLV-encoded custom fields.
    pub extensions: TinyOrdMap<u16, SmallBlob>,
}

impl StrictSerialize for ContractSuppl {}
impl StrictDeserialize for ContractSuppl {}

impl ContractSuppl {
    pub fn suppl_id(&self) -> SupplId { self.commit_id() }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum TickerSuppl {
    #[strict_type(tag = 0, dumb)]
    Absent,
    #[strict_type(tag = 1)]
    Global(GlobalStateType, value::Path),
    #[strict_type(tag = 2)]
    Owned(AssignmentType, value::Path),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct OwnedStateSuppl {
    pub meaning: TinyString,
    pub velocity: VelocityHint,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, try_from_u8, into_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(lowercase)]
#[repr(u8)]
pub enum VelocityHint {
    #[default]
    Unspecified = 0,
    /// Should be used for thinks like secondary issuance for tokens which do
    /// not inflate very often.
    Seldom = 15,
    /// Should be used for digital identity revocations.
    Episodic = 31,
    /// Should be used for digital art, shares, bonds etc.
    Regular = 63,
    /// Should be used for fungible tokens.
    Frequent = 127,
    /// Should be used for stablecoins and money.
    HighFrequency = 255,
}

impl VelocityHint {
    pub fn with_value(value: &u8) -> Self {
        match *value {
            0 => VelocityHint::Unspecified,
            1..=15 => VelocityHint::Seldom,
            16..=31 => VelocityHint::Episodic,
            32..=63 => VelocityHint::Regular,
            64..=127 => VelocityHint::Frequent,
            128..=255 => VelocityHint::HighFrequency,
        }
    }
}
