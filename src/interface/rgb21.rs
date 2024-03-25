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

#![allow(unused_braces)]

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::str::FromStr;

use amplify::ascii::AsciiString;
use amplify::confinement::{Confined, NonEmptyVec, SmallBlob};
use bp::bc::stl::bp_tx_stl;
use bp::dbc::Method;
use rgb::{AltLayer1, AssetTag, DataState, GenesisSeal};
use strict_encoding::stl::AsciiPrintable;
use strict_encoding::{
    InvalidIdent, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, TypedWrite,
};
use strict_types::stl::std_stl;
use strict_types::{CompileError, LibBuilder, StrictVal, TypeLib};

use super::{
    AssignIface, ContractBuilder, DataAllocation, GenesisIface, GlobalIface, Iface, IssuerClass,
    OutpointFilter, OwnedIface, Req, SchemaIssuer, TransitionIface, VerNo,
};
use crate::containers::Contract;
use crate::interface::{
    ArgSpec, BuilderError, ContractIface, IfaceClass, IfaceId, IfaceWrapper, TxOutpoint,
};
use crate::invoice::Precision;
use crate::persistence::PersistedState;
use crate::stl::{
    rgb_contract_stl, Attachment, Details, DivisibleAssetSpec, MediaType, Name, ProofOfReserves,
    RicardianContract, StandardTypes, Ticker, Timestamp,
};

pub const LIB_NAME_RGB21: &str = "RGB21";
/// Strict types id for the library providing data types for RGB21 interface.
pub const LIB_ID_RGB21: &str =
    "urn:ubideco:stl:7kUn2VT5xKgZWCAYsa7usNsKWtQBrvyg1pdxRGtendf#tarzan-riviera-vampire";

#[derive(
    Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From
)]
#[wrapper(Display, FromStr, Add, Sub, Mul, Div, Rem)]
#[wrapper_mut(AddAssign, SubAssign, MulAssign, DivAssign, RemAssign)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ItemsCount(u32);

#[derive(
    Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From
)]
#[wrapper(Display, FromStr, Add, Sub, Mul, Div, Rem)]
#[wrapper_mut(AddAssign, SubAssign, MulAssign, DivAssign, RemAssign)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct TokenIndex(u32);

#[derive(
    Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From
)]
#[wrapper(Display, FromStr, Add, Sub, Mul, Div, Rem)]
#[wrapper_mut(AddAssign, SubAssign, MulAssign, DivAssign, RemAssign)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct OwnedFraction(u64);

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Allocation(TokenIndex, OwnedFraction);

impl Allocation {
    pub fn with(index: TokenIndex, fraction: OwnedFraction) -> Allocation {
        Allocation(index, fraction)
    }

    pub fn token_index(self) -> TokenIndex { self.0 }

    pub fn fraction(self) -> OwnedFraction { self.1 }
}

impl StrictSerialize for Allocation {}
impl StrictDeserialize for Allocation {}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct EngravingData {
    pub applied_to: TokenIndex,
    pub content: EmbeddedMedia,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct EmbeddedMedia {
    #[strict_type(rename = "type")]
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub ty: MediaType,
    pub data: SmallBlob,
}

impl EmbeddedMedia {
    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let ty = MediaType::from_strict_val_unchecked(value.unwrap_struct("type"));
        let data =
            SmallBlob::from_collection_unsafe(value.unwrap_struct("data").unwrap_bytes().into());

        Self { ty, data }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21, dumb = { AttachmentType::with(0, "dumb") })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AttachmentType {
    pub id: u8,
    pub name: AttachmentName,
}

impl AttachmentType {
    pub fn with(id: u8, name: &'static str) -> AttachmentType {
        AttachmentType {
            id,
            name: AttachmentName::from(name),
        }
    }
}

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, From)]
#[wrapper(Deref, Display)]
#[derive(StrictType, StrictDumb, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21, dumb = { AttachmentName::from("dumb") })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct AttachmentName(Confined<AsciiString, 1, 20>);
impl StrictEncode for AttachmentName {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> std::io::Result<W> {
        let iter = self
            .0
            .as_bytes()
            .iter()
            .map(|c| AsciiPrintable::try_from(*c).unwrap());
        writer
            .write_newtype::<Self>(&NonEmptyVec::<AsciiPrintable, 20>::try_from_iter(iter).unwrap())
    }
}

// TODO: Ensure all constructors filter invalid characters
impl FromStr for AttachmentName {
    type Err = InvalidIdent;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = AsciiString::from_ascii(s.as_bytes())?;
        let s = Confined::try_from_iter(s.chars())?;
        Ok(Self(s))
    }
}

impl From<&'static str> for AttachmentName {
    fn from(s: &'static str) -> Self { Self::from_str(s).expect("invalid attachment name") }
}

impl TryFrom<String> for AttachmentName {
    type Error = InvalidIdent;

    fn try_from(name: String) -> Result<Self, InvalidIdent> {
        let name = AsciiString::from_ascii(name.as_bytes())?;
        let s = Confined::try_from(name)?;
        Ok(Self(s))
    }
}

impl Debug for AttachmentName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AttachmentName")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TokenData {
    pub index: TokenIndex,
    pub ticker: Option<Ticker>,
    pub name: Option<Name>,
    pub details: Option<Details>,
    pub preview: Option<EmbeddedMedia>,
    pub media: Option<Attachment>,
    pub attachments: Confined<BTreeMap<u8, Attachment>, 0, 20>,
    pub reserves: Option<ProofOfReserves>,
}

impl StrictSerialize for TokenData {}
impl StrictDeserialize for TokenData {}

impl TokenData {
    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let index = TokenIndex(value.unwrap_struct("index").unwrap_num().unwrap_uint());
        let ticker = value
            .unwrap_struct("ticker")
            .unwrap_option()
            .map(|x| Ticker::from_str(&x.unwrap_string()).expect("invalid uda ticker"));

        let name = value
            .unwrap_struct("name")
            .unwrap_option()
            .map(|x| Name::from_str(&x.unwrap_string()).expect("invalid uda name"));

        let details = value
            .unwrap_struct("details")
            .unwrap_option()
            .map(|x| Details::from_str(&x.unwrap_string()).expect("invalid uda details"));

        let preview = value
            .unwrap_struct("preview")
            .unwrap_option()
            .map(EmbeddedMedia::from_strict_val_unchecked);
        let media = value
            .unwrap_struct("media")
            .unwrap_option()
            .map(Attachment::from_strict_val_unchecked);

        let attachments = if let StrictVal::Map(list) = value.unwrap_struct("attachments") {
            Confined::from_collection_unsafe(
                list.iter()
                    .map(|(k, v)| (k.unwrap_uint(), Attachment::from_strict_val_unchecked(v)))
                    .collect(),
            )
        } else {
            Confined::default()
        };

        let reserves = value
            .unwrap_struct("reserves")
            .unwrap_option()
            .map(ProofOfReserves::from_strict_val_unchecked);
        Self {
            index,
            ticker,
            name,
            details,
            preview,
            media,
            attachments,
            reserves,
        }
    }
}

const FRACTION_OVERFLOW: u8 = 1;
const NON_EQUAL_VALUES: u8 = 2;
const INVALID_PROOF: u8 = 3;
const INSUFFICIENT_RESERVES: u8 = 4;
const ISSUE_EXCEEDS_ALLOWANCE: u8 = 6;
const NON_FRACTIONAL_TOKEN: u8 = 7;
const NON_ENGRAVABLE_TOKEN: u8 = 8;
const INVALID_ATTACHMENT_TYPE: u8 = 9;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
pub enum Error {
    #[strict_type(dumb)]
    /// amount of token > 1
    FractionOverflow = FRACTION_OVERFLOW,
    NonEqualValues = NON_EQUAL_VALUES,
    InvalidProof = INVALID_PROOF,
    InsufficientReserves = INSUFFICIENT_RESERVES,
    IssueExceedsAllowance = ISSUE_EXCEEDS_ALLOWANCE,
    NonFractionalToken = NON_FRACTIONAL_TOKEN,
    NonEngravableToken = NON_ENGRAVABLE_TOKEN,
    InvalidAttachmentType = INVALID_ATTACHMENT_TYPE,
}

fn _rgb21_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB21), tiny_bset! {
        std_stl().to_dependency(),
        bp_tx_stl().to_dependency(),
        rgb_contract_stl().to_dependency()
    })
    .transpile::<TokenData>()
    .transpile::<EngravingData>()
    .transpile::<ItemsCount>()
    .transpile::<Allocation>()
    .transpile::<AttachmentType>()
    .transpile::<Error>()
    .compile()
}

/// Generates strict type library providing data types for RGB21 interface.
pub fn rgb21_stl() -> TypeLib { _rgb21_stl().expect("invalid strict type RGB21 library") }

pub fn rgb21() -> Iface {
    let types = StandardTypes::with(rgb21_stl());

    Iface {
        version: VerNo::V1,
        name: tn!("RGB21"),
        global_state: tiny_bmap! {
            fname!("spec") => GlobalIface::required(types.get("RGBContract.DivisibleAssetSpec")),
            fname!("terms") => GlobalIface::required(types.get("RGBContract.RicardianContract")),
            fname!("created") => GlobalIface::required(types.get("RGBContract.Timestamp")),
            fname!("tokens") => GlobalIface::none_or_many(types.get("RGB21.TokenData")),
            fname!("engravings") => GlobalIface::none_or_many(types.get("RGB21.EngravingData")),
            fname!("attachmentTypes") => GlobalIface::none_or_many(types.get("RGB21.AttachmentType")),
        },
        assignments: tiny_bmap! {
            fname!("inflationAllowance") => AssignIface::public(OwnedIface::Data(types.get("RGB21.ItemsCount")), Req::NoneOrMore),
            fname!("updateRight") => AssignIface::public(OwnedIface::Rights, Req::Optional),
            fname!("assetOwner") => AssignIface::private(OwnedIface::Data(types.get("RGB21.Allocation")), Req::NoneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            metadata: Some(types.get("RGBContract.IssueMeta")),
            global: tiny_bmap! {
                fname!("spec") => ArgSpec::required(),
                fname!("terms") => ArgSpec::required(),
                fname!("created") => ArgSpec::required(),
                fname!("tokens") => ArgSpec::many(),
                fname!("attachmentTypes") => ArgSpec::many(),
            },
            assignments: tiny_bmap! {
                fname!("assetOwner") => ArgSpec::many(),
                fname!("inflationAllowance") => ArgSpec::many(),
                fname!("updateRight") => ArgSpec::optional(),
            },
            valencies: none!(),
            errors: tiny_bset! {
                FRACTION_OVERFLOW,
                INVALID_PROOF,
                INSUFFICIENT_RESERVES,
                INVALID_ATTACHMENT_TYPE
            },
        },
        transitions: tiny_bmap! {
            tn!("Transfer") => TransitionIface {
                optional: false,
                metadata: None,
                globals: none!(),
                inputs: tiny_bmap! {
                    fname!("previous") => ArgSpec::from_non_empty("assetOwner"),
                },
                assignments: tiny_bmap! {
                    fname!("beneficiary") => ArgSpec::from_non_empty("assetOwner"),
                },
                valencies: none!(),
                errors: tiny_bset! {
                    NON_EQUAL_VALUES,
                    FRACTION_OVERFLOW,
                    NON_FRACTIONAL_TOKEN
                },
                default_assignment: Some(fname!("beneficiary")),
            },
            tn!("Engrave") => TransitionIface {
                optional: true,
                metadata: None,
                globals: tiny_bmap! {
                    fname!("engravings") => ArgSpec::required(),
                },
                inputs: tiny_bmap! {
                    fname!("previous") => ArgSpec::from_non_empty("assetOwner"),
                },
                assignments: tiny_bmap! {
                    fname!("beneficiary") => ArgSpec::from_non_empty("assetOwner"),
                },
                valencies: none!(),
                errors: tiny_bset! {
                    NON_EQUAL_VALUES,
                    FRACTION_OVERFLOW,
                    NON_FRACTIONAL_TOKEN,
                    NON_ENGRAVABLE_TOKEN
                },
                default_assignment: Some(fname!("beneficiary")),
            },
            tn!("Issue") => TransitionIface {
                optional: true,
                metadata: Some(types.get("RGBContract.IssueMeta")),
                globals: tiny_bmap! {
                    fname!("newTokens") => ArgSpec::from_many("tokens"),
                    fname!("newAttachmentTypes") => ArgSpec::from_many("attachmentTypes"),
                },
                inputs: tiny_bmap! {
                    fname!("used") => ArgSpec::from_non_empty("inflationAllowance"),
                },
                assignments: tiny_bmap! {
                    fname!("beneficiary") => ArgSpec::from_many("assetOwner"),
                    fname!("future") => ArgSpec::from_many("inflationAllowance"),
                },
                valencies: none!(),
                errors: tiny_bset! {
                    FRACTION_OVERFLOW,
                    INVALID_PROOF,
                    INSUFFICIENT_RESERVES,
                    INVALID_ATTACHMENT_TYPE,
                    ISSUE_EXCEEDS_ALLOWANCE,
                },
                default_assignment: Some(fname!("beneficiary")),
            },
            tn!("Rename") => TransitionIface {
                optional: true,
                metadata: None,
                globals: tiny_bmap! {
                    fname!("new") => ArgSpec::from_required("spec"),
                },
                inputs: tiny_bmap! {
                    fname!("used") => ArgSpec::from_required("updateRight"),
                },
                assignments: tiny_bmap! {
                    fname!("future") => ArgSpec::from_optional("updateRight"),
                },
                valencies: none!(),
                errors: none!(),
                default_assignment: Some(fname!("future")),
            },
        },
        extensions: none!(),
        error_type: types.get("RGB21.Error"),
        default_operation: Some(tn!("Transfer")),
        type_system: types.type_system(),
    }
}

#[derive(Wrapper, WrapperMut, Clone, Eq, PartialEq, Debug)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
pub struct Rgb21(ContractIface);

impl From<ContractIface> for Rgb21 {
    fn from(iface: ContractIface) -> Self {
        if iface.iface.iface_id != Rgb21::IFACE_ID {
            panic!("the provided interface is not RGB20 interface");
        }
        Self(iface)
    }
}

impl IfaceWrapper for Rgb21 {
    const IFACE_NAME: &'static str = LIB_NAME_RGB21;
    const IFACE_ID: IfaceId = IfaceId::from_array([
        0xfc, 0xdb, 0xa8, 0x94, 0x6c, 0x74, 0x8b, 0x4f, 0xe2, 0xbc, 0x84, 0xd0, 0x15, 0x89, 0x64,
        0xe8, 0xe9, 0xa9, 0xc8, 0x94, 0x89, 0xb8, 0xa2, 0x55, 0x0f, 0xa1, 0x6d, 0x36, 0x05, 0xe0,
        0x58, 0x24,
    ]);
}

#[derive(Debug, Clone)]
pub struct Rgb21PrimaryIssue {
    builder: ContractBuilder,
    deterministic: bool,
}

impl Rgb21PrimaryIssue {
    // init testnet issue uda asset
    // add all required global state here(just in the current version)
    fn testnet_init(
        issuer: SchemaIssuer<Rgb21>,
        ticker: &str,
        name: &str,
        details: Option<&str>,
        token_index: u32,
        timestamp: Timestamp,
    ) -> Result<Self, InvalidIdent> {
        // we set Precision::Indivisible here, because it's rgb21 uda asset.
        let spec = DivisibleAssetSpec::with(ticker, name, Precision::Indivisible, details)?;
        // set default terms, RicardianContract
        let terms = RicardianContract::default();
        // set token data here, just set index to 0 now.
        let token_data = TokenData {
            index: TokenIndex(token_index),
            ..Default::default()
        };
        // get rgb21 schema, and ifaceimpl
        let (schema, main_iface_impl) = issuer.into_split();
        // setup rgb21 contract builder
        let builder = ContractBuilder::testnet(rgb21(), schema, main_iface_impl)
            .expect("schema interface mismatch")
            .add_global_state("spec", spec)
            .expect("invalid RGB21 schema (token specification mismatch)")
            .add_global_state("terms", terms)
            .expect("invalid RGB21 schema (terms mismatch)")
            .add_global_state("tokens", token_data)
            .expect("invalid RGB21 schema (tokens data mismatch)")
            .add_global_state("created", timestamp)
            .expect("invalid RGB21 schema (creation timestamp mismatch)");

        Ok(Self {
            builder,
            deterministic: false,
        })
    }

    // issue uda asset with testnet
    pub fn testnet<C: IssuerClass<IssuingIface = Rgb21>>(
        ticker: &str,
        name: &str,
        details: Option<&str>,
        token_index: u32,
    ) -> Result<Self, InvalidIdent> {
        Self::testnet_init(C::issuer(), ticker, name, details, token_index, Timestamp::now())
    }

    // issue uda asset with testnet
    pub fn testnet_with(
        issuer: SchemaIssuer<Rgb21>,
        ticker: &str,
        name: &str,
        details: Option<&str>,
        token_index: u32,
    ) -> Result<Self, InvalidIdent> {
        Self::testnet_init(issuer, ticker, name, details, token_index, Timestamp::now())
    }

    // issue testnet uda asset with deterministic asset tag
    pub fn testnet_det<C: IssuerClass<IssuingIface = Rgb21>>(
        ticker: &str,
        name: &str,
        details: Option<&str>,
        token_index: u32,
        timestamp: Timestamp,
        asset_tag: AssetTag,
    ) -> Result<Self, InvalidIdent> {
        let mut rgb21_testnet_issue =
            Self::testnet_init(C::issuer(), ticker, name, details, token_index, timestamp)?;
        rgb21_testnet_issue.builder = rgb21_testnet_issue
            .builder
            .add_asset_tag("assetOwner", asset_tag)
            .expect("invalid RGB21 schema (assetOwner mismatch)");
        rgb21_testnet_issue.deterministic = true;
        Ok(rgb21_testnet_issue)
    }

    // add support for Liquid Chain
    pub fn support_liquid(mut self) -> Self {
        self.builder = self
            .builder
            .add_layer1(AltLayer1::Liquid)
            .expect("only one layer1 can be added");
        self
    }

    // add genesis beneficiary
    pub fn allocate_det<O: TxOutpoint>(
        mut self,
        method: Method,
        beneficiary: O,
        allocation: invoice::Allocation,
    ) -> Result<Self, Error> {
        debug_assert!(
            !self.deterministic,
            "for creating deterministic contracts please use allocate_det method"
        );
        // set genesis seal(map genesis beneficiary)
        let beneficiary = beneficiary.map_to_xchain(|outpoint| {
            GenesisSeal::new_random(method, outpoint.txid, outpoint.vout)
        });
        // not sure the definition of second param of the PersistedState::Data
        // so we just set 0u128 now.
        // then add deterministic owned state

        self.builder = self
            .builder
            .add_owned_state_det(
                "assetOwner",
                beneficiary,
                PersistedState::Data(DataState::from(allocation), 0u128),
            )
            .expect("add owned state for assetOwner failed");
        Ok(self)
    }

    #[allow(clippy::result_large_err)]
    pub fn issue_contract(self) -> Result<Contract, BuilderError> { self.builder.issue_contract() }
}

impl IfaceClass for Rgb21 {
    fn iface() -> Iface { rgb21() }
    fn stl() -> TypeLib { rgb21_stl() }
}

impl Rgb21 {
    pub fn testnet<C: IssuerClass<IssuingIface = Self>>(
        ticker: &str,
        name: &str,
        details: Option<&str>,
        token_index: u32,
    ) -> Result<Rgb21PrimaryIssue, InvalidIdent> {
        Rgb21PrimaryIssue::testnet::<C>(ticker, name, details, token_index)
    }

    pub fn testnet_det<C: IssuerClass<IssuingIface = Self>>(
        ticker: &str,
        name: &str,
        details: Option<&str>,
        token_index: u32,
        timestamp: Timestamp,
        asset_tag: AssetTag,
    ) -> Result<Rgb21PrimaryIssue, InvalidIdent> {
        Rgb21PrimaryIssue::testnet_det::<C>(
            ticker,
            name,
            details,
            token_index,
            timestamp,
            asset_tag,
        )
    }

    pub fn spec(&self) -> DivisibleAssetSpec {
        let strict_val = &self
            .0
            .global("spec")
            .expect("RGB21 interface requires global `spec`")[0];
        DivisibleAssetSpec::from_strict_val_unchecked(strict_val)
    }

    pub fn terms(&self) -> RicardianContract {
        let strict_val = &self
            .0
            .global("terms")
            .expect("RGB21 interface requires global `terms`")[0];
        RicardianContract::from_str(&strict_val.unwrap_string()).expect("invalid asset `terms`")
    }

    pub fn token_data(&self) -> TokenData {
        let strict_val = &self
            .0
            .global("tokens")
            .expect("RGB21 interface requires global `tokens`")[0];
        TokenData::from_strict_val_unchecked(strict_val)
    }

    pub fn created(&self) -> Timestamp {
        let strict_val = &self
            .0
            .global("created")
            .expect("RGB21 interface requires global state `created`")[0];
        Timestamp::from_strict_val_unchecked(strict_val)
    }

    pub fn allocations<'c>(
        &'c self,
        filter: impl OutpointFilter + 'c,
    ) -> impl Iterator<Item = DataAllocation> + 'c {
        self.0
            .data("assetOwner", filter)
            .expect("RGB21 interface requires `assetOwner` state")
    }

    pub fn balance(&self, filter: impl OutpointFilter) -> Vec<invoice::Allocation> {
        self.allocations(filter)
            .map(|alloc| invoice::Allocation::from(alloc.state))
            .collect::<Vec<invoice::Allocation>>()
    }

    pub fn owned_token_index(&self, filter: impl OutpointFilter) -> Vec<u32> {
        self.balance(filter)
            .iter()
            .map(|allocation| allocation.token_index())
            .collect::<Vec<u32>>()
    }

    pub fn owned_fraction(&self, filter: impl OutpointFilter) -> Vec<u64> {
        self.balance(filter)
            .iter()
            .map(|allocation| allocation.fraction())
            .collect::<Vec<u64>>()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::containers::BindleContent;

    const RGB21: &str = include_str!("../../tests/data/rgb21.rgba");

    #[test]
    fn lib_id() {
        let lib = rgb21_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB21);
    }

    #[test]
    fn iface_id() {
        assert_eq!(Rgb21::IFACE_ID, rgb21().iface_id());
    }

    #[test]
    fn iface_creation() { rgb21(); }

    #[test]
    fn iface_bindle() {
        assert_eq!(format!("{}", rgb21().bindle()), RGB21);
    }
}
