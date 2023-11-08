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

#![allow(unused_braces)]

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::str::FromStr;

use amplify::ascii::AsciiString;
use amplify::confinement::{Confined, NonEmptyVec, SmallBlob};
use bp::bc::stl::bp_tx_stl;
use strict_encoding::stl::AsciiPrintable;
use strict_encoding::{
    InvalidIdent, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, TypedWrite,
};
use strict_types::stl::std_stl;
use strict_types::{CompileError, LibBuilder, TypeLib};

use super::{
    AssignIface, GenesisIface, GlobalIface, Iface, OwnedIface, Req, TransitionIface, VerNo,
};
use crate::interface::{ArgSpec, ContractIface, IfaceId, IfaceWrapper};
use crate::stl::{
    rgb_contract_stl, Attachment, Details, DivisibleAssetSpec, MediaType, Name, ProofOfReserves,
    StandardTypes, Ticker,
};

pub const LIB_NAME_RGB21: &str = "RGB21";
/// Strict types id for the library providing data types for RGB21 interface.
pub const LIB_ID_RGB21: &str =
    "urn:ubideco:stl:3HCD3uDCC2EmGASKnxPaFUCgRBT59SbmJkHjkXh8Ht7B#compare-ship-voodoo";

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

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB21)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Allocation(TokenIndex, OwnedFraction);

impl Allocation {
    pub fn with(index: TokenIndex, fraction: OwnedFraction) -> Allocation {
        Allocation(index, fraction)
    }
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
        0x6d, 0xef, 0xbb, 0x86, 0xe8, 0x3b, 0xd3, 0x74, 0xf2, 0xdd, 0xd5, 0x02, 0x55, 0x1f, 0x66,
        0xad, 0x70, 0x62, 0xc7, 0x44, 0xf9, 0xfa, 0x4f, 0x52, 0x77, 0xde, 0x26, 0x01, 0x83, 0xf9,
        0x90, 0x1d,
    ]);
}

impl Rgb21 {
    pub fn spec(&self) -> DivisibleAssetSpec {
        let strict_val = &self
            .0
            .global("spec")
            .expect("RGB21 interface requires global `spec`")[0];
        DivisibleAssetSpec::from_strict_val_unchecked(strict_val)
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
