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
use rgb::{Occurrences, Types};
use strict_encoding::stl::AsciiPrintable;
use strict_encoding::{
    InvalidIdent, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, TypedWrite,
};
use strict_types::stl::std_stl;
use strict_types::{CompileError, LibBuilder, StrictVal, TypeLib};

use super::{
    AssignIface, DataAllocation, GenesisIface, GlobalIface, Iface, IfaceClass, Modifier,
    OutpointFilter, OwnedIface, Req, TransitionIface, VerNo,
};
use crate::interface::rgb20::{named_asset, renameable, reservable};
use crate::interface::{ContractIface, IfaceId, IfaceWrapper};
use crate::stl::{
    rgb_contract_stl, AssetSpec, AssetTerms, Attachment, Details, MediaType, Name, ProofOfReserves,
    StandardTypes, Ticker,
};

pub const LIB_NAME_RGB21: &str = "RGB21";
/// Strict types id for the library providing data types for RGB21 interface.
pub const LIB_ID_RGB21: &str =
    "urn:ubideco:stl:9GETUAH3q2Aw4JSiCzGy4Z8bTuagKQvPa4hH4mDxcX9d#type-economy-shannon";

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

impl EngravingData {
    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let index = TokenIndex(value.unwrap_struct("index").unwrap_num().unwrap_uint());
        let content = EmbeddedMedia::from_strict_val_unchecked(value.unwrap_struct("content"));

        Self {
            applied_to: index,
            content,
        }
    }
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
    .compile()
}

/// Generates strict type library providing data types for RGB21 interface.
fn rgb21_stl() -> TypeLib { _rgb21_stl().expect("invalid strict type RGB21 library") }

pub fn nft() -> Iface {
    let types = StandardTypes::with(rgb21_stl());
    Iface {
        version: VerNo::V1,
        name: tn!("NonFungibleToken"),
        inherits: none!(),
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        global_state: tiny_bmap! {
            fname!("tokens") => GlobalIface::none_or_many(types.get("RGB21.TokenData")),
            fname!("attachmentTypes") => GlobalIface::none_or_many(types.get("RGB21.AttachmentType")),
        },
        assignments: tiny_bmap! {
            fname!("assetOwner") => AssignIface::private(OwnedIface::Data(types.get("RGB21.Allocation")), Req::NoneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Override,
            metadata: None,
            globals: tiny_bmap! {
                fname!("tokens") => Occurrences::NoneOrMore,
                fname!("attachmentTypes") => Occurrences::NoneOrMore,
            },
            assignments: tiny_bmap! {
                fname!("assetOwner") => Occurrences::NoneOrMore,
            },
            valencies: none!(),
            errors: tiny_bset! {
                vname!("fractionOverflow"),
                vname!("invalidAttachmentType")
            },
        },
        transitions: tiny_bmap! {
            fname!("transfer") => TransitionIface {
                modifier: Modifier::Final,
                optional: false,
                metadata: None,
                globals: none!(),
                inputs: tiny_bmap! {
                    fname!("assetOwner") => Occurrences::OnceOrMore,
                },
                assignments: tiny_bmap! {
                    fname!("assetOwner") => Occurrences::OnceOrMore,
                },
                valencies: none!(),
                errors: tiny_bset! {
                    vname!("nonEqualValues"),
                    vname!("fractionOverflow"),
                    vname!("nonFractionalToken")
                },
                default_assignment: Some(fname!("assetOwner")),
            },
        },
        extensions: none!(),
        errors: tiny_bmap! {
            vname!("fractionOverflow")
                => tiny_s!("the amount of fractional token in outputs exceeds 1"),

            vname!("nonEqualValues")
                => tiny_s!("the sum of spent token fractions doesn't equal to the sum of token fractions in outputs"),

            vname!("nonFractionalToken")
                => tiny_s!("attempt to transfer a fraction of non-fractionable token"),

            vname!("invalidAttachmentType")
                => tiny_s!("attachment has a type which is not allowed for the token"),
        },
        default_operation: Some(fname!("transfer")),
        types: Types::Strict(types.type_system()),
    }
}

pub fn unique() -> Iface {
    let types = StandardTypes::with(rgb21_stl());
    Iface {
        version: VerNo::V1,
        name: tn!("UniqueNft"),
        inherits: tiny_bset![nft().iface_id()],
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        global_state: tiny_bmap! {
            fname!("tokens") => GlobalIface::required(types.get("RGB21.TokenData")),
            fname!("attachmentTypes") => GlobalIface::required(types.get("RGB21.AttachmentType")),
        },
        assignments: tiny_bmap! {
            fname!("assetOwner") => AssignIface::private(OwnedIface::Data(types.get("RGB21.Allocation")), Req::OneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Override,
            metadata: None,
            globals: tiny_bmap! {
                fname!("tokens") => Occurrences::Once,
                fname!("attachmentTypes") => Occurrences::Once,
            },
            assignments: tiny_bmap! {
                fname!("assetOwner") => Occurrences::OnceOrMore,
            },
            valencies: none!(),
            errors: none!(),
        },
        transitions: none!(),
        extensions: none!(),
        errors: none!(),
        default_operation: None,
        types: Types::Strict(types.type_system()),
    }
}

pub fn limited() -> Iface {
    let types = StandardTypes::with(rgb21_stl());
    Iface {
        version: VerNo::V1,
        name: tn!("LimitedNft"),
        inherits: tiny_bset![nft().iface_id()],
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        global_state: tiny_bmap! {
            fname!("tokens") => GlobalIface::one_or_many(types.get("RGB21.TokenData")),
            fname!("attachmentTypes") => GlobalIface::one_or_many(types.get("RGB21.AttachmentType")),
        },
        assignments: tiny_bmap! {
            fname!("assetOwner") => AssignIface::private(OwnedIface::Data(types.get("RGB21.Allocation")), Req::OneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Override,
            metadata: None,
            globals: tiny_bmap! {
                fname!("tokens") => Occurrences::OnceOrMore,
                fname!("attachmentTypes") => Occurrences::OnceOrMore,
            },
            assignments: tiny_bmap! {
                fname!("assetOwner") => Occurrences::OnceOrMore,
            },
            valencies: none!(),
            errors: none!(),
        },
        transitions: none!(),
        extensions: none!(),
        errors: none!(),
        default_operation: None,
        types: Types::Strict(types.type_system()),
    }
}

pub fn engravable() -> Iface {
    let types = StandardTypes::with(rgb21_stl());
    Iface {
        version: VerNo::V1,
        name: tn!("EngravableNft"),
        inherits: tiny_bset![nft().iface_id()],
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        global_state: tiny_bmap! {
            fname!("engravings") => GlobalIface::none_or_many(types.get("RGB21.EngravingData")),
        },
        assignments: none!(),
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Override,
            metadata: None,
            globals: none!(),
            assignments: none!(),
            valencies: none!(),
            errors: none!(),
        },
        transitions: tiny_bmap! {
            fname!("engrave") => TransitionIface {
                modifier: Modifier::Final,
                optional: false,
                metadata: None,
                globals: tiny_bmap! {
                    fname!("engravings") => Occurrences::Once,
                },
                inputs: tiny_bmap! {
                    fname!("assetOwner") => Occurrences::OnceOrMore,
                },
                assignments: tiny_bmap! {
                    fname!("assetOwner") => Occurrences::OnceOrMore,
                },
                valencies: none!(),
                errors: tiny_bset! {
                    vname!("nonEqualValues"),
                    vname!("fractionOverflow"),
                    vname!("nonFractionalToken"),
                    vname!("nonEngravableToken")
                },
                default_assignment: Some(fname!("assetOwner")),
            },
        },
        extensions: none!(),
        errors: tiny_bmap! {
            vname!("nonEngravableToken")
                => tiny_s!("attempt to engrave on a token which prohibit engraving"),
        },
        default_operation: None,
        types: Types::Strict(types.type_system()),
    }
}

pub fn issuable() -> Iface {
    let types = StandardTypes::with(rgb21_stl());
    Iface {
        version: VerNo::V1,
        name: tn!("IssuableNft"),
        inherits: tiny_bset![nft().iface_id()],
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        global_state: none!(),
        assignments: tiny_bmap! {
            fname!("inflationAllowance") => AssignIface::public(OwnedIface::Data(types.get("RGB21.ItemsCount")), Req::OneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Override,
            metadata: None,
            globals: none!(),
            assignments: tiny_bmap! {
                fname!("inflationAllowance") => Occurrences::OnceOrMore,
            },
            valencies: none!(),
            errors: none!(),
        },
        transitions: tiny_bmap! {
            fname!("issue") => TransitionIface {
                modifier: Modifier::Abstract,
                optional: false,
                metadata: None,
                globals: tiny_bmap! {
                    fname!("tokens") => Occurrences::NoneOrMore,
                    fname!("attachmentTypes") => Occurrences::NoneOrMore,
                },
                inputs: tiny_bmap! {
                    fname!("inflationAllowance") => Occurrences::OnceOrMore,
                },
                assignments: tiny_bmap! {
                    fname!("assetOwner") => Occurrences::NoneOrMore,
                    fname!("inflationAllowance") => Occurrences::NoneOrMore,
                },
                valencies: none!(),
                errors: tiny_bset! {
                    vname!("fractionOverflow"),
                    vname!("invalidProof"),
                    vname!("insufficientReserves"),
                    vname!("invalidAttachmentType"),
                    vname!("issueExceedsAllowance"),
                },
                default_assignment: Some(fname!("assetOwner")),
            },
        },
        extensions: none!(),
        errors: tiny_bmap! {
            vname!("issueExceedsAllowance")
                => tiny_s!("you try to issue more assets than allowed by the contract terms"),
        },
        default_operation: None,
        types: Types::Strict(types.type_system()),
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub enum Issues {
    #[default]
    Unique,
    Limited,
    MultiIssue,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub struct Features {
    pub renaming: bool,
    pub reserves: bool,
    pub engraving: bool,
    pub issues: Issues,
}

impl Features {
    pub fn none() -> Self {
        Features {
            renaming: false,
            reserves: false,
            engraving: false,
            issues: Issues::Unique,
        }
    }
    pub fn all() -> Self {
        Features {
            renaming: true,
            reserves: true,
            engraving: true,
            issues: Issues::MultiIssue,
        }
    }
}

#[derive(Wrapper, WrapperMut, Clone, Eq, PartialEq, Debug)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
pub struct Rgb21(ContractIface);

impl From<ContractIface> for Rgb21 {
    fn from(iface: ContractIface) -> Self {
        if iface.iface.iface_id != Rgb21::IFACE_ID {
            panic!("the provided interface is not RGB21 interface");
        }
        Self(iface)
    }
}

impl IfaceWrapper for Rgb21 {
    const IFACE_NAME: &'static str = LIB_NAME_RGB21;
    const IFACE_ID: IfaceId = IfaceId::from_array([
        0x98, 0x2b, 0x4e, 0xc1, 0xc8, 0x8a, 0xbc, 0xa3, 0x9f, 0x93, 0xa1, 0x4f, 0x1c, 0x1c, 0xfa,
        0x80, 0x5c, 0x81, 0x54, 0xb0, 0x29, 0x5b, 0xf3, 0x98, 0xbf, 0xcb, 0xa1, 0x60, 0xe9, 0xad,
        0x57, 0xe9,
    ]);
}

impl IfaceClass for Rgb21 {
    type Features = Features;
    fn iface(features: Self::Features) -> Iface {
        let mut iface = named_asset().expect_extended(nft());
        if features.renaming {
            iface = iface.expect_extended(renameable());
        }
        if features.engraving {
            iface = iface.expect_extended(engravable());
        }
        iface = match features.issues {
            Issues::Unique => iface.expect_extended(unique()),
            Issues::Limited => iface.expect_extended(limited()),
            Issues::MultiIssue => iface.expect_extended(issuable()),
        };
        if features.reserves {
            iface = iface.expect_extended(reservable());
        }
        iface.name = Self::IFACE_NAME.into();
        iface
    }
    fn stl() -> TypeLib { rgb21_stl() }
}

impl Rgb21 {
    pub fn spec(&self) -> AssetSpec {
        let strict_val = &self
            .0
            .global("spec")
            .expect("RGB21 interface requires global `spec`")[0];
        AssetSpec::from_strict_val_unchecked(strict_val)
    }

    pub fn contract_terms(&self) -> AssetTerms {
        let strict_val = &self
            .0
            .global("terms")
            .expect("RGB21 interface requires global `terms`")[0];
        AssetTerms::from_strict_val_unchecked(strict_val)
    }

    pub fn token_data(&self) -> TokenData {
        let strict_val = &self
            .0
            .global("tokens")
            .expect("RGB21 interface requires global `tokens`")[0];
        TokenData::from_strict_val_unchecked(strict_val)
    }

    pub fn engarving_data(&self) -> EngravingData {
        let strict_val = &self
            .0
            .global("engravings")
            .expect("RGB21 interface requires global state `engravings`")[0];
        EngravingData::from_strict_val_unchecked(strict_val)
    }

    pub fn allocations<'c>(
        &'c self,
        filter: impl OutpointFilter + 'c,
    ) -> impl Iterator<Item = DataAllocation> + 'c {
        self.0
            .data("assetOwner", filter)
            .expect("RGB21 interface requires `assetOwner` state")
    }
}

#[cfg(test)]
mod test {
    use armor::AsciiArmor;

    use super::*;

    const RGB21: &str = include_str!("../../tests/data/rgb21.rgba");

    #[test]
    fn lib_id() {
        let lib = rgb21_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB21);
    }

    #[test]
    fn iface_id() {
        let iface_id = Rgb21::iface(Features::all()).iface_id();
        eprintln!("{:#04x?}", iface_id.to_byte_array());
        assert_eq!(Rgb21::IFACE_ID, iface_id);
    }

    #[test]
    fn iface_bindle() {
        assert_eq!(format!("{}", Rgb21::iface(Features::all()).to_ascii_armored_string()), RGB21);
    }

    #[test]
    fn iface_check() {
        if let Err(err) = Rgb21::iface(Features::all()).check() {
            for e in err {
                eprintln!("{e}");
            }
            panic!("invalid RGB21 interface definition");
        }
    }
}
