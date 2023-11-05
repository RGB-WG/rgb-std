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

#![allow(unused_braces)] // caused by rustc unable to understand strict_dumb

use std::fmt;
use std::fmt::{Debug, Display, Formatter, Write};
use std::iter::Sum;
use std::str::FromStr;

use amplify::ascii::AsciiString;
use amplify::confinement::{Confined, NonEmptyString, NonEmptyVec, SmallOrdSet, SmallString, U8};
use bp::Sats;
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use strict_encoding::stl::{AlphaCapsNum, AsciiPrintable};
use strict_encoding::{
    InvalidIdent, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, StrictType,
    TypedWrite,
};
use strict_types::value::StrictNum;
use strict_types::StrictVal;

use super::{MediaType, ProofOfReserves, LIB_NAME_RGB_CONTRACT};

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct BurnMeta {
    pub burn_proofs: SmallOrdSet<ProofOfReserves>,
}
impl StrictSerialize for BurnMeta {}
impl StrictDeserialize for BurnMeta {}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct IssueMeta {
    pub reserves: SmallOrdSet<ProofOfReserves>,
}
impl StrictSerialize for IssueMeta {}
impl StrictDeserialize for IssueMeta {}

#[derive(
    Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From
)]
#[wrapper(Display, FromStr, Add, Sub, Mul, Div, Rem)]
#[wrapper_mut(AddAssign, SubAssign, MulAssign, DivAssign, RemAssign)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Amount(
    #[from]
    #[from(u32)]
    #[from(u16)]
    #[from(u8)]
    #[from(Sats)]
    u64,
);

impl StrictSerialize for Amount {}
impl StrictDeserialize for Amount {}

impl Amount {
    pub const ZERO: Self = Amount(0);

    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        value.unwrap_uint::<u64>().into()
    }

    pub fn with_precision(amount: u64, precision: impl Into<Precision>) -> Self {
        precision.into().unchecked_convert(amount)
    }

    pub fn with_precision_checked(amount: u64, precision: impl Into<Precision>) -> Option<Self> {
        precision.into().checked_convert(amount)
    }

    pub fn value(self) -> u64 { self.0 }

    pub fn split(self, precision: impl Into<Precision>) -> (u64, u64) {
        let precision = precision.into();
        let int = self.floor(precision);
        let fract = self.rem(precision);
        (int, fract)
    }

    pub fn round(&self, precision: impl Into<Precision>) -> u64 {
        let precision = precision.into();
        let mul = precision.multiplier();
        if self.0 == 0 {
            return 0;
        }
        let inc = 2 * self.rem(precision) / mul;
        self.0 / mul + inc
    }

    pub fn ceil(&self, precision: impl Into<Precision>) -> u64 {
        let precision = precision.into();
        if self.0 == 0 {
            return 0;
        }
        let inc = if self.rem(precision) > 0 { 1 } else { 0 };
        self.0 / precision.multiplier() + inc
    }

    pub fn floor(&self, precision: impl Into<Precision>) -> u64 {
        if self.0 == 0 {
            return 0;
        }
        self.0 / precision.into().multiplier()
    }

    pub fn rem(&self, precision: impl Into<Precision>) -> u64 {
        self.0 % precision.into().multiplier()
    }

    pub fn saturating_add(&self, other: impl Into<Self>) -> Self {
        self.0.saturating_add(other.into().0).into()
    }
    pub fn saturating_sub(&self, other: impl Into<Self>) -> Self {
        self.0.saturating_sub(other.into().0).into()
    }

    pub fn saturating_add_assign(&mut self, other: impl Into<Self>) {
        *self = self.0.saturating_add(other.into().0).into();
    }
    pub fn saturating_sub_assign(&mut self, other: impl Into<Self>) {
        *self = self.0.saturating_sub(other.into().0).into();
    }
}

impl Sum<u64> for Amount {
    fn sum<I: Iterator<Item = u64>>(iter: I) -> Self {
        iter.fold(Amount::ZERO, |sum, value| sum.saturating_add(value))
    }
}

impl Sum for Amount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Amount::ZERO, |sum, value| sum.saturating_add(value))
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
#[repr(u8)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum Precision {
    Indivisible = 0,
    Deci = 1,
    Centi = 2,
    Milli = 3,
    DeciMilli = 4,
    CentiMilli = 5,
    Micro = 6,
    DeciMicro = 7,
    #[default]
    CentiMicro = 8,
    Nano = 9,
    DeciNano = 10,
    CentiNano = 11,
    Pico = 12,
    DeciPico = 13,
    CentiPico = 14,
    Femto = 15,
    DeciFemto = 16,
    CentiFemto = 17,
    Atto = 18,
}
impl StrictSerialize for Precision {}
impl StrictDeserialize for Precision {}

impl Precision {
    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self { value.unwrap_enum() }
    pub const fn decimals(self) -> u8 { self as u8 }
    pub const fn decimals_u32(self) -> u32 { self as u8 as u32 }

    pub const fn multiplier(self) -> u64 {
        match self {
            Precision::Indivisible => 1,
            Precision::Deci => 10,
            Precision::Centi => 100,
            Precision::Milli => 1000,
            Precision::DeciMilli => 10_000,
            Precision::CentiMilli => 100_000,
            Precision::Micro => 1_000_000,
            Precision::DeciMicro => 10_000_000,
            Precision::CentiMicro => 100_000_000,
            Precision::Nano => 1_000_000_000,
            Precision::DeciNano => 10_000_000_000,
            Precision::CentiNano => 100_000_000_000,
            Precision::Pico => 1_000_000_000_000,
            Precision::DeciPico => 10_000_000_000_000,
            Precision::CentiPico => 100_000_000_000_000,
            Precision::Femto => 1_000_000_000_000_000,
            Precision::DeciFemto => 10_000_000_000_000_000,
            Precision::CentiFemto => 100_000_000_000_000_000,
            Precision::Atto => 1_000_000_000_000_000_000,
        }
    }

    pub fn unchecked_convert(self, amount: impl Into<u64>) -> Amount {
        (amount.into() * self.multiplier()).into()
    }

    pub fn checked_convert(self, amount: impl Into<u64>) -> Option<Amount> {
        amount
            .into()
            .checked_mul(self.multiplier())
            .map(Amount::from)
    }
    pub fn saturating_convert(self, amount: impl Into<u64>) -> Amount {
        amount.into().saturating_mul(self.multiplier()).into()
    }
}

impl From<Precision> for u16 {
    fn from(value: Precision) -> Self { value as u8 as u16 }
}

impl From<Precision> for u32 {
    fn from(value: Precision) -> Self { value as u8 as u32 }
}

impl From<Precision> for u64 {
    fn from(value: Precision) -> Self { value as u8 as u64 }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct CoinAmount {
    pub int: u64,
    pub fract: u64,
    pub precision: Precision,
}

impl CoinAmount {
    pub fn with(value: impl Into<Amount>, precision: impl Into<Precision>) -> Self {
        let precision = precision.into();
        let value = value.into();
        let (int, fract) = value.split(precision);
        CoinAmount {
            int,
            fract,
            precision,
        }
    }
}

impl Display for CoinAmount {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut int = self.int.to_string();
        if f.alternate() {
            int = int
                .chars()
                .rev()
                .collect::<String>()
                .as_bytes()
                .chunks(3)
                .map(<[u8]>::to_owned)
                .map(|mut chunk| unsafe {
                    chunk.reverse();
                    String::from_utf8_unchecked(chunk)
                })
                .rev()
                .collect::<Vec<_>>()
                .join("`");
        }
        f.write_str(&int)?;
        if self.fract > 0 {
            f.write_char('.')?;
            let mut float = self.fract.to_string();
            let len = float.len();
            if let Some(decimals) = f.precision() {
                float.extend("0".repeat(decimals - len).chars());
            }
            if f.alternate() {
                float = float
                    .as_bytes()
                    .chunks(3)
                    .map(|chunk| unsafe { String::from_utf8_unchecked(chunk.to_owned()) })
                    .collect::<Vec<_>>()
                    .join("`");
            }
            f.write_str(&float)?;
        }
        Ok(())
    }
}

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, From)]
#[wrapper(Deref, Display)]
#[derive(StrictDumb, StrictType, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT, dumb = { Ticker::from("DUMB") })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Ticker(Confined<AsciiString, 1, 8>);
impl StrictEncode for Ticker {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> std::io::Result<W> {
        let iter = self
            .0
            .as_bytes()
            .iter()
            .map(|c| AlphaCapsNum::try_from(*c).unwrap());
        writer.write_newtype::<Self>(&NonEmptyVec::<AlphaCapsNum, 8>::try_from_iter(iter).unwrap())
    }
}
impl StrictSerialize for Ticker {}
impl StrictDeserialize for Ticker {}

// TODO: Ensure all constructors filter invalid characters
impl FromStr for Ticker {
    type Err = InvalidIdent;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = AsciiString::from_ascii(s.as_bytes())?;
        Self::try_from(s)
    }
}

impl From<&'static str> for Ticker {
    fn from(s: &'static str) -> Self { Self::from_str(s).expect("invalid ticker name") }
}

impl TryFrom<String> for Ticker {
    type Error = InvalidIdent;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let s = AsciiString::from_ascii(s.as_bytes())?;
        Self::try_from(s)
    }
}

impl TryFrom<AsciiString> for Ticker {
    type Error = InvalidIdent;

    fn try_from(ascii: AsciiString) -> Result<Self, InvalidIdent> {
        if ascii.is_empty() {
            return Err(InvalidIdent::Empty);
        }
        if let Some(ch) = ascii
            .as_slice()
            .iter()
            .copied()
            .find(|ch| AlphaCapsNum::try_from(ch.as_byte()).is_err())
        {
            return Err(InvalidIdent::InvalidChar(ascii, ch));
        }
        let s = Confined::try_from(ascii)?;
        Ok(Self(s))
    }
}

impl Debug for Ticker {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ticker").field(&self.as_str()).finish()
    }
}

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, From)]
#[wrapper(Deref, Display)]
#[derive(StrictType, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Name(Confined<AsciiString, 1, 40>);
impl StrictEncode for Name {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> std::io::Result<W> {
        let iter = self
            .0
            .as_bytes()
            .iter()
            .map(|c| AsciiPrintable::try_from(*c).unwrap());
        writer
            .write_newtype::<Self>(&NonEmptyVec::<AsciiPrintable, 40>::try_from_iter(iter).unwrap())
    }
}
impl StrictSerialize for Name {}
impl StrictDeserialize for Name {}

impl Name {
    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        Name::from_str(&value.unwrap_string()).unwrap()
    }
}

impl StrictDumb for Name {
    fn strict_dumb() -> Self { Name::from("Dumb contract name") }
}

// TODO: Ensure all constructors filter invalid characters
impl FromStr for Name {
    type Err = InvalidIdent;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = AsciiString::from_ascii(s.as_bytes())?;
        Self::try_from(s)
    }
}

impl TryFrom<AsciiString> for Name {
    type Error = InvalidIdent;

    fn try_from(ascii: AsciiString) -> Result<Self, InvalidIdent> {
        if ascii.is_empty() {
            return Err(InvalidIdent::Empty);
        }
        if let Some(ch) = ascii
            .as_slice()
            .iter()
            .copied()
            .find(|ch| AsciiPrintable::try_from(ch.as_byte()).is_err())
        {
            return Err(InvalidIdent::InvalidChar(ascii, ch));
        }
        let s = Confined::try_from(ascii)?;
        Ok(Self(s))
    }
}

impl From<&'static str> for Name {
    fn from(s: &'static str) -> Self { Self::from_str(s).expect("invalid ticker name") }
}

impl TryFrom<String> for Name {
    type Error = InvalidIdent;

    fn try_from(name: String) -> Result<Self, InvalidIdent> {
        let name = AsciiString::from_ascii(name.as_bytes())?;
        Self::try_from(name)
    }
}

impl Debug for Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ContractName").field(&self.as_str()).finish()
    }
}

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, From)]
#[wrapper(Deref, Display)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Details(NonEmptyString<U8>);
impl StrictSerialize for Details {}
impl StrictDeserialize for Details {}

impl Details {
    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        Details::from_str(&value.unwrap_string()).unwrap()
    }
}

impl StrictDumb for Details {
    fn strict_dumb() -> Self {
        Self(Confined::try_from(s!("Dumb long description which is stupid and so on...")).unwrap())
    }
}

impl FromStr for Details {
    type Err = InvalidIdent;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = Confined::try_from_iter(s.chars())?;
        Ok(Self(s))
    }
}

impl From<&'static str> for Details {
    fn from(s: &'static str) -> Self { Self::from_str(s).expect("invalid ticker name") }
}

impl TryFrom<String> for Details {
    type Error = InvalidIdent;

    fn try_from(name: String) -> Result<Self, InvalidIdent> {
        let s = Confined::try_from(name)?;
        Ok(Self(s))
    }
}

impl Debug for Details {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ContractDetails")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AssetNaming {
    pub ticker: Ticker,
    pub name: Name,
    pub details: Option<Details>,
}
impl StrictSerialize for AssetNaming {}
impl StrictDeserialize for AssetNaming {}

impl AssetNaming {
    pub fn new(ticker: &'static str, name: &'static str) -> AssetNaming {
        AssetNaming {
            ticker: Ticker::from(ticker),
            name: Name::from(name),
            details: None,
        }
    }

    pub fn with(
        ticker: &str,
        name: &str,
        details: Option<&str>,
    ) -> Result<AssetNaming, InvalidIdent> {
        Ok(AssetNaming {
            ticker: Ticker::try_from(ticker.to_owned())?,
            name: Name::try_from(name.to_owned())?,
            details: details.map(Details::from_str).transpose()?,
        })
    }

    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let ticker = value.unwrap_struct("ticker").unwrap_string();
        let name = value.unwrap_struct("name").unwrap_string();
        let details = value
            .unwrap_struct("details")
            .unwrap_option()
            .map(StrictVal::unwrap_string);
        AssetNaming {
            ticker: Ticker::from_str(&ticker).expect("invalid asset ticker"),
            name: Name::from_str(&name).expect("invalid asset name"),
            details: details
                .as_deref()
                .map(Details::from_str)
                .transpose()
                .expect("invalid asset details"),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct DivisibleAssetSpec {
    pub naming: AssetNaming,
    pub precision: Precision,
}
impl StrictSerialize for DivisibleAssetSpec {}
impl StrictDeserialize for DivisibleAssetSpec {}

impl DivisibleAssetSpec {
    pub fn new(
        ticker: &'static str,
        name: &'static str,
        precision: Precision,
    ) -> DivisibleAssetSpec {
        DivisibleAssetSpec {
            naming: AssetNaming::new(ticker, name),
            precision,
        }
    }

    pub fn with(
        ticker: &str,
        name: &str,
        precision: Precision,
        details: Option<&str>,
    ) -> Result<DivisibleAssetSpec, InvalidIdent> {
        Ok(DivisibleAssetSpec {
            naming: AssetNaming::with(ticker, name, details)?,
            precision,
        })
    }

    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let naming = AssetNaming::from_strict_val_unchecked(value.unwrap_struct("naming"));
        let precision = value.unwrap_struct("precision").unwrap_enum();
        Self { naming, precision }
    }

    pub fn ticker(&self) -> &str { self.naming.ticker.as_str() }

    pub fn name(&self) -> &str { self.naming.name.as_str() }

    pub fn details(&self) -> Option<&str> { self.naming.details.as_ref().map(|d| d.as_str()) }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Default)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct RicardianContract(SmallString);
impl StrictSerialize for RicardianContract {}
impl StrictDeserialize for RicardianContract {}

impl FromStr for RicardianContract {
    type Err = InvalidIdent;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = Confined::try_from_iter(s.chars())?;
        Ok(Self(s))
    }
}

#[derive(Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, Display, FromStr, MathOps)]
#[wrapper_mut(DerefMut, MathAssign)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT, dumb = Timestamp::start_of_epoch())]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Timestamp(i64);
impl StrictSerialize for Timestamp {}
impl StrictDeserialize for Timestamp {}

impl Timestamp {
    pub fn start_of_epoch() -> Self { Timestamp(0) }

    pub fn now() -> Self { Timestamp(Local::now().timestamp()) }

    pub fn to_utc(self) -> Option<DateTime<Utc>> {
        NaiveDateTime::from_timestamp_opt(self.0, 0)
            .map(|naive| DateTime::from_naive_utc_and_offset(naive, Utc))
    }

    pub fn to_local(self) -> Option<DateTime<Local>> { self.to_utc().map(DateTime::<Local>::from) }

    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        // TODO: Move this logic to strict_types StrictVal::unwrap_int method
        let StrictVal::Number(StrictNum::Int(val)) = value.skip_wrapper() else {
            panic!("required integer number");
        };
        Self(*val as i64)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Attachment {
    #[strict_type(rename = "type")]
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub ty: MediaType,
    pub digest: [u8; 32],
}
impl StrictSerialize for Attachment {}
impl StrictDeserialize for Attachment {}

impl Attachment {
    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let ty = MediaType::from_strict_val_unchecked(value.unwrap_struct("type"));
        let digest = value
            .unwrap_struct("digest")
            .unwrap_bytes()
            .try_into()
            .expect("invalid digest");
        Self { ty, digest }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractData {
    pub terms: RicardianContract,
    pub media: Option<Attachment>,
}
impl StrictSerialize for ContractData {}
impl StrictDeserialize for ContractData {}

impl ContractData {
    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let terms = RicardianContract::from_str(&value.unwrap_struct("terms").unwrap_string())
            .expect("invalid terms");
        let media = value
            .unwrap_struct("media")
            .unwrap_option()
            .map(Attachment::from_strict_val_unchecked);
        Self { terms, media }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn coin_amount() {
        let amount = CoinAmount::with(10_000_436_081_95u64, Precision::default());
        assert_eq!(amount.int, 10_000);
        assert_eq!(amount.fract, 436_081_95);
        assert_eq!(format!("{amount}"), "10000.43608195");
        assert_eq!(format!("{amount:#.10}"), "10`000.436`081`950`0");
    }
}
