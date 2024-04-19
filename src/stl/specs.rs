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

#![allow(unused_braces)] // caused by rustc unable to understand strict_dumb

use std::fmt::{self, Debug, Formatter};
use std::str::FromStr;

use amplify::confinement::{Confined, NonEmptyString, SmallOrdSet, SmallString, U8};
use amplify::Bytes32;
use invoice::Precision;
use strict_encoding::stl::{Alpha, AlphaNum, AsciiPrintable};
use strict_encoding::{
    InvalidRString, RString, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize,
    StrictType,
};
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

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, From)]
#[wrapper(Deref, Display, FromStr)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT, dumb = { Article::from("DUMB") })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Article(RString<Alpha, AlphaNum, 1, 32>);

impl_ident_type!(Article);
impl_ident_subtype!(Article);

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, From)]
#[wrapper(Deref, Display, FromStr)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT, dumb = { Ticker::from("DUMB") })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Ticker(RString<Alpha, AlphaNum, 1, 8>);

impl_ident_type!(Ticker);
impl_ident_subtype!(Ticker);

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, From)]
#[wrapper(Deref, Display, FromStr)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Name(RString<AsciiPrintable, AsciiPrintable, 1, 40>);

impl StrictSerialize for Name {}
impl StrictDeserialize for Name {}

impl_ident_type!(Name);
impl_ident_subtype!(Name);

impl Name {
    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        Name::from_str(&value.unwrap_string()).unwrap()
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

impl AsRef<str> for Details {
    #[inline]
    fn as_ref(&self) -> &str { self.0.as_str() }
}

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
    type Err = InvalidRString;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = Confined::try_from_iter(s.chars())?;
        Ok(Self(s))
    }
}

impl From<&'static str> for Details {
    fn from(s: &'static str) -> Self { Self::from_str(s).expect("invalid ticker name") }
}

impl TryFrom<String> for Details {
    type Error = InvalidRString;

    fn try_from(name: String) -> Result<Self, InvalidRString> {
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
pub struct AssetSpec {
    pub ticker: Ticker,
    pub name: Name,
    pub details: Option<Details>,
    pub precision: Precision,
}
impl StrictSerialize for AssetSpec {}
impl StrictDeserialize for AssetSpec {}

impl AssetSpec {
    pub fn new(ticker: &'static str, name: &'static str, precision: Precision) -> AssetSpec {
        AssetSpec {
            ticker: Ticker::from(ticker),
            name: Name::from(name),
            details: None,
            precision,
        }
    }

    pub fn with(
        ticker: &str,
        name: &str,
        precision: Precision,
        details: Option<&str>,
    ) -> Result<AssetSpec, InvalidRString> {
        Ok(AssetSpec {
            ticker: Ticker::try_from(ticker.to_owned())?,
            name: Name::try_from(name.to_owned())?,
            details: details.map(Details::from_str).transpose()?,
            precision,
        })
    }

    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let ticker = value.unwrap_struct("ticker").unwrap_string();
        let name = value.unwrap_struct("name").unwrap_string();
        let details = value
            .unwrap_struct("details")
            .unwrap_option()
            .map(StrictVal::unwrap_string);
        let precision = value.unwrap_struct("precision").unwrap_enum();
        Self {
            ticker: Ticker::from_str(&ticker).expect("invalid asset ticker"),
            name: Name::from_str(&name).expect("invalid asset name"),
            details: details
                .as_deref()
                .map(Details::from_str)
                .transpose()
                .expect("invalid asset details"),
            precision,
        }
    }

    pub fn ticker(&self) -> &str { self.ticker.as_str() }

    pub fn name(&self) -> &str { self.name.as_str() }

    pub fn details(&self) -> Option<&str> { self.details.as_ref().map(|d| d.as_str()) }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractSpec {
    pub article: Option<Article>,
    pub name: Name,
    pub details: Option<Details>,
    pub precision: Precision,
}
impl StrictSerialize for ContractSpec {}
impl StrictDeserialize for ContractSpec {}

impl ContractSpec {
    pub fn new(name: &'static str, precision: Precision) -> ContractSpec {
        ContractSpec {
            article: None,
            name: Name::from(name),
            details: None,
            precision,
        }
    }

    pub fn with(
        article: &str,
        name: &str,
        precision: Precision,
        details: Option<&str>,
    ) -> Result<ContractSpec, InvalidRString> {
        Ok(ContractSpec {
            article: Some(Article::try_from(article.to_owned())?),
            name: Name::try_from(name.to_owned())?,
            details: details.map(Details::from_str).transpose()?,
            precision,
        })
    }

    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let article = value.unwrap_struct("article").unwrap_option();
        let name = value.unwrap_struct("name").unwrap_string();
        let details = value
            .unwrap_struct("details")
            .unwrap_option()
            .map(StrictVal::unwrap_string);
        let precision = value.unwrap_struct("precision").unwrap_enum();
        Self {
            article: article.map(|val| {
                Article::from_str(&val.unwrap_string()).expect("invalid contract article")
            }),
            name: Name::from_str(&name).expect("invalid contract name"),
            details: details
                .as_deref()
                .map(Details::from_str)
                .transpose()
                .expect("invalid contract details"),
            precision,
        }
    }

    pub fn article(&self) -> Option<&str> { self.article.as_ref().map(|a| a.as_str()) }

    pub fn name(&self) -> &str { self.name.as_str() }

    pub fn details(&self) -> Option<&str> { self.details.as_ref().map(|d| d.as_str()) }
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

impl AsRef<str> for RicardianContract {
    #[inline]
    fn as_ref(&self) -> &str { self.0.as_str() }
}

impl FromStr for RicardianContract {
    type Err = InvalidRString;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = Confined::try_from_iter(s.chars())?;
        Ok(Self(s))
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
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
    pub digest: Bytes32,
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
pub struct ContractTerms {
    pub text: RicardianContract,
    pub media: Option<Attachment>,
}
impl StrictSerialize for ContractTerms {}
impl StrictDeserialize for ContractTerms {}

impl ContractTerms {
    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let text = RicardianContract::from_str(&value.unwrap_struct("text").unwrap_string())
            .expect("invalid text");
        let media = value
            .unwrap_struct("media")
            .unwrap_option()
            .map(Attachment::from_strict_val_unchecked);
        Self { text, media }
    }
}
