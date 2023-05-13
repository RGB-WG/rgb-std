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
use std::fmt::{Debug, Formatter};
use std::str::FromStr;

use amplify::ascii::AsciiString;
use amplify::confinement::{Confined, NonEmptyString, SmallString, U8};
use amplify::IoError;
use baid58::Baid58ParseError;
use bp::dbc::LIB_NAME_BPCORE;
use bp::LIB_NAME_BITCOIN;
use strict_encoding::{InvalidIdent, StrictDeserialize, StrictDumb, StrictSerialize, StrictType};
use strict_types::typelib::{LibBuilder, TranslateError};
use strict_types::typesys::SystemBuilder;
use strict_types::{typesys, Dependency, SemId, TypeLib, TypeLibId, TypeSystem};

pub const LIB_NAME_RGB_CONTRACT: &str = "RGBContract";

#[derive(Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Default, From)]
#[wrapper(Deref, Display, FromStr, MathOps)]
#[wrapper_mut(DerefMut, MathAssign)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Timestamp(i32);
impl StrictSerialize for Timestamp {}
impl StrictDeserialize for Timestamp {}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Default)]
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

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, From)]
#[wrapper(Deref, Display)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT, dumb = { Ticker::from("DUMB") })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Ticker(Confined<AsciiString, 1, 8>);
impl StrictSerialize for Ticker {}
impl StrictDeserialize for Ticker {}

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
            .find(|ch| !ch.is_ascii_uppercase())
        {
            return Err(InvalidIdent::InvalidChar(ch));
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
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Name(Confined<AsciiString, 1, 40>);
impl StrictSerialize for Name {}
impl StrictDeserialize for Name {}

impl StrictDumb for Name {
    fn strict_dumb() -> Self { Name::from("Dumb contract name") }
}

impl FromStr for Name {
    type Err = InvalidIdent;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = AsciiString::from_ascii(s.as_bytes())?;
        let s = Confined::try_from_iter(s.chars())?;
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
        let s = Confined::try_from(name)?;
        Ok(Self(s))
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

#[derive(Clone, Eq, PartialEq, Debug)]
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
}

#[derive(Clone, Eq, PartialEq, Debug)]
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
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
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

#[derive(Debug, From)]
enum Error {
    #[from(std::io::Error)]
    Io(IoError),
    #[from]
    Baid58(Baid58ParseError),
    #[from]
    Translate(TranslateError),
    #[from]
    Compile(typesys::Error),
    #[from]
    Link(Vec<typesys::Error>),
}

#[derive(Debug)]
pub struct StandardLib(TypeLib);

impl StandardLib {
    pub fn new() -> Self {
        fn builder() -> Result<TypeLib, Error> {
            let bitcoin_id = TypeLibId::from_str(
                "circus_report_jeep_2bj6eDer24ZBSVq6JgQW2BrARt6vx56vMWzF35J45gzY",
            )?;
            let bpcore_id = TypeLibId::from_str(
                "harlem_null_puma_DxuLX8d9UiMyEJMRJivMFviK1B8t1QWyjywXuDC13iKR",
            )?;

            let imports = bset! {
                Dependency::with(bitcoin_id, libname!(LIB_NAME_BITCOIN)),
                Dependency::with(bpcore_id, libname!(LIB_NAME_BPCORE)),
            };

            LibBuilder::new(libname!(LIB_NAME_RGB_CONTRACT))
                .process::<Timestamp>()?
                .process::<DivisibleAssetSpec>()?
                .process::<RicardianContract>()?
                .compile(imports)
                .map_err(Error::from)
        }

        Self(builder().expect("error in standard RGBContract type library"))
    }

    pub fn type_lib(&self) -> TypeLib { self.0.clone() }
}

#[derive(Debug)]
pub struct StandardTypes(TypeSystem);

impl StandardTypes {
    pub fn new() -> Self {
        fn builder() -> Result<TypeSystem, Error> {
            let lib = StandardLib::new().type_lib();
            let sys = SystemBuilder::new().import(lib)?.finalize()?;
            Ok(sys)
        }

        Self(builder().expect("error in standard RGBContract type system"))
    }

    pub fn type_system(&self) -> TypeSystem { self.0.clone() }

    pub fn get(&self, name: &'static str) -> SemId {
        self.0
            .id_by_name(name)
            .expect("type is absent in standard RGBContract type library")
    }
}
