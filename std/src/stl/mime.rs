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

use std::fmt::{self, Debug, Formatter};
use std::str::FromStr;

use amplify::ascii::AsciiString;
use amplify::confinement::{Confined, NonEmptyVec};
use strict_encoding::{
    InvalidIdent, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, TypedWrite,
};

use super::LIB_NAME_RGB_CONTRACT;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct MediaType {
    #[strict_type(rename = "type")]
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub ty: MediaRegName,
    pub subtype: MediaRegName,
    pub charset: Option<MediaRegName>,
}
impl StrictDumb for MediaType {
    fn strict_dumb() -> Self { MediaType::with("text/plain") }
}
impl StrictSerialize for MediaType {}
impl StrictDeserialize for MediaType {}

impl MediaType {
    /// # Safety
    ///
    /// Panics is the provided string is an invalid type specifier.
    pub fn with(s: &'static str) -> Self {
        let (ty, subty) = s.split_once("/").expect("invalid static media type string");
        MediaType {
            ty: MediaRegName::from(ty),
            subtype: MediaRegName::from(subty),
            charset: None,
        }
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
pub struct MediaRegName(Confined<AsciiString, 1, 64>);
impl StrictEncode for MediaRegName {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> std::io::Result<W> {
        writer.write_newtype::<Self>(
            &NonEmptyVec::<MimeChar, 64>::try_from_iter([MimeChar::try_from(b'D').unwrap()])
                .unwrap(),
        )
    }
}

impl StrictDumb for MediaRegName {
    fn strict_dumb() -> Self { MediaRegName::from("dumb") }
}

// TODO: Ensure all constructors filter invalid characters
impl FromStr for MediaRegName {
    type Err = InvalidIdent;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = AsciiString::from_ascii(s.as_bytes())?;
        let s = Confined::try_from_iter(s.chars())?;
        Ok(Self(s))
    }
}

impl From<&'static str> for MediaRegName {
    fn from(s: &'static str) -> Self { Self::from_str(s).expect("invalid ticker name") }
}

impl TryFrom<String> for MediaRegName {
    type Error = InvalidIdent;

    fn try_from(name: String) -> Result<Self, InvalidIdent> {
        let name = AsciiString::from_ascii(name.as_bytes())?;
        let s = Confined::try_from(name)?;
        Ok(Self(s))
    }
}

impl Debug for MediaRegName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ContractName").field(&self.as_str()).finish()
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT, tags = repr, into_u8, try_from_u8)]
#[display(inner)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum MimeChar {
    #[strict_type(dumb)]
    #[display("!")]
    Excl = b'!',
    #[display("#")]
    Hash = b'#',
    #[display("$")]
    Dollar = b'$',
    #[display("&")]
    Amp = b'&',
    #[display("+")]
    Plus = b'+',
    #[display("-")]
    Dash = b'-',
    #[display(".")]
    Dot = b'.',
    #[display("0")]
    Zero = b'0',
    #[display("1")]
    One = b'1',
    #[display("2")]
    Two = b'2',
    #[display("3")]
    Three = b'3',
    #[display("4")]
    Four = b'4',
    #[display("5")]
    Five = b'5',
    #[display("6")]
    Six = b'6',
    #[display("7")]
    Seven = b'7',
    #[display("8")]
    Eight = b'8',
    #[display("9")]
    Nine = b'9',
    #[strict_type(dumb, rename = "A")]
    A = b'A',
    #[strict_type(rename = "B")]
    B = b'B',
    #[strict_type(rename = "C")]
    C = b'C',
    #[strict_type(rename = "D")]
    D = b'D',
    #[strict_type(rename = "E")]
    E = b'E',
    #[strict_type(rename = "F")]
    F = b'F',
    #[strict_type(rename = "G")]
    G = b'G',
    #[strict_type(rename = "H")]
    H = b'H',
    #[strict_type(rename = "I")]
    I = b'I',
    #[strict_type(rename = "J")]
    J = b'J',
    #[strict_type(rename = "K")]
    K = b'K',
    #[strict_type(rename = "L")]
    L = b'L',
    #[strict_type(rename = "M")]
    M = b'M',
    #[strict_type(rename = "N")]
    N = b'N',
    #[strict_type(rename = "O")]
    O = b'O',
    #[strict_type(rename = "P")]
    P = b'P',
    #[strict_type(rename = "Q")]
    Q = b'Q',
    #[strict_type(rename = "R")]
    R = b'R',
    #[strict_type(rename = "S")]
    S = b'S',
    #[strict_type(rename = "T")]
    T = b'T',
    #[strict_type(rename = "U")]
    U = b'U',
    #[strict_type(rename = "V")]
    V = b'V',
    #[strict_type(rename = "W")]
    W = b'W',
    #[strict_type(rename = "X")]
    X = b'X',
    #[strict_type(rename = "Y")]
    Y = b'Y',
    #[strict_type(rename = "Z")]
    Z = b'Z',
    #[display("^")]
    Caret = b'^',
    #[display("_")]
    Lodash = b'_',
    #[display("a")]
    a = b'a',
    #[display("b")]
    b = b'b',
    #[display("c")]
    c = b'c',
    #[display("d")]
    d = b'd',
    #[display("e")]
    e = b'e',
    #[display("f")]
    f = b'f',
    #[display("g")]
    g = b'g',
    #[display("h")]
    h = b'h',
    #[display("i")]
    i = b'i',
    #[display("j")]
    j = b'j',
    #[display("k")]
    k = b'k',
    #[display("l")]
    l = b'l',
    #[display("m")]
    m = b'm',
    #[display("n")]
    n = b'n',
    #[display("o")]
    o = b'o',
    #[display("p")]
    p = b'p',
    #[display("q")]
    q = b'q',
    #[display("r")]
    r = b'r',
    #[display("s")]
    s = b's',
    #[display("t")]
    t = b't',
    #[display("u")]
    u = b'u',
    #[display("v")]
    v = b'v',
    #[display("w")]
    w = b'w',
    #[display("x")]
    x = b'x',
    #[display("y")]
    y = b'y',
    #[display("z")]
    z = b'z',
}
