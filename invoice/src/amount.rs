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

use std::fmt;
use std::fmt::{Display, Formatter, Write};
use std::iter::Sum;

use bp::Sats;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::StrictVal;

use crate::LIB_NAME_RGB_CONTRACT;

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
                float.push_str(&"0".repeat(decimals - len));
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[allow(clippy::inconsistent_digit_grouping)]
    fn coin_amount() {
        let amount = CoinAmount::with(10_000_436_081_95u64, Precision::default());
        assert_eq!(amount.int, 10_000);
        assert_eq!(amount.fract, 436_081_95);
        assert_eq!(format!("{amount}"), "10000.43608195");
        assert_eq!(format!("{amount:#.10}"), "10`000.436`081`950`0");
    }
}
