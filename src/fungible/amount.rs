// RGB20 Library: fungible digital assets for bitcoin & lightning
// Written in 2020-2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Different representations of the fungible asset amounts.
//!
//! RGB20 assets may have a custom precision (see [`Asset::decimal_precision`]),
//! thus the amount of assets can be presented by either floating point value
//! [`FloatingAmount`], which may lead to the loss of the exact amount, or by
//! unsigned integer number [`AtomicValue`], analogous to Bitcoin satoshis.
//! However, since asset may have custom decimal precision, this information is
//! also incomplete. Because of this a special type [`PreciseAmount`] is
//! introduced.
//!
//! General convention followed in RGB20 APIs is to call methods returning
//! floating point amount with `*_amount` suffix, and reserve `*_value` suffix
//! for methods returning atomic value.

use std::ops::{Add, AddAssign, Deref};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::AtomicValue;

/// Representation of the float asset amount after dividing asset value (see
/// [`AtomicValue`]) on the asset decimal precision exponential.
pub type FractionalAmount = f64;

/// Accounting amount keeps track of the asset precision
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Default, StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display("{0}~{1}")]
pub struct PreciseAmount(AtomicValue, u8);

impl PreciseAmount {
    const DIVIDER: [u64; 20] = [
        1,
        10,
        100,
        1_000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
        10_000_000_000,
        100_000_000_000,
        1_000_000_000_000,
        10_000_000_000_000,
        100_000_000_000_000,
        1_000_000_000_000_000,
        10_000_000_000_000_000,
        100_000_000_000_000_000,
        1_000_000_000_000_000_000,
        10_000_000_000_000_000_000,
    ];

    /// Converts fractional amount into atomic value using the provided decimal
    /// precision
    #[inline]
    pub fn transmutate_from(
        fractional_amount: FractionalAmount,
        decimal_precision: u8,
    ) -> AtomicValue {
        PreciseAmount::from_fractional_amount(fractional_amount, decimal_precision).atomic_value()
    }

    /// Converts atomic value into a floating-point fractional amount using the
    /// provided decimal precision
    #[inline]
    pub fn transmutate_into(atomic_value: AtomicValue, decimal_precision: u8) -> FractionalAmount {
        PreciseAmount::from_atomic_value(atomic_value, decimal_precision).fractional_amount()
    }

    /// Constructs [`PreciseAmount`] from atomic value and decimal precision
    /// data
    #[inline]
    pub fn from_atomic_value(atomic_value: AtomicValue, decimal_precision: u8) -> Self {
        Self(atomic_value, decimal_precision)
    }

    /// Constructs [`PreciseAmount`] from fractional amount and decimal
    /// precision data
    #[inline]
    pub fn from_fractional_amount(
        fractional_amount: FractionalAmount,
        decimal_precision: u8,
    ) -> Self {
        let full = (fractional_amount.trunc() as u64) * Self::DIVIDER[decimal_precision as usize];
        let fract = fractional_amount.fract() as u64;
        Self(full + fract, decimal_precision)
    }

    /// Returns fractional amount
    #[inline]
    pub fn fractional_amount(&self) -> FractionalAmount {
        self.0 as f64 / Self::DIVIDER[self.1 as usize] as f64
    }

    /// Returns atomic value
    #[inline]
    pub fn atomic_value(&self) -> AtomicValue { self.0 }

    /// Returns decimal precision
    #[inline]
    pub fn decimal_precision(&self) -> u8 { self.1 }
}

impl Add for PreciseAmount {
    type Output = PreciseAmount;

    fn add(self, rhs: Self) -> Self::Output {
        if self.decimal_precision() != rhs.decimal_precision() {
            panic!("Addition of amounts with different fractional bits")
        } else {
            PreciseAmount::from_atomic_value(
                self.atomic_value() + rhs.atomic_value(),
                self.decimal_precision(),
            )
        }
    }
}

impl AddAssign for PreciseAmount {
    fn add_assign(&mut self, rhs: Self) {
        if self.decimal_precision() != rhs.decimal_precision() {
            panic!("Addition of amounts with different fractional bits")
        } else {
            self.0 += rhs.0
        }
    }
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq)]
#[display(doc_comments)]
/// Asset decimal precision exceeds 18 digits
pub struct DecimalPrecisionOverflow;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(inner)]
/// Decimal precision for asset value: a wrapper limiting the value range to 0..=18
pub struct DecimalPrecision(u8);

impl Deref for DecimalPrecision {
    type Target = u8;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl TryFrom<amplify::num::u5> for DecimalPrecision {
    type Error = DecimalPrecisionOverflow;

    fn try_from(value: amplify::num::u5) -> Result<Self, Self::Error> {
        Self::try_from(value.as_u8())
    }
}

impl TryFrom<u8> for DecimalPrecision {
    type Error = DecimalPrecisionOverflow;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0..=18 => Ok(DecimalPrecision(value)),
            _ => Err(DecimalPrecisionOverflow),
        }
    }
}

impl TryFrom<usize> for DecimalPrecision {
    type Error = DecimalPrecisionOverflow;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_from(u8::try_from(value).map_err(|_| DecimalPrecisionOverflow)?)
    }
}

impl DecimalPrecision {
    pub fn zero() -> Self { Self(0) }

    pub fn one() -> Self { Self(1) }
}

#[cfg(test)]
mod test {
    use amplify::num::u5;

    use super::*;

    #[test]
    fn decimal_precision() {
        // Minimal
        assert_eq!(*DecimalPrecision::try_from(u5::ZERO).unwrap(), 0);
        assert_eq!(*DecimalPrecision::try_from(0u8).unwrap(), 0);
        assert_eq!(*DecimalPrecision::try_from(0usize).unwrap(), 0);

        // Maximal
        let u5_18 = u5::try_from(18).unwrap();
        assert_eq!(*DecimalPrecision::try_from(u5_18).unwrap(), 18);
        assert_eq!(*DecimalPrecision::try_from(18u8).unwrap(), 18);
        assert_eq!(*DecimalPrecision::try_from(18usize).unwrap(), 18);

        // Overflow: >18
        let u5_19 = u5::try_from(19).unwrap();
        assert_eq!(
            DecimalPrecision::try_from(u5_19).unwrap_err(),
            DecimalPrecisionOverflow
        );
        assert_eq!(
            DecimalPrecision::try_from(19u8).unwrap_err(),
            DecimalPrecisionOverflow
        );
        assert_eq!(
            DecimalPrecision::try_from(19usize).unwrap_err(),
            DecimalPrecisionOverflow
        );
        assert_eq!(
            DecimalPrecision::try_from(usize::MAX).unwrap_err(),
            DecimalPrecisionOverflow
        );
    }

    #[test]
    fn decimal_precision_constructors() {
        assert_eq!(*DecimalPrecision::zero(), 0);
        assert_eq!(*DecimalPrecision::one(), 1);
    }
}
