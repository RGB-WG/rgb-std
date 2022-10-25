// RGB Standard Library: high-level API to RGB smart contracts.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use lnpbp_bech32::{FromBech32Str, ToBech32String};

use super::{ConsignmentType, InmemConsignment};

impl<T> lnpbp_bech32::Strategy for InmemConsignment<T>
where T: ConsignmentType
{
    const HRP: &'static str = "rgbc";
    type Strategy = lnpbp_bech32::strategies::CompressedStrictEncoding;
}

impl<T> Display for InmemConsignment<T>
where T: ConsignmentType
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { f.write_str(&self.to_bech32_string()) }
}

impl<T> FromStr for InmemConsignment<T>
where T: ConsignmentType
{
    type Err = lnpbp_bech32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_bech32_str(s) }
}
