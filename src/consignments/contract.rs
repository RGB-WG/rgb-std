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
use rgb_core::ContractId;

use super::Contract;

impl lnpbp_bech32::Strategy for Contract {
    const HRP: &'static str = "rgbc";
    type Strategy = lnpbp_bech32::strategies::CompressedStrictEncoding;
}

impl Display for Contract {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { f.write_str(&self.to_bech32_string()) }
}

impl FromStr for Contract {
    type Err = lnpbp_bech32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_bech32_str(s) }
}

impl Contract {
    pub fn contract_id(&self) -> ContractId { self.genesis.contract_id() }
}
