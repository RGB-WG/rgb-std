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

use std::str::FromStr;

use bitcoin::hashes::{sha256, sha256t};
use commit_verify::{commit_encode, CommitVerify, PrehashedProtocol, TaggedHash};
use lnpbp_bech32::{FromBech32Str, ToBech32String};

static MIDSTATE_CONSIGNMENT_ID: [u8; 32] = [
    8, 36, 37, 167, 51, 70, 76, 241, 171, 132, 169, 56, 76, 108, 174, 226, 197, 98, 75, 254, 29,
    125, 170, 233, 184, 121, 13, 183, 90, 51, 134, 6,
];

/// Tag used for [`ConsignmentId`] hash types
pub struct ConsignmentIdTag;

impl sha256t::Tag for ConsignmentIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_CONSIGNMENT_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Unique transfer identifier equivalent to the commitment hash
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Display, From)]
#[derive(StrictEncode, StrictDecode)]
#[wrapper(LowerHex, BorrowSlice)]
#[display(ConsignmentId::to_bech32_string)]
pub struct ConsignmentId(sha256t::Hash<ConsignmentIdTag>);

impl<Msg> CommitVerify<Msg, PrehashedProtocol> for ConsignmentId
where Msg: AsRef<[u8]>
{
    #[inline]
    fn commit(msg: &Msg) -> ConsignmentId { ConsignmentId::hash(msg) }
}

impl commit_encode::Strategy for ConsignmentId {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl lnpbp_bech32::Strategy for ConsignmentId {
    const HRP: &'static str = "id";
    type Strategy = lnpbp_bech32::strategies::UsingStrictEncoding;
}

impl FromStr for ConsignmentId {
    type Err = lnpbp_bech32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> { ConsignmentId::from_bech32_str(s) }
}

#[cfg(test)]
pub(crate) mod test {
    use amplify::Wrapper;
    use commit_verify::tagged_hash;

    use super::*;

    #[test]
    fn test_consignment_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:consignment");
        assert_eq!(midstate.into_inner().into_inner(), MIDSTATE_CONSIGNMENT_ID);
    }
}
