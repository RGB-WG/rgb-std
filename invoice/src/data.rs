use std::str::FromStr;

use rgb::{DataState, KnownState, RevealedData};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::LIB_NAME_RGB_CONTRACT;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum NonFungible {
    #[display(inner)]
    RGB21(Allocation),
}

impl FromStr for NonFungible {
    type Err = AllocationParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let allocation = Allocation::from_str(s)?;
        Ok(NonFungible::RGB21(allocation))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum AllocationParseError {
    #[display(doc_comments)]
    /// invalid token index {0}.
    InvalidIndex(String),

    #[display(doc_comments)]
    /// invalid fraction {0}.
    InvalidFraction(String),

    #[display(doc_comments)]
    /// allocation must have format <fraction>@<token_index>.
    WrongFormat,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From, Display)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display("{1}@{0}")]
pub struct Allocation(u32, u64);

impl StrictSerialize for Allocation {}
impl StrictDeserialize for Allocation {}

impl KnownState for Allocation {}

impl From<RevealedData> for Allocation {
    fn from(data: RevealedData) -> Self {
        Allocation::from_strict_serialized(data.value.into()).expect("invalid allocation data")
    }
}

impl From<DataState> for Allocation {
    fn from(state: DataState) -> Self {
        Allocation::from_strict_serialized(state.into()).expect("invalid allocation data")
    }
}

impl From<Allocation> for DataState {
    fn from(allocation: Allocation) -> Self {
        DataState::from(
            allocation
                .to_strict_serialized()
                .expect("invalid allocation data"),
        )
    }
}

impl FromStr for Allocation {
    type Err = AllocationParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.contains('@') {
            return Err(AllocationParseError::WrongFormat);
        }

        match s.split_once('@') {
            Some((fraction, token_index)) => Ok(Allocation::with(
                token_index
                    .parse()
                    .map_err(|_| AllocationParseError::InvalidIndex(token_index.to_owned()))?,
                fraction
                    .parse()
                    .map_err(|_| AllocationParseError::InvalidFraction(fraction.to_lowercase()))?,
            )),
            None => Err(AllocationParseError::WrongFormat),
        }
    }
}

impl Allocation {
    pub fn with(token_index: u32, fraction: u64) -> Self { Self(token_index, fraction) }

    pub fn token_index(self) -> u32 { self.0 }

    pub fn fraction(self) -> u64 { self.1 }
}
