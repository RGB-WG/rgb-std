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

use amplify::hex::ToHex;
use amplify::Wrapper;
use strict_encoding::{DecodeError, StrictDecode, TypedRead};

use crate::LIB_NAME_RGB_STD;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictEncode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct ReservedBytes<const VAL: u8, const LEN: usize>([u8; LEN]);

impl<const VAL: u8, const LEN: usize> Wrapper for ReservedBytes<VAL, LEN> {
    type Inner = [u8; LEN];
    fn from_inner(inner: Self::Inner) -> Self { Self::from(inner) }
    fn as_inner(&self) -> &Self::Inner { &self.0 }
    fn into_inner(self) -> Self::Inner { self.0 }
}

impl<const VAL: u8, const LEN: usize> From<[u8; LEN]> for ReservedBytes<VAL, LEN> {
    fn from(value: [u8; LEN]) -> Self {
        assert_eq!(value, [VAL; LEN]);
        Self(value)
    }
}

impl<const VAL: u8, const LEN: usize> Default for ReservedBytes<VAL, LEN> {
    fn default() -> Self { ReservedBytes([VAL; LEN]) }
}

impl<const VAL: u8, const LEN: usize> StrictDecode for ReservedBytes<VAL, LEN> {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        let me = reader.read_newtype::<Self>()?;
        if me.0 != [VAL; LEN] {
            Err(DecodeError::DataIntegrityError(format!(
                "reserved bytes required to have value [{VAL}; {LEN}] while {} was found",
                me.0.to_hex()
            )))
        } else {
            Ok(me)
        }
    }
}

#[cfg(feature = "serde")]
mod _serde {
    use std::fmt;

    use serde_crate::de::Visitor;
    use serde_crate::{de, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl<const VAL: u8, const LEN: usize> Serialize for ReservedBytes<VAL, LEN> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            // Doing nothing
            serializer.serialize_unit()
        }
    }

    impl<'de, const VAL: u8, const LEN: usize> Deserialize<'de> for ReservedBytes<VAL, LEN> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            #[derive(Default)]
            pub struct UntaggedUnitVisitor;

            impl<'de> Visitor<'de> for UntaggedUnitVisitor {
                type Value = ();

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(formatter, "reserved unit")
                }

                fn visit_none<E>(self) -> Result<(), E>
                where E: de::Error {
                    Ok(())
                }

                fn visit_unit<E>(self) -> Result<(), E>
                where E: de::Error {
                    Ok(())
                }
            }

            deserializer.deserialize_unit(UntaggedUnitVisitor)?;
            Ok(default!())
        }
    }
}
