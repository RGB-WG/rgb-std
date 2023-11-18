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

//! RGB contract interface provides a mapping between identifiers of RGB schema-
//! defined contract state and operation types to a human-readable and
//! standardized wallet APIs.

mod iface;
mod iimpl;
mod contract;
mod builder;
pub mod rgb20;
pub mod rgb21;
pub mod rgb25;
mod suppl;

pub use asset_tag_ext::AssetTagExt;
pub use builder::{BuilderError, ContractBuilder, TransitionBuilder};
pub use contract::{
    AllocationWitness, ContractIface, FilterExclude, FilterIncludeAll, FungibleAllocation,
    IfaceWrapper, OutpointFilter, TypedState,
};
pub use iface::{
    ArgMap, ArgSpec, AssignIface, ExtensionIface, GenesisIface, GlobalIface, Iface, IfaceId,
    OwnedIface, Req, TransitionIface, ValencyIface,
};
pub use iimpl::{IfaceImpl, IfacePair, ImplId, NamedField, NamedType, SchemaIfaces};
pub use rgb20::{rgb20, rgb20_stl, Rgb20, LIB_ID_RGB20, LIB_NAME_RGB20};
pub use rgb21::{rgb21, rgb21_stl, Rgb21, LIB_ID_RGB21, LIB_NAME_RGB21};
pub use rgb25::{rgb25, rgb25_stl, Rgb25, LIB_ID_RGB25, LIB_NAME_RGB25};
pub use suppl::{ContractSuppl, OwnedStateSuppl, SupplId, TickerSuppl, VelocityHint};

use crate::stl::Ticker;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = crate::LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
#[non_exhaustive]
pub enum VerNo {
    #[default]
    #[display("v1")]
    V1 = 0,
}

mod asset_tag_ext {
    use std::time::SystemTime;

    use amplify::confinement::U8;
    use bp::secp256k1::rand::{thread_rng, RngCore};
    use commit_verify::{DigestExt, Sha256};
    use rgb::AssetTag;
    use strict_encoding::TypeName;

    use super::*;

    pub trait AssetTagExt: Sized {
        fn new_rgb20(issuer_domain: &str, ticker: &Ticker) -> Self {
            Self::new_custom("RGB20", issuer_domain, ticker)
        }
        fn new_rgb21(issuer_domain: &str, ticker: &Ticker) -> Self {
            Self::new_custom("RGB21", issuer_domain, ticker)
        }
        fn new_rgb25(issuer_domain: &str, ticker: &Ticker) -> Self {
            Self::new_custom("RGB25", issuer_domain, ticker)
        }
        fn new_custom(
            iface_name: impl Into<TypeName>,
            issuer_domain: impl AsRef<str>,
            ticker: impl AsRef<str>,
        ) -> Self;
    }

    impl AssetTagExt for AssetTag {
        fn new_custom(
            iface_name: impl Into<TypeName>,
            issuer_domain: impl AsRef<str>,
            ticker: impl AsRef<str>,
        ) -> Self {
            let rand = thread_rng().next_u64();
            let timestamp = SystemTime::now().elapsed().expect("system time error");
            let mut hasher = Sha256::default();
            hasher.input_with_len::<U8>(iface_name.into().as_bytes());
            hasher.input_with_len::<U8>(issuer_domain.as_ref().as_bytes());
            hasher.input_with_len::<U8>(ticker.as_ref().as_bytes());
            hasher.input_raw(&timestamp.as_nanos().to_le_bytes());
            hasher.input_raw(&rand.to_le_bytes());
            AssetTag::from(hasher.finish())
        }
    }
}
