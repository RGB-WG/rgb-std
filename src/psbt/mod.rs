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

//! Managing RGB-related proprietary keys inside PSBT.
//!
//! Supports Tapret, Opret, P2C and S2C commitments and LNPBP4 structures used
//! by all of them.

// TODO: Move to BP wallet
mod lnpbp4;
// TODO: Move to BP wallet
mod dbc;
// TODO: Move to BP wallet
pub mod opret;
// TODO: Move to BP wallet
pub mod tapret;
mod rgb;

pub use dbc::{DbcPsbtError, PsbtDbc};
pub use lnpbp4::{
    Lnpbp4PsbtError, ProprietaryKeyLnpbp4, PSBT_LNPBP4_PREFIX, PSBT_OUT_LNPBP4_ENTROPY,
    PSBT_OUT_LNPBP4_MESSAGE, PSBT_OUT_LNPBP4_MIN_TREE_DEPTH,
};
pub use opret::{
    OpretKeyError, ProprietaryKeyOpret, PSBT_OPRET_PREFIX, PSBT_OUT_OPRET_COMMITMENT,
    PSBT_OUT_OPRET_HOST,
};
pub use tapret::{
    ProprietaryKeyTapret, TapretKeyError, PSBT_IN_TAPRET_TWEAK, PSBT_OUT_TAPRET_COMMITMENT,
    PSBT_OUT_TAPRET_HOST, PSBT_OUT_TAPRET_PROOF, PSBT_TAPRET_PREFIX,
};

pub use self::rgb::{
    ProprietaryKeyRgb, RgbExt, RgbInExt, RgbPsbtError, PSBT_GLOBAL_RGB_TRANSITION,
    PSBT_IN_RGB_CONSUMED_BY, PSBT_RGB_PREFIX,
};
