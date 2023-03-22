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

//! Processing proprietary PSBT keys related to OP_RETURN (or opret)
//! commitments.
//!
//! NB: Wallets supporting opret commitments must do that through the use of
//! deterministic bitcoin commitments crate (`bp-dpc`) in order to ensure
//! that multiple protocols can put commitment inside the same transaction
//! without collisions between them.
//!
//! This module provides support for marking PSBT outputs which may host
//! opret commitment and populating PSBT with the data related to opret
//! commitments.

use bitcoin::psbt::raw::ProprietaryKey;
use bitcoin::psbt::Output;
use commit_verify::mpc;

/// PSBT proprietary key prefix used for opret commitment.
pub const PSBT_OPRET_PREFIX: &[u8] = b"OPRET";

/// Proprietary key subtype marking PSBT outputs which may host opret
/// commitment.
pub const PSBT_OUT_OPRET_HOST: u8 = 0x00;
/// Proprietary key subtype holding 32-byte commitment which will be put into
/// opret data.
pub const PSBT_OUT_OPRET_COMMITMENT: u8 = 0x01;

/// Extension trait for static functions returning opret-related proprietary
/// keys.
pub trait ProprietaryKeyOpret {
    /// Constructs [`PSBT_OUT_OPRET_HOST`] proprietary key.
    fn opret_host() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_OPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_OPRET_HOST,
            key: vec![],
        }
    }

    /// Constructs [`PSBT_OUT_OPRET_COMMITMENT`] proprietary key.
    fn opret_commitment() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_OPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_OPRET_COMMITMENT,
            key: vec![],
        }
    }
}

impl ProprietaryKeyOpret for ProprietaryKey {}

/// Errors processing opret-related proprietary PSBT keys and their values.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum OpretKeyError {
    /// output already contains commitment; there must be a single commitment
    /// per output.
    OutputAlreadyHasCommitment,

    /// the output can't host a commitment since it does not contain OP_RETURN
    /// script
    NonOpReturnOutput,

    /// the output is not marked to host opret commitments. Please first set
    /// PSBT_OUT_OPRET_HOST flag.
    OpretProhibited,
}

pub trait OutputOpret {
    fn is_opret_host(&self) -> bool;
    fn set_opret_host(&mut self) -> Result<bool, OpretKeyError>;
    fn has_opret_commitment(&self) -> Result<bool, OpretKeyError>;
    fn opret_commitment(&self) -> Option<mpc::Commitment>;
    fn set_opret_commitment(&mut self, commitment: mpc::Commitment) -> Result<(), OpretKeyError>;
}

impl OutputOpret for Output {
    /// Returns whether this output may contain opret commitment. This is
    /// detected by the presence of [`PSBT_OUT_OPRET_HOST`] key.
    #[inline]
    fn is_opret_host(&self) -> bool {
        // TODO: Check that output is OP_RETURN
        self.proprietary.contains_key(&ProprietaryKey::opret_host()) // && self.script.is_op_return()
    }

    /// Allows opret commitments for this output. Returns whether opret
    /// commitments were enabled before.
    ///
    /// # Errors
    ///
    /// If output script is not OP_RETURN script
    #[inline]
    fn set_opret_host(&mut self) -> Result<bool, OpretKeyError> {
        // TODO: Check that output is OP_RETURN
        /* if !self.script.is_op_return() {
            return Err(OpretKeyError::NonOpReturnOutput);
        } */
        Ok(self
            .proprietary
            .insert(ProprietaryKey::opret_host(), vec![])
            .is_some())
    }

    /// Detects presence of a valid [`PSBT_OUT_OPRET_COMMITMENT`].
    ///
    /// If [`PSBT_OUT_OPRET_COMMITMENT`] is absent or its value is invalid,
    /// returns `false`. In the future, when `PSBT_OUT_OPRET_COMMITMENT` will
    /// become a standard and non-custom key, PSBTs with invalid key values
    /// will error at deserialization and this function will return `false`
    /// only in cases when the output does not have
    /// `PSBT_OUT_OPRET_COMMITMENT`.
    ///
    /// # Errors
    ///
    /// If output script is not OP_RETURN script
    fn has_opret_commitment(&self) -> Result<bool, OpretKeyError> {
        // TODO: Check that output is OP_RETURN
        /*
        if !self.script.is_op_return() {
            return Err(OpretKeyError::NonOpReturnOutput);
        }*/
        Ok(self
            .proprietary
            .contains_key(&ProprietaryKey::opret_commitment()))
    }

    /// Returns valid opret commitment from the [`PSBT_OUT_OPRET_COMMITMENT`]
    /// key, if present. If the commitment is absent or invalid, returns
    /// `None`.
    ///
    /// We do not error on invalid commitments in order to support future update
    /// of this proprietary key to the standard one. In this case, the
    /// invalid commitments (having non-32 bytes) will be filtered at the
    /// moment of PSBT deserialization and this function will return `None`
    /// only in situations when the commitment is absent.
    ///
    /// # Errors
    ///
    /// If output script is not OP_RETURN script
    fn opret_commitment(&self) -> Option<mpc::Commitment> {
        // TODO: Check that output is OP_RETURN
        /*if !self.script.is_op_return() {
            return Err(OpretKeyError::NonOpReturnOutput);
        }*/
        let data = self.proprietary.get(&ProprietaryKey::opret_commitment())?;
        mpc::Commitment::from_slice(data)
    }

    /// Assigns value of the opreturn commitment to this PSBT output, by
    /// adding [`PSBT_OUT_OPRET_COMMITMENT`] proprietary key containing the
    /// 32-byte commitment as its value.
    ///
    /// Errors with [`OpretKeyError::OutputAlreadyHasCommitment`] if the
    /// commitment is already present in the output.
    ///
    /// # Errors
    ///
    /// If output script is not OP_RETURN script or opret commitments are not
    /// enabled for this output.
    fn set_opret_commitment(&mut self, commitment: mpc::Commitment) -> Result<(), OpretKeyError> {
        if !self.is_opret_host() {
            return Err(OpretKeyError::OpretProhibited);
        }

        if self.has_opret_commitment()? {
            return Err(OpretKeyError::OutputAlreadyHasCommitment);
        }

        self.proprietary
            .insert(ProprietaryKey::opret_commitment(), commitment.to_vec());

        Ok(())
    }
}
