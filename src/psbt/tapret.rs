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

//! Processing proprietary PSBT keys related to taproot-based OP_RETURN
//! (or tapret) commitments.
//!
//! NB: Wallets supporting tapret commitments must do that through the use of
//! deterministic bitcoin commitments crate (`bp-dpc`) in order to ensure
//! that multiple protocols can put commitment inside the same transaction
//! without collisions between them.
//!
//! This module provides support for marking PSBT outputs which may host
//! tapreturn commitment and populating PSBT with the data related to tapret
//! commitments.

use amplify::confinement::{Confined, U16};
use bitcoin::psbt::raw::ProprietaryKey;
use bitcoin::psbt::Output;
use bp::dbc::tapret::TapretPathProof;
use commit_verify::mpc;
use strict_encoding::{StrictDeserialize, StrictSerialize};

/// PSBT proprietary key prefix used for tapreturn commitment.
pub const PSBT_TAPRET_PREFIX: &[u8] = b"TAPRET";

/// Proprietary key subtype for PSBT inputs containing the applied tapret tweak
/// information.
pub const PSBT_IN_TAPRET_TWEAK: u8 = 0x00;

/// Proprietary key subtype marking PSBT outputs which may host tapreturn
/// commitment.
pub const PSBT_OUT_TAPRET_HOST: u8 = 0x00;
/// Proprietary key subtype holding 32-byte commitment which will be put into
/// tapreturn tweak.
pub const PSBT_OUT_TAPRET_COMMITMENT: u8 = 0x01;
/// Proprietary key subtype holding merkle branch path to tapreturn tweak inside
/// the taptree structure.
pub const PSBT_OUT_TAPRET_PROOF: u8 = 0x02;

/// Extension trait for static functions returning tapreturn-related proprietary
/// keys.
pub trait ProprietaryKeyTapret {
    /// Constructs [`PSBT_IN_TAPRET_TWEAK`] proprietary key.
    fn tapret_tweak() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_IN_TAPRET_TWEAK,
            key: vec![],
        }
    }

    /// Constructs [`PSBT_OUT_TAPRET_HOST`] proprietary key.
    fn tapret_host() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_TAPRET_HOST,
            key: vec![],
        }
    }

    /// Constructs [`PSBT_OUT_TAPRET_COMMITMENT`] proprietary key.
    fn tapret_commitment() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_TAPRET_COMMITMENT,
            key: vec![],
        }
    }

    /// Constructs [`PSBT_OUT_TAPRET_PROOF`] proprietary key.
    fn tapret_proof() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_TAPRET_PROOF,
            key: vec![],
        }
    }
}

impl ProprietaryKeyTapret for ProprietaryKey {}

/// Errors processing tapret-related proprietary PSBT keys and their values.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TapretKeyError {
    /// output already contains commitment; there must be a single commitment
    /// per output.
    OutputAlreadyHasCommitment,

    /// the output is not marked to host tapret commitments. Please first set
    /// PSBT_OUT_TAPRET_HOST flag.
    TapretProhibited,

    /// the provided tapret proof is invalid: it has a script longer than 64KiB.
    InvalidProof,

    /// the provided output is not a taproot output and can't host a tapret
    /// commitment.
    NotTaprootOutput,
}

pub trait OutputTapret {
    fn is_tapret_host(&self) -> bool;
    fn set_tapret_host(&mut self) -> Result<(), TapretKeyError>;
    fn has_tapret_commitment(&self) -> bool;
    fn tapret_commitment(&self) -> Option<mpc::Commitment>;
    fn set_tapret_commitment(
        &mut self,
        commitment: mpc::Commitment,
        proof: &TapretPathProof,
    ) -> Result<(), TapretKeyError>;
    fn has_tapret_proof(&self) -> bool;
    fn tapret_proof(&self) -> Option<TapretPathProof>;
}

impl OutputTapret for Output {
    /// Returns whether this output may contain tapret commitment. This is
    /// detected by the presence of [`PSBT_OUT_TAPRET_HOST`] key.
    #[inline]
    fn is_tapret_host(&self) -> bool {
        self.proprietary
            .contains_key(&ProprietaryKey::tapret_host())
    }

    /// Sets [`PSBT_OUT_TAPRET_HOST`] key.
    ///
    /// # Errors
    ///
    /// Errors with [`TapretKeyError::NotTaprootOutput`] if the output is not a
    /// taproot output.
    fn set_tapret_host(&mut self) -> Result<(), TapretKeyError> {
        // TODO: With new PSBT library check scriptPubkey directly
        if self.tap_internal_key.is_none() {
            return Err(TapretKeyError::NotTaprootOutput);
        }

        self.proprietary
            .insert(ProprietaryKey::tapret_host(), vec![]);

        Ok(())
    }

    /// Detects presence of a valid [`PSBT_OUT_TAPRET_COMMITMENT`].
    ///
    /// If [`PSBT_OUT_TAPRET_COMMITMENT`] is absent or its value is invalid,
    /// returns `false`. In the future, when `PSBT_OUT_TAPRET_COMMITMENT` will
    /// become a standard and non-custom key, PSBTs with invalid key values
    /// will error at deserialization and this function will return `false`
    /// only in cases when the output does not have
    /// `PSBT_OUT_TAPRET_COMMITMENT`.
    fn has_tapret_commitment(&self) -> bool { self.tapret_commitment().is_some() }

    /// Returns valid tapret commitment from the [`PSBT_OUT_TAPRET_COMMITMENT`]
    /// key, if present. If the commitment is absent or invalid, returns
    /// `None`.
    ///
    /// We do not error on invalid commitments in order to support future update
    /// of this proprietary key to the standard one. In this case, the
    /// invalid commitments (having non-32 bytes) will be filtered at the
    /// moment of PSBT deserialization and this function will return `None`
    /// only in situations when the commitment is absent.
    fn tapret_commitment(&self) -> Option<mpc::Commitment> {
        let data = self.proprietary.get(&ProprietaryKey::tapret_commitment())?;
        mpc::Commitment::from_slice(data)
    }

    /// Assigns value of the tapreturn commitment to this PSBT output, by
    /// adding [`PSBT_OUT_TAPRET_COMMITMENT`] and [`PSBT_OUT_TAPRET_PROOF`]
    /// proprietary keys containing the 32-byte commitment as its proof.
    ///
    /// # Errors
    ///
    /// Errors with [`TapretKeyError::OutputAlreadyHasCommitment`] if the
    /// commitment is already present in the output, and with
    /// [`TapretKeyError::TapretProhibited`] if tapret commitments are not
    /// enabled for this output.
    fn set_tapret_commitment(
        &mut self,
        commitment: mpc::Commitment,
        proof: &TapretPathProof,
    ) -> Result<(), TapretKeyError> {
        if !self.is_tapret_host() {
            return Err(TapretKeyError::TapretProhibited);
        }

        if self.has_tapret_commitment() {
            return Err(TapretKeyError::OutputAlreadyHasCommitment);
        }

        self.proprietary
            .insert(ProprietaryKey::tapret_commitment(), commitment.to_vec());

        let val = proof
            .to_strict_serialized::<U16>()
            .map_err(|_| TapretKeyError::InvalidProof)?;
        self.proprietary
            .insert(ProprietaryKey::tapret_proof(), val.into_inner());

        Ok(())
    }

    /// Detects presence of a valid [`PSBT_OUT_TAPRET_PROOF`].
    ///
    /// If [`PSBT_OUT_TAPRET_PROOF`] is absent or its value is invalid,
    /// returns `false`. In the future, when `PSBT_OUT_TAPRET_PROOF` will
    /// become a standard and non-custom key, PSBTs with invalid key values
    /// will error at deserialization and this function will return `false`
    /// only in cases when the output does not have `PSBT_OUT_TAPRET_PROOF`.
    fn has_tapret_proof(&self) -> bool { self.tapret_proof().is_some() }

    /// Returns valid tapret commitment proof from the [`PSBT_OUT_TAPRET_PROOF`]
    /// key, if present. If the commitment is absent or invalid, returns `None`.
    ///
    /// We do not error on invalid proofs in order to support future update of
    /// this proprietary key to a standard one. In this case, the invalid
    /// commitments (having non-32 bytes) will be filtered at the moment of PSBT
    /// deserialization and this function will return `None` only in situations
    /// when the commitment is absent.
    ///
    /// Function returns generic type since the real type will create dependency
    /// on `bp-dpc` crate, which will result in circular dependency with the
    /// current crate.
    fn tapret_proof(&self) -> Option<TapretPathProof> {
        let data = self.proprietary.get(&ProprietaryKey::tapret_proof())?;
        let vec = Confined::try_from_iter(data.iter().copied()).ok()?;
        TapretPathProof::from_strict_serialized::<U16>(vec).ok()
    }
}
