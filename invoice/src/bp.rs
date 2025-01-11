// Invoice Library for RGB smart contracts
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

use amplify::confinement::{self, TinyBlob};
use amplify::Bytes;
use baid64::base64::alphabet::Alphabet;
use baid64::base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use baid64::base64::{DecodeError, Engine};
use baid64::BAID64_ALPHABET;
use bp::seals::Noise;
use bp::ScriptPubkey;
use commit_verify::{Digest, DigestExt, ReservedBytes, Sha256};
use strict_encoding::{DeserializeError, StrictDeserialize, StrictSerialize};

pub const WITNESS_OUT_HRI: &str = "wout:";

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = "RGB")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct WitnessOut {
    reserved: ReservedBytes<1>,
    salt: u64,
    script_pubkey: TinyBlob,
}
impl StrictSerialize for WitnessOut {}
impl StrictDeserialize for WitnessOut {}

impl Into<ScriptPubkey> for WitnessOut {
    fn into(self) -> ScriptPubkey { ScriptPubkey::from_unsafe(self.script_pubkey.into_vec()) }
}

impl WitnessOut {
    pub fn noise(&self) -> Noise {
        let mut noise_engine = Sha256::new();
        noise_engine.input_raw(&self.salt.to_le_bytes());
        noise_engine.input_raw(self.script_pubkey.as_ref());
        let mut noise = [0xFFu8; 40];
        noise[..32].copy_from_slice(&noise_engine.finish());
        Bytes::from(noise).into()
    }

    pub fn to_script_pubkey(&self) -> ScriptPubkey {
        ScriptPubkey::from_unsafe(self.script_pubkey.to_vec())
    }

    pub fn checksum(&self) -> [u8; 4] {
        let key = Sha256::digest(WITNESS_OUT_HRI.as_bytes());
        let mut sha = Sha256::new_with_prefix(key);
        sha.update(&[0]);
        sha.update(self.salt.to_le_bytes());
        sha.update(self.script_pubkey.as_ref());
        let sha = sha.finalize();
        [sha[0], sha[1], sha[1], sha[2]]
    }
}

impl Display for WitnessOut {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(WITNESS_OUT_HRI)?;

        let mut data = self
            .to_strict_serialized::<{ u8::MAX as usize }>()
            .expect("script pubkey length in WitnessOut should be controlled during creation")
            .release();
        data.extend(self.checksum());

        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new());
        let encoded = engine.encode(data).chars().collect::<Vec<_>>();

        for chunk in encoded.chunks(8) {
            f.write_str(&chunk.iter().collect::<String>())?;
            f.write_str("-")?;
        }

        Ok(())
    }
}

impl FromStr for WitnessOut {
    type Err = ParseWitnessOutError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(WITNESS_OUT_HRI)
            .ok_or(ParseWitnessOutError::NoPrefix)?;

        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new());
        let decoded = engine.decode(s.as_bytes())?;

        let (data, checksum) = decoded
            .split_last_chunk::<4>()
            .ok_or(ParseWitnessOutError::NoChecksum)?;

        let data = TinyBlob::try_from_slice(data)?;
        let wout = WitnessOut::from_strict_serialized::<{ u8::MAX as usize }>(data)?;

        if *checksum != wout.checksum() {
            return Err(ParseWitnessOutError::InvalidChecksum);
        }

        Ok(wout)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ParseWitnessOutError {
    /// witness output seal definition doesn't start with a necessary prefix `wout:`.
    NoPrefix,

    /// the provided witness output seal definition doesn't contain checksum.
    NoChecksum,

    /// checksum of the provided witness output seal definition is invalid.
    InvalidChecksum,

    /// invalid Base64 encoding in itness output seal definition - {0}.
    #[from]
    Base64(DecodeError),

    /// the length of encoded witness output seal definition string exceeds 255 chars.
    #[from(confinement::Error)]
    TooLong,

    /// invalid witness output seal definition binary data - {0}.
    #[from]
    Encoding(DeserializeError),
}
