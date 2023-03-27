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

use std::collections::BTreeMap;

use amplify::confinement;
use amplify::confinement::Confined;
use bitcoin::psbt::raw::ProprietaryKey;
use bitcoin::psbt::Output;
use commit_verify::mpc::{self, Message, ProtocolId};

/// PSBT proprietary key prefix used for LNPBP4 commitment-related data.
pub const PSBT_LNPBP4_PREFIX: &[u8] = b"LNPBP4";

/// Proprietary key subtype for storing LNPBP4 single commitment message under
/// some protocol in global map.
pub const PSBT_OUT_LNPBP4_MESSAGE: u8 = 0x00;
/// Proprietary key subtype for storing LNPBP4 entropy constant.
pub const PSBT_OUT_LNPBP4_ENTROPY: u8 = 0x01;
/// Proprietary key subtype for storing LNPBP4 requirement for a minimal tree
/// size.
pub const PSBT_OUT_LNPBP4_MIN_TREE_DEPTH: u8 = 0x04;

/// Extension trait for static functions returning LNPBP4-related proprietary
/// keys.
pub trait ProprietaryKeyLnpbp4 {
    fn lnpbp4_message(protocol_id: ProtocolId) -> ProprietaryKey;
    fn lnpbp4_entropy() -> ProprietaryKey;
    fn lnpbp4_min_tree_depth() -> ProprietaryKey;
}

impl ProprietaryKeyLnpbp4 for ProprietaryKey {
    /// Constructs [`PSBT_OUT_LNPBP4_MESSAGE`] proprietary key.
    fn lnpbp4_message(protocol_id: ProtocolId) -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_LNPBP4_PREFIX.to_vec(),
            subtype: PSBT_OUT_LNPBP4_MESSAGE,
            key: protocol_id.to_vec(),
        }
    }

    /// Constructs [`PSBT_OUT_LNPBP4_ENTROPY`] proprietary key.
    fn lnpbp4_entropy() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_LNPBP4_PREFIX.to_vec(),
            subtype: PSBT_OUT_LNPBP4_ENTROPY,
            key: empty!(),
        }
    }

    /// Constructs [`PSBT_OUT_LNPBP4_MIN_TREE_DEPTH`] proprietary key.
    fn lnpbp4_min_tree_depth() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_LNPBP4_PREFIX.to_vec(),
            subtype: PSBT_OUT_LNPBP4_MIN_TREE_DEPTH,
            key: empty!(),
        }
    }
}

/// Errors processing LNPBP4-related proprietary PSBT keys and their values.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Lnpbp4PsbtError {
    /// the key contains invalid value.
    #[from(bitcoin::hashes::Error)]
    InvalidKeyValue,

    /// message map produced from PSBT inputs exceeds maximum size bounds.
    #[from]
    MessageMapTooLarge(confinement::Error),

    /// the key is already present, but has a different value.
    AlreadySet,
}

pub trait OutputLnpbp4 {
    fn lnpbp4_message_map(&self) -> Result<mpc::MessageMap, Lnpbp4PsbtError>;
    fn lnpbp4_message(&self, protocol_id: ProtocolId) -> Option<Message>;
    fn lnpbp4_entropy(&self) -> Option<u64>;
    fn lnpbp4_min_tree_depth(&self) -> Option<u8>;
    fn set_lnpbp4_message(
        &mut self,
        protocol_id: ProtocolId,
        message: Message,
    ) -> Result<bool, Lnpbp4PsbtError>;
    fn set_lnpbp4_entropy(&mut self, entropy: u64) -> Result<bool, Lnpbp4PsbtError>;
    fn set_lnpbp4_min_tree_depth(&mut self, min_depth: u8) -> Option<u8>;
}

/// Extension trait for [`Output`] for working with proprietary LNPBP4
/// keys.
impl OutputLnpbp4 for Output {
    /// Returns [`lnpbp4::MessageMap`] constructed from the proprietary key
    /// data.
    fn lnpbp4_message_map(&self) -> Result<mpc::MessageMap, Lnpbp4PsbtError> {
        let map = self
            .proprietary
            .iter()
            .filter(|(key, _)| {
                // TODO: Error when only a single key is present
                key.prefix == PSBT_LNPBP4_PREFIX && key.subtype == PSBT_OUT_LNPBP4_MESSAGE
            })
            .map(|(key, val)| {
                Ok((
                    ProtocolId::from_slice(&key.key).ok_or(Lnpbp4PsbtError::InvalidKeyValue)?,
                    Message::from_slice(val).ok_or(Lnpbp4PsbtError::InvalidKeyValue)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, Lnpbp4PsbtError>>()?;
        Confined::try_from(map).map_err(Lnpbp4PsbtError::from)
    }

    /// Returns a valid LNPBP-4 [`Message`] associated with the given
    /// [`ProtocolId`], if any.
    ///
    /// We do not error on invalid data in order to support future update of
    /// this proprietary key to a standard one. In this case, the invalid
    /// data will be filtered at the moment of PSBT deserialization and this
    /// function will return `None` only in situations when the key is absent.
    fn lnpbp4_message(&self, protocol_id: ProtocolId) -> Option<Message> {
        let key = ProprietaryKey::lnpbp4_message(protocol_id);
        let data = self.proprietary.get(&key)?;
        Message::from_slice(data)
    }

    /// Returns a valid LNPBP-4 entropy value, if present.
    ///
    /// We do not error on invalid data in order to support future update of
    /// this proprietary key to a standard one. In this case, the invalid
    /// data will be filtered at the moment of PSBT deserialization and this
    /// function will return `None` only in situations when the key is absent.
    fn lnpbp4_entropy(&self) -> Option<u64> {
        let key = ProprietaryKey::lnpbp4_entropy();
        let data = self.proprietary.get(&key)?;
        if data.len() != 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(data);
        Some(u64::from_le_bytes(buf))
    }

    /// Returns a valid LNPBP-4 minimal tree depth value, if present.
    ///
    /// # Errors
    ///
    /// If the key is present, but it's value can't be deserialized as a valid
    /// minimal tree depth value.
    fn lnpbp4_min_tree_depth(&self) -> Option<u8> {
        let key = ProprietaryKey::lnpbp4_min_tree_depth();
        let data = self.proprietary.get(&key)?;
        if data.len() != 1 {
            return None;
        }
        Some(data[0])
    }

    /// Sets LNPBP4 [`Message`] for the given [`ProtocolId`].
    ///
    /// # Returns
    ///
    /// `true`, if the message was set successfully, `false` if this message was
    /// already present for this protocol.
    ///
    /// # Errors
    ///
    /// If the key for the given [`ProtocolId`] is already present and the
    /// message is different.
    fn set_lnpbp4_message(
        &mut self,
        protocol_id: ProtocolId,
        message: Message,
    ) -> Result<bool, Lnpbp4PsbtError> {
        let key = ProprietaryKey::lnpbp4_message(protocol_id);
        let val = message.to_vec();
        if let Some(v) = self.proprietary.get(&key) {
            if v != &val {
                return Err(Lnpbp4PsbtError::InvalidKeyValue);
            }
            return Ok(false);
        }
        self.proprietary.insert(key, val);
        Ok(true)
    }

    /// Sets LNPBP4 entropy value.
    ///
    /// # Returns
    ///
    /// `true`, if the entropy was set successfully, `false` if this entropy
    /// value was already set.
    ///
    /// # Errors
    ///
    /// If the entropy was already set with a different value than the provided
    /// one.
    fn set_lnpbp4_entropy(&mut self, entropy: u64) -> Result<bool, Lnpbp4PsbtError> {
        let key = ProprietaryKey::lnpbp4_entropy();
        let val = entropy.to_le_bytes().to_vec();
        if let Some(v) = self.proprietary.get(&key) {
            if v != &val {
                return Err(Lnpbp4PsbtError::InvalidKeyValue);
            }
            return Ok(false);
        }
        self.proprietary.insert(key, val);
        Ok(true)
    }

    /// Sets LNPBP4 min tree depth value.
    ///
    /// # Returns
    ///
    /// Previous minimal tree depth value, if it was present and valid - or None
    /// if the value was absent or invalid (the new value is still assigned).
    fn set_lnpbp4_min_tree_depth(&mut self, min_depth: u8) -> Option<u8> {
        let key = ProprietaryKey::lnpbp4_min_tree_depth();
        let val = vec![min_depth];
        let prev = self.lnpbp4_min_tree_depth();
        self.proprietary.insert(key, val).and_then(|_| prev)
    }
}
