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

// TODO: Implement state transition ops for PSBT

use std::collections::BTreeSet;

use bitcoin::psbt::raw::ProprietaryKey;
use commit_verify::TaggedHash;
use rgb_core::{ContractId, NodeId, Transition};
use wallet::psbt;
use wallet::psbt::Psbt;

use crate::Contract;

/// PSBT proprietary key prefix used for RGB.
pub const PSBT_RGB_PREFIX: &[u8] = b"RGB";

/// Proprietary key subtype for storing RGB contract consignment in global map.
pub const PSBT_GLOBAL_RGB_CONTRACT: u8 = 0x00;
/// Proprietary key subtype for storing RGB state transition in global map.
pub const PSBT_GLOBAL_RGB_TRANSITION: u8 = 0x01;
/// Proprietary key subtype for storing RGB node id in input map.
pub const PSBT_IN_RGB_NODE_ID: u8 = 0x03;

/// Extension trait for static functions returning RGB-related proprietary keys.
pub trait ProprietaryKeyRgb {
    /// Constructs [`PSBT_GLOBAL_RGB_CONTRACT`] proprietary key.
    fn rgb_contract() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_RGB_PREFIX.to_vec(),
            subtype: PSBT_GLOBAL_RGB_CONTRACT,
            key: vec![],
        }
    }

    /// Constructs [`PSBT_GLOBAL_RGB_TRANSITION`] proprietary key.
    fn rgb_transition() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_RGB_PREFIX.to_vec(),
            subtype: PSBT_GLOBAL_RGB_TRANSITION,
            key: vec![],
        }
    }

    /// Constructs [`PSBT_IN_RGB_NODE_ID`] proprietary key.
    fn rgb_node_id(contract_id: ContractId) -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_RGB_PREFIX.to_vec(),
            subtype: PSBT_IN_RGB_NODE_ID,
            key: contract_id.to_bytes().to_vec(),
        }
    }
}

impl ProprietaryKeyRgb for ProprietaryKey {}

/// Errors processing RGB-related proprietary PSBT keys and their values.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum KeyError {
    /// The key contains invalid value
    #[from(strict_encoding::Error)]
    #[from(bitcoin::hashes::Error)]
    InvalidKeyValue,

    /// The key is already present, but has a different value
    AlreadySet,
}

pub trait RgbExt {
    fn has_rgb_contract(&self, contract_id: ContractId) -> bool {
        self.rgb_contracts().contains(&contract_id)
    }

    fn rgb_contracts(&self) -> BTreeSet<ContractId>;

    fn merge_rgb_transition(
        &self,
        contract: Contract,
        transition: Transition,
    ) -> Result<bool, KeyError>;
}

pub trait RgbInExt {
    fn rgb_node(&self, contract_id: ContractId) -> Result<Option<NodeId>, KeyError>;

    /// Adds information about state transition to the PSBT input.
    ///
    /// # Returns
    ///
    /// `Ok(false)`, if the same node id under the same contract was already present in the input.
    /// `Ok(true)`, if the id node was successfully added to the input
    ///
    /// # Errors
    ///
    /// If the input already contains [`PSBT_IN_RGB_NODE_ID`] key with the given `contract_id` but
    /// referencing different [`NodeId`].
    fn add_rgb_node(&mut self, contract_id: ContractId, node_id: NodeId) -> Result<bool, KeyError>;
}

impl RgbExt for Psbt {
    fn rgb_contracts(&self) -> BTreeSet<ContractId> { todo!() }

    fn merge_rgb_transition(
        &self,
        contract: Contract,
        transition: Transition,
    ) -> Result<bool, KeyError> {
        // DO not forget to merge contract
        todo!()
    }
}

impl RgbInExt for psbt::Input {
    fn rgb_node(&self, contract_id: ContractId) -> Result<Option<NodeId>, KeyError> {
        self.proprietary
            .get(&ProprietaryKey::rgb_node_id(contract_id))
            .map(Vec::as_slice)
            .map(NodeId::from_slice)
            .transpose()
            .map_err(KeyError::from)
    }

    fn add_rgb_node(&mut self, contract_id: ContractId, node_id: NodeId) -> Result<bool, KeyError> {
        match self.rgb_node(contract_id)? {
            None => {
                self.proprietary.insert(
                    ProprietaryKey::rgb_node_id(contract_id),
                    node_id.as_slice().to_vec(),
                );
                Ok(true)
            }
            Some(id) if id == node_id => Ok(false),
            Some(_) => Err(KeyError::AlreadySet),
        }
    }
}
