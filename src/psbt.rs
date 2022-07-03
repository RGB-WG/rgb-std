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

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::psbt::raw::ProprietaryKey;
use bitcoin::{Script, TxOut};
use commit_verify::{lnpbp4, TaggedHash};
use rgb_core::bundle::NoDataError;
use rgb_core::{reveal, ContractId, MergeReveal, Node, NodeId, Transition, TransitionBundle};
use strict_encoding::{StrictDecode, StrictEncode};
use wallet::psbt;
use wallet::psbt::{Output, Psbt};

use crate::Contract;

/// PSBT proprietary key prefix used for RGB.
pub const PSBT_RGB_PREFIX: &[u8] = b"RGB";

/// Proprietary key subtype for storing RGB contract consignment in global map.
pub const PSBT_GLOBAL_RGB_CONTRACT: u8 = 0x00;
/// Proprietary key subtype for storing RGB state transition in global map.
pub const PSBT_GLOBAL_RGB_TRANSITION: u8 = 0x01;
/// Proprietary key subtype for storing RGB state transition node id which consumes this input.
pub const PSBT_IN_RGB_CONSUMED_BY: u8 = 0x03;

/// Extension trait for static functions returning RGB-related proprietary keys.
pub trait ProprietaryKeyRgb {
    /// Constructs [`PSBT_GLOBAL_RGB_CONTRACT`] proprietary key.
    fn rgb_contract(contract_id: ContractId) -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_RGB_PREFIX.to_vec(),
            subtype: PSBT_GLOBAL_RGB_CONTRACT,
            key: contract_id.to_vec(),
        }
    }

    /// Constructs [`PSBT_GLOBAL_RGB_TRANSITION`] proprietary key.
    fn rgb_transition(node_id: NodeId) -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_RGB_PREFIX.to_vec(),
            subtype: PSBT_GLOBAL_RGB_TRANSITION,
            key: node_id.to_vec(),
        }
    }

    /// Constructs [`PSBT_IN_RGB_CONSUMED_BY`] proprietary key.
    fn rgb_in_consumed_by(contract_id: ContractId) -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_RGB_PREFIX.to_vec(),
            subtype: PSBT_IN_RGB_CONSUMED_BY,
            key: contract_id.to_vec(),
        }
    }
}

impl ProprietaryKeyRgb for ProprietaryKey {}

/// Errors processing RGB-related proprietary PSBT keys and their values.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum KeyError {
    /// The key contains invalid value
    #[from(strict_encoding::Error)]
    #[from(bitcoin::hashes::Error)]
    InvalidKeyValue,

    /// The key is already present, but has a different value
    AlreadySet,

    /// internal mismatch between RGB data stored in different keys. {0}
    InternalMismatch(String),

    /// state transition {0} already present in PSBT is not related to the state transition {1} which has to be added to RGB
    UnrelatedTransitions(NodeId, NodeId, reveal::Error),

    /// state transition bundle with zero transitions
    #[from(NoDataError)]
    EmptyData,
}

pub trait RgbExt {
    fn has_rgb_contract(&self, contract_id: ContractId) -> bool {
        self.rgb_contract_ids().contains(&contract_id)
    }

    fn rgb_contract_ids(&self) -> BTreeSet<ContractId>;

    fn rgb_contract(&self, contract_id: ContractId) -> Result<Option<Contract>, KeyError>;

    fn rgb_contract_consumers(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<(NodeId, u16)>, KeyError>;

    fn set_rgb_contract(&mut self, contract: Contract) -> Result<(), KeyError>;

    fn rgb_node_ids(&self, contract_id: ContractId) -> BTreeSet<NodeId>;

    fn rgb_transitions(&self, contract_id: ContractId) -> BTreeMap<NodeId, Transition> {
        self.rgb_node_ids(contract_id)
            .into_iter()
            .filter_map(|node_id| {
                self.rgb_transition(node_id)
                    .ok()
                    .flatten()
                    .map(|ts| (node_id, ts))
            })
            .collect()
    }

    fn rgb_transition(&self, node_id: NodeId) -> Result<Option<Transition>, KeyError>;

    fn push_rgb_transition(&mut self, transition: Transition) -> Result<bool, KeyError>;

    fn rgb_bundles(&self) -> Result<BTreeMap<ContractId, TransitionBundle>, KeyError> {
        self.rgb_contract_ids()
            .into_iter()
            .map(|contract_id| {
                let mut revealed: BTreeMap<Transition, BTreeSet<u16>> = bmap!();
                let mut concealed: BTreeMap<NodeId, BTreeSet<u16>> = bmap!();
                for (node_id, no) in self.rgb_contract_consumers(contract_id)? {
                    if let Some(transition) = self.rgb_transition(node_id)? {
                        revealed.entry(transition).or_default().insert(no);
                    } else {
                        concealed.entry(node_id).or_default().insert(no);
                    }
                }
                let bundle = TransitionBundle::with(revealed, concealed)?;
                Ok((contract_id, bundle))
            })
            .collect()
    }

    fn rgb_bundle_to_lnpbp4(&mut self) -> Result<usize, KeyError>;
}

impl RgbExt for Psbt {
    fn rgb_contract_ids(&self) -> BTreeSet<ContractId> {
        self.proprietary
            .keys()
            .filter(|prop_key| {
                prop_key.prefix == PSBT_RGB_PREFIX && prop_key.subtype == PSBT_GLOBAL_RGB_CONTRACT
            })
            .map(|prop_key| &prop_key.key)
            .filter_map(|key| ContractId::from_bytes(key).ok())
            .collect()
    }

    fn rgb_contract(&self, contract_id: ContractId) -> Result<Option<Contract>, KeyError> {
        self.proprietary
            .get(&ProprietaryKey::rgb_contract(contract_id))
            .map(|val| Contract::strict_deserialize(val).map_err(KeyError::from))
            .transpose()
    }

    fn rgb_contract_consumers(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<(NodeId, u16)>, KeyError> {
        let mut consumers: BTreeSet<(NodeId, u16)> = bset! {};
        for (no, input) in self.inputs.iter().enumerate() {
            if let Some(node_id) = input.rgb_consumer(contract_id)? {
                consumers.insert((node_id, no as u16));
            }
        }
        Ok(consumers)
    }

    fn set_rgb_contract(&mut self, contract: Contract) -> Result<(), KeyError> {
        let contract_id = contract.contract_id();
        if self.has_rgb_contract(contract_id) {
            return Err(KeyError::AlreadySet);
        }
        let serialized_contract = contract.strict_serialize().map_err(KeyError::from)?;
        self.proprietary.insert(
            ProprietaryKey::rgb_contract(contract_id),
            serialized_contract,
        );
        Ok(())
    }

    fn rgb_node_ids(&self, contract_id: ContractId) -> BTreeSet<NodeId> {
        self.inputs
            .iter()
            .filter_map(|input| {
                input
                    .proprietary
                    .get(&ProprietaryKey::rgb_contract(contract_id))
                    .and_then(|val| NodeId::strict_deserialize(val).ok())
            })
            .collect()
    }

    fn rgb_transition(&self, node_id: NodeId) -> Result<Option<Transition>, KeyError> {
        self.proprietary
            .get(&ProprietaryKey::rgb_transition(node_id))
            .map(|val| Transition::strict_deserialize(val).map_err(KeyError::from))
            .transpose()
    }

    fn push_rgb_transition(&mut self, mut transition: Transition) -> Result<bool, KeyError> {
        let node_id = transition.node_id();
        let prev_transition = self.rgb_transition(node_id).ok().flatten();
        if let Some(ref prev_transition) = prev_transition {
            transition = transition
                .merge_reveal(prev_transition.clone())
                .map_err(|err| {
                    KeyError::UnrelatedTransitions(prev_transition.node_id(), node_id, err)
                })?;
        }
        let serialized_transition = transition.strict_serialize()?;
        self.proprietary.insert(
            ProprietaryKey::rgb_transition(node_id),
            serialized_transition,
        );
        Ok(prev_transition.is_none())
    }

    fn rgb_bundle_to_lnpbp4(&mut self) -> Result<usize, KeyError> {
        let bundles = self.rgb_bundles()?;

        let output = match self
            .outputs
            .iter_mut()
            .find(|output| output.is_tapret_host())
        {
            Some(output) => output,
            None => {
                let output = Output::new(self.outputs.len(), TxOut {
                    value: 0,
                    script_pubkey: Script::new_op_return(&[0u8; 32]),
                });
                self.outputs.push(output);
                self.outputs.last_mut().expect("just inserted")
            }
        };

        let len = bundles.len();
        for (contract_id, bundle) in bundles {
            output
                .set_lnpbp4_message(
                    lnpbp4::ProtocolId::from(contract_id),
                    bundle.bundle_id().into(),
                )
                .map_err(|_| KeyError::AlreadySet)?;
        }

        Ok(len)
    }
}

pub trait RgbInExt {
    fn rgb_consumer(&self, contract_id: ContractId) -> Result<Option<NodeId>, KeyError>;

    /// Adds information about state transition consuming this PSBT input.
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
    fn set_rgb_consumer(
        &mut self,
        contract_id: ContractId,
        node_id: NodeId,
    ) -> Result<bool, KeyError>;
}

impl RgbInExt for psbt::Input {
    fn rgb_consumer(&self, contract_id: ContractId) -> Result<Option<NodeId>, KeyError> {
        self.proprietary
            .get(&ProprietaryKey::rgb_in_consumed_by(contract_id))
            .map(NodeId::from_bytes)
            .transpose()
            .map_err(KeyError::from)
    }

    fn set_rgb_consumer(
        &mut self,
        contract_id: ContractId,
        node_id: NodeId,
    ) -> Result<bool, KeyError> {
        match self.rgb_consumer(contract_id)? {
            None => {
                self.proprietary.insert(
                    ProprietaryKey::rgb_in_consumed_by(contract_id),
                    node_id.as_slice().to_vec(),
                );
                Ok(true)
            }
            Some(id) if id == node_id => Ok(false),
            Some(_) => Err(KeyError::AlreadySet),
        }
    }
}
