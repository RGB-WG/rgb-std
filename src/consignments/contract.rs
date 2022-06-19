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

use std::collections::BTreeSet;
use std::io::Read;

use bitcoin::Txid;
use commit_verify::{commit_encode, ConsensusCommit};
use rgb_core::{
    schema, BundleId, ConsistencyError, Extension, Genesis, Node, NodeId, Schema, Transition,
    TransitionBundle,
};
use strict_encoding::StrictDecode;

use super::{AnchoredBundles, ConsignmentEndpoints, ConsignmentId, ExtensionList};

pub const RGB_CONTRACT_VERSION: u8 = 0;

#[cfg_attr(
    all(feature = "cli", feature = "serde"),
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Clone, PartialEq, Eq, Debug, StrictEncode)]
pub struct Contract {
    /// Version, used internally
    version: u8,

    pub schema: Schema,

    pub root_schema: Option<Schema>,

    /// Genesis data
    pub genesis: Genesis,

    pub endpoints: ConsignmentEndpoints,

    /// Data on all anchored state transitions contained in the consignments
    pub anchored_bundles: AnchoredBundles,

    /// Data on all state extensions contained in the consignments
    pub state_extensions: ExtensionList,
}

impl commit_encode::Strategy for Contract {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl ConsensusCommit for Contract {
    type Commitment = ConsignmentId;
}

impl StrictDecode for Contract {
    fn strict_decode<D: Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        let contract = strict_decode_self!(d; version, schema, root_schema, genesis, endpoints, anchored_bundles, state_extensions);
        if contract.version != RGB_CONTRACT_VERSION {
            return Err(strict_encoding::Error::UnsupportedDataStructure(
                "Contract container versions above 0 are not supported",
            ));
        }
        Ok(contract)
    }
}

impl Contract {
    #[inline]
    pub fn with(
        schema: Schema,
        root_schema: Option<Schema>,
        genesis: Genesis,
        endpoints: ConsignmentEndpoints,
        anchored_bundles: AnchoredBundles,
        state_extensions: ExtensionList,
    ) -> Contract {
        Self {
            version: RGB_CONTRACT_VERSION,
            schema,
            root_schema,
            genesis,
            endpoints,
            state_extensions,
            anchored_bundles,
        }
    }

    #[inline]
    pub fn id(&self) -> ConsignmentId { self.clone().consensus_commit() }

    #[inline]
    pub fn version(&self) -> u8 { self.version }
}
