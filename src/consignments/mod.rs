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

mod transfer;
mod id;
mod contract;
mod container;
mod graph;
mod iter;

use commit_verify::lnpbp4;
use rgb_core::{Anchor, BundleId, Extension, SealEndpoint, TransitionBundle};
use strict_encoding::LargeVec;

pub use self::container::{InmemConsignment, RGB_INMEM_CONSIGNMENT_VERSION};
pub use self::id::ConsignmentId;
pub use self::iter::{ChainIter, MeshIter};

pub type AnchoredBundles = LargeVec<(Anchor<lnpbp4::MerkleProof>, TransitionBundle)>;
pub type ExtensionList = LargeVec<Extension>;
pub type ConsignmentEndpoints = Vec<(BundleId, SealEndpoint)>;

pub trait ConsignmentType: Clone + Eq + Default {}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub struct TransferConsignment;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub struct ContractConsignment;

impl ConsignmentType for TransferConsignment {}
impl ConsignmentType for ContractConsignment {}

pub type StateTransfer = InmemConsignment<TransferConsignment>;
pub type Contract = InmemConsignment<ContractConsignment>;
