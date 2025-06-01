// Standard Library for RGB smart contracts
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

use alloc::collections::BTreeSet;
use core::error::Error as StdError;
use core::fmt::Debug;
use core::marker::PhantomData;
use core::num::NonZeroU64;
use std::cmp::Ordering;
use std::collections::HashSet;

use amplify::confinement::SmallOrdMap;
use hypersonic::Opid;
use rgb::RgbSeal;

use crate::CellAddr;

/// The status of the witness transaction.
///
/// Note on comparison:
/// the ordering is done in a way that more trustfull status is always greater than less trustfull.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Default)]
#[display(lowercase)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub enum WitnessStatus {
    /// No witness, which is the case for genesis operations.
    Genesis,

    /// Valid public witness included in the current consensus at a specific height, which,
    /// however, may be eventually re-orged.
    ///
    /// A zero height (used by Bitcoin genesis which can't contain any RGB operation) is used for
    /// the operations which do not have witness (genesis operation) - see [`Self::Genesis`].
    #[display(inner)]
    Mined(NonZeroU64),

    /// Indicates offchain status where the used is in a full control over transaction execution
    /// and the transaction can't be replaced (RBFed) without the receiver participation - for
    /// instance, like in lightning channel transactions (but only for the current channel
    /// state).
    Offchain,

    /// Indicates known public witness which can be replaced or RBF'ed without the control of the
    /// receiving side.
    Tentative,

    /// Indicates past public witness which is no more valid - it is not included in the
    /// blockchain, not present in the mempool, or belongs to the past Lightning channel state.
    #[default]
    Archived,
}

impl PartialOrd for WitnessStatus {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for WitnessStatus {
    fn cmp(&self, other: &Self) -> Ordering {
        <[u8; 8] as Ord>::cmp(&(*self).into(), &(*other).into())
    }
}

impl WitnessStatus {
    const GENESIS: u64 = 0;
    const TENTATIVE: u64 = u64::MAX ^ 0x01;
    const OFFCHAIN: u64 = u64::MAX ^ 0x02;
    const ARCHIVED: u64 = u64::MAX;

    pub fn is_mined(&self) -> bool { matches!(self, Self::Mined(_)) }
    pub fn is_valid(&self) -> bool { !matches!(self, Self::Archived) }
    pub fn is_tentative(&self) -> bool { matches!(self, Self::Tentative) }
    pub fn is_archived(&self) -> bool { matches!(self, Self::Archived) }
    pub fn is_offchain(&self) -> bool { matches!(self, Self::Offchain) }
}

// We use big-endian encoding of the inverted numbers to allow lexicographic sorting
impl From<[u8; 8]> for WitnessStatus {
    fn from(value: [u8; 8]) -> Self {
        match u64::MAX - u64::from_be_bytes(value) {
            Self::GENESIS => Self::Genesis,
            Self::ARCHIVED => Self::Archived,
            Self::TENTATIVE => Self::Tentative,
            Self::OFFCHAIN => Self::Offchain,
            height => Self::Mined(NonZeroU64::new(height).expect("GENESIS=0 is already checked")),
        }
    }
}

// We use big-endian encoding of the inverted numbers to allow lexicographic sorting
impl From<WitnessStatus> for [u8; 8] {
    fn from(value: WitnessStatus) -> Self {
        let fake_height = u64::MAX
            - match value {
                WitnessStatus::Genesis => WitnessStatus::GENESIS,
                WitnessStatus::Archived => WitnessStatus::ARCHIVED,
                WitnessStatus::Tentative => WitnessStatus::TENTATIVE,
                WitnessStatus::Offchain => WitnessStatus::OFFCHAIN,
                WitnessStatus::Mined(info) => info.get(),
            };
        fake_height.to_be_bytes()
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Witness<Seal: RgbSeal> {
    pub id: Seal::WitnessId,
    pub published: Seal::Published,
    pub client: Seal::Client,
    pub status: WitnessStatus,
    pub opids: HashSet<Opid>,
}

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize),
    serde(bound = "Seal::WitnessId: serde::Serialize, Seal::Definition: serde::Serialize")
)]
pub struct OpRels<Seal: RgbSeal> {
    pub opid: Opid,
    pub witness_ids: BTreeSet<Seal::WitnessId>,
    pub defines: SmallOrdMap<u16, Seal::Definition>,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub _phantom: PhantomData<Seal>,
}

/// Persistent storage for contract witness and single-use seal definition data.
pub trait Pile {
    /// Type of RGB seal used in the contract.
    type Seal: RgbSeal;

    /// Persistence configuration type.
    type Conf;

    type Error: StdError;

    /// Instantiates a new pile (persistence for contract witness data) using a given
    /// implementation-specific configuration.
    ///
    /// # Panics
    ///
    /// This call must not panic, and instead must return an error.
    ///
    /// # Blocking I/O
    ///
    /// This call MAY perform I/O operations.
    fn new(conf: Self::Conf) -> Result<Self, Self::Error>
    where Self: Sized;

    /// Loads a contract from persistence using the provided configuration.
    ///
    /// # Panics
    ///
    /// This call must not panic, and instead must return an error.
    ///
    /// # Blocking I/O
    ///
    /// This call MAY perform I/O operations.
    fn load(conf: Self::Conf) -> Result<Self, Self::Error>
    where Self: Sized;

    fn pub_witness(
        &self,
        wid: <Self::Seal as RgbSeal>::WitnessId,
    ) -> <Self::Seal as RgbSeal>::Published;

    fn has_witness(&self, wid: <Self::Seal as RgbSeal>::WitnessId) -> bool;

    fn cli_witness(
        &self,
        wid: <Self::Seal as RgbSeal>::WitnessId,
    ) -> <Self::Seal as RgbSeal>::Client;

    fn witness_status(&self, wid: <Self::Seal as RgbSeal>::WitnessId) -> WitnessStatus;

    fn witness_ids(&self) -> impl Iterator<Item = <Self::Seal as RgbSeal>::WitnessId>;

    fn witnesses(&self) -> impl Iterator<Item = Witness<Self::Seal>>;

    fn witnesses_since(
        &self,
        transaction_no: u64,
    ) -> impl Iterator<Item = <Self::Seal as RgbSeal>::WitnessId>;

    fn op_witness_ids(
        &self,
        opid: Opid,
    ) -> impl ExactSizeIterator<Item = <Self::Seal as RgbSeal>::WitnessId>;

    fn ops_by_witness_id(
        &self,
        wid: <Self::Seal as RgbSeal>::WitnessId,
    ) -> impl ExactSizeIterator<Item = Opid>;

    fn seal(&self, addr: CellAddr) -> Option<<Self::Seal as RgbSeal>::Definition>;

    fn seals(
        &self,
        opid: Opid,
        up_to: u16,
    ) -> SmallOrdMap<u16, <Self::Seal as RgbSeal>::Definition>;

    fn op_relations(&self, opid: Opid, up_to: u16) -> OpRels<Self::Seal>;

    /// Adds operation id and witness components, registers witness as `Archived`.
    ///
    /// If the anchor (client-side witness) is already present, MUST update the anchor.
    fn add_witness(
        &mut self,
        opid: Opid,
        wid: <Self::Seal as RgbSeal>::WitnessId,
        published: &<Self::Seal as RgbSeal>::Published,
        anchor: &<Self::Seal as RgbSeal>::Client,
        status: WitnessStatus,
    );

    fn add_seals(
        &mut self,
        opid: Opid,
        seals: SmallOrdMap<u16, <Self::Seal as RgbSeal>::Definition>,
    );

    /// # Panics
    ///
    /// If the witness is not known
    fn update_witness_status(
        &mut self,
        wid: <Self::Seal as RgbSeal>::WitnessId,
        status: WitnessStatus,
    );

    /// Commits information about all updated witness statuses ("mine" structure) to the
    /// persistence as a new database transaction.
    ///
    /// # Nota bene
    ///
    /// It is required to call this method after each witness update or consignment consumption.
    /// If the method was not called, the data won't persist, and on termination the program will
    /// panic.
    fn commit_transaction(&mut self);
}

#[cfg(test)]
mod tests {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use super::*;

    #[test]
    fn witness_status_bytes() {
        assert_eq!(
            WitnessStatus::Genesis,
            [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].into()
        );
        assert_eq!(<[u8; 8]>::from(WitnessStatus::Genesis), [
            0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ]);
    }

    #[test]
    fn witness_status_ordering() {
        assert!(WitnessStatus::Genesis > WitnessStatus::Mined(NonZeroU64::new(1).unwrap()));
        assert!(WitnessStatus::Mined(NonZeroU64::new(1).unwrap()) > WitnessStatus::Tentative);
        assert!(WitnessStatus::Tentative < WitnessStatus::Offchain);
        assert!(WitnessStatus::Offchain > WitnessStatus::Archived);
        assert!(WitnessStatus::Archived < WitnessStatus::Genesis);
    }
}
