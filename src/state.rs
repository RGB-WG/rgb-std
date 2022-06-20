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

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::OutPoint;
use rgb_core::contract::attachment;
use rgb_core::schema::OwnedRightType;
use rgb_core::{data, AtomicValue, ContractId, NodeOutpoint};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_order, repr = u8)]
#[display(inner)]
pub enum State {
    #[display("void")]
    Void,
    Fungible(AtomicValue),
    NonFungible(data::Revealed),
    Attachment(attachment::Revealed),
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[display("{state}@{seal}")]
pub struct AssignedState {
    pub seal: OutPoint,
    pub state: State,
    pub outpoint: NodeOutpoint,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
pub struct ContractState {
    pub contract_id: ContractId,
    pub assignments: BTreeMap<OwnedRightType, BTreeSet<AssignedState>>,
}
