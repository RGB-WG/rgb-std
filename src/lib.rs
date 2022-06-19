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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate stens;
#[macro_use]
extern crate rgb_core;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

mod consignment;
mod disclosure;
mod graph;
mod iter;
mod stash;
mod schemata;
pub mod fungible;

pub mod prelude {
    pub use consignment::{
        ConsignmentEndpoints, ConsignmentId, FullConsignment, RGB_CONSIGNMENT_VERSION,
    };
    pub use disclosure::{Disclosure, DisclosureId, RGB_DISCLOSURE_VERSION};
    pub use iter::ChainIter;
    pub use rgb_core::prelude::*;
    pub use rgb_core::{field, secp256k1zkp, type_map};
    pub use schemata::rgb20;
    pub use stash::Stash;

    use super::*;
}

pub use prelude::*;
