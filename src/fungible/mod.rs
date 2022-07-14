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

//! RGB20 library for working with fungible asset types, operating under
//! schemata, defined with LNPBP-20 standard:
//! - Root RGB20 schema, returned by [`schema::schema()`] with id
//!   [`SCHEMA_ID_BECH32`]
//! - RGB20 subschema, returned by [`schema::subschema()`], prohibiting asset
//!   replacement procedure and having id [`SUBSCHEMA_ID_BECH32`]
//! - High-level RGB20 API performing asset issuance, transfers and other
//!   asset-management operations

pub mod amount;
pub mod allocation;
pub mod asset;
pub mod schema;
pub mod create;
pub mod transitions;

pub use asset::{Asset, Error};
pub use create::Rgb20;
pub use schema::{schema, subschema, SCHEMA_ID_BECH32, SUBSCHEMA_ID_BECH32};
