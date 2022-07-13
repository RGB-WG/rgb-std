// RGB20 Library: high-level API to RGB fungible assets.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::btree_set;

use bitcoin::OutPoint;

use crate::{
    fungible::schema::schema, ConsignmentType, ContractState, InmemConsignment, NodeId, OwnedValue,
};

/// RGB20 asset information.
///
/// Structure presents complete set of RGB20 asset-related data which can be
/// extracted from the genesis or a consignment. It is not the source of the
/// truth, and the presence of the data in the structure does not imply their
/// validity, since the structure constructor does not validates blockchain or
/// LN-based transaction commitments or satisfaction of schema requirements.
///
/// The main reason of the structure is:
/// 1) to persist *cached* copy of the asset data without the requirement to
///    parse all stash transition each time in order to extract allocation
///    information;
/// 2) to present data from asset genesis or consignment for UI in convenient
///    form.
/// 3) to orchestrate generation of new state transitions taking into account
///    known asset information.
///
/// (1) is important for wallets, (2) is for more generic software, like
/// client-side-validated data explorers, developer & debugging tools etc and
/// (3) for asset-management software.
///
/// In both (2) and (3) case there is no need to persist the structure; genesis
/// /consignment should be persisted instead and the structure must be
/// reconstructed each time from that data upon the launch
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
pub struct Asset(ContractState);

impl Asset {
    /// Lists all known allocations for the given bitcoin transaction
    /// [`OutPoint`]
    pub fn known_coins(&self) -> btree_set::Iter<OwnedValue> {
        self.0.owned_values.iter()
    }

    /// Lists all known allocations for the given bitcoin transaction
    /// [`OutPoint`]
    pub fn outpoint_coins(&self, outpoint: OutPoint) -> Vec<OwnedValue> {
        self.known_coins()
            .filter(|a| a.seal == outpoint)
            .cloned()
            .collect()
    }
}

impl<T> TryFrom<&InmemConsignment<T>> for Asset
where
    T: ConsignmentType,
{
    type Error = Error;

    fn try_from(consignment: &InmemConsignment<T>) -> Result<Self, Self::Error> {
        let state = ContractState::from(consignment);
        let asset = Asset(state);
        asset.validate()?;
        Ok(asset)
    }
}

impl Asset {
    fn validate(&self) -> Result<(), Error> {
        if self.0.schema_id != schema().schema_id() {
            Err(Error::WrongSchemaId)?;
        }
        // TODO: Validate the state
        Ok(())
    }
}

/// Errors generated during RGB20 asset information parsing from the underlying
/// genesis or consignment data
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// genesis schema id does not match any of RGB20 schemata
    WrongSchemaId,

    /// genesis defines a seal referencing witness transaction while there
    /// can't be a witness transaction for genesis
    GenesisSeal,

    /// epoch seal definition for node {0} contains confidential data
    EpochSealConfidential(NodeId),

    /// nurn & replace seal definition for node {0} contains confidential data
    BurnSealConfidential(NodeId),

    /// inflation assignment (seal or state) for node {0} contains confidential
    /// data
    InflationAssignmentConfidential(NodeId),

    /// not of all epochs referenced in burn or burn & replace operation
    /// history are known from the consignment
    NotAllEpochsExposed,
}
