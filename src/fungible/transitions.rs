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

use std::collections::BTreeSet;

use bitcoin::OutPoint;
use bp::seals::txout::ExplicitSeal;

use crate::fungible::{
    allocation::{AllocationMap, AllocationValueMap, AllocationValueVec},
    schema::{OwnedRightType, TransitionType},
    Asset,
};
use crate::prelude::*;

/// Errors happening during construction of RGB-20 asset state transitions
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum Error {
    /// input {0} is not related to the contract
    UnrelatedInput(OutPoint),

    /// sum of inputs and outputs is not equal
    InputsNotEqualOutputs,

    /// issue allowance {allowed} for the provided set of issue-controlling
    /// rights is insufficient to issue the requested amount {requested}
    InsufficientIssueAllowance {
        /// Allowed issue value
        allowed: AtomicValue,
        /// Requested issue value
        requested: AtomicValue,
    },

    /// the requested supply {requested} does not match the total supply
    /// {assigned} allocated to the owned rights consumed by the operation
    SupplyMismatch {
        /// Assigned supply change rights
        assigned: AtomicValue,
        /// Requested supply change
        requested: AtomicValue,
    },

    /// method was provided with a set of seals for owned rights which are not
    /// a part of the asset data: {0:?}
    UnknownSeals(BTreeSet<OutPoint>),
}

impl Asset {
    /// Performs secondary issue closing an inflation-controlling seal over
    /// inflation state transition, which is constructed and returned by this
    /// function
    pub fn inflate(
        &self,
        _closing: BTreeSet<OutPoint>,
        _next_inflation: AllocationValueMap,
        _allocations: AllocationValueVec,
    ) -> Result<Transition, Error> {
        todo!()
    }

    /// Opens a new epoch by closing epoch-controlling seal over epoch opening
    /// state transition, which is constructed and returned by this function
    pub fn epoch(
        &self,
        _closing: OutPoint,
        _next_epoch: Option<ExplicitSeal>,
        _burning_seal: Option<ExplicitSeal>,
    ) -> Result<Transition, Error> {
        todo!()
    }

    /// Burns certain amount of the asset by closing burn-controlling seal over
    /// proof-of-burn state transition, which is constructed and returned by
    /// this function
    pub fn burn(
        &self,
        _closing: OutPoint,
        _burned_value: AtomicValue,
        _burned_utxos: BTreeSet<OutPoint>,
        _next_burn: Option<ExplicitSeal>,
    ) -> Result<Transition, Error> {
        todo!()
    }

    /// Burns and re-allocates certain amount of the asset by closing
    /// burn-controlling seal over proof-of-burn state transition, which is
    /// constructed and returned by this function
    pub fn burn_replace(
        &self,
        _closing: OutPoint,
        _burned_value: AtomicValue,
        _burned_utxos: BTreeSet<OutPoint>,
        _next_burn: Option<ExplicitSeal>,
        _allocations: AllocationValueVec,
    ) -> Result<Transition, Error> {
        todo!()
    }

    /// Creates a fungible asset-specific state transition (i.e. RGB-20
    /// schema-based) given an asset information, inputs and desired outputs
    pub fn transfer(
        &self,
        inputs: BTreeSet<OutPoint>,
        payment: EndpointValueMap,
        change: SealValueMap,
    ) -> Result<Transition, Error> {
        // Collecting all input allocations
        let mut input_usto = Vec::<OwnedValue>::new();
        for outpoint in inputs {
            let coins = self.outpoint_coins(outpoint);
            if coins.is_empty() {
                Err(Error::UnrelatedInput(outpoint))?
            }
            input_usto.extend(coins);
        }
        // Computing sum of inputs
        let input_amounts: Vec<_> = input_usto.iter().map(|coin| coin.state).collect();
        let total_inputs = input_amounts
            .iter()
            .fold(0u64, |acc, coin| acc + coin.value);
        let total_outputs = change.sum() + payment.sum();

        if total_inputs != total_outputs {
            Err(Error::InputsNotEqualOutputs)?
        }

        let assignments = type_map! {
            OwnedRightType::Assets =>
            TypedAssignments::zero_balanced(input_amounts, change, payment)
        };

        let mut parent = ParentOwnedRights::default();
        for coin in input_usto {
            parent
                .entry(coin.outpoint.node_id)
                .or_insert_with(|| empty!())
                .entry(OwnedRightType::Assets.into())
                .or_insert_with(|| empty!())
                .push(coin.outpoint.no);
        }

        let transition = Transition::with(
            TransitionType::Transfer,
            empty!(),
            empty!(),
            assignments.into(),
            empty!(),
            parent,
        );

        Ok(transition)
    }
}
