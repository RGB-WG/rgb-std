// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use amplify::confinement::Confined;
use amplify::Wrapper;
use bp::Outpoint;
use commit_verify::mpc::LeafNotKnown;
use rgb::validation::AnchoredBundle;
use rgb::{ContractId, OpId, Operation, TxoSeal};

use crate::accessors::{BundleExt, TypedAssignsExt};
use crate::containers::{Consignment, Terminal, TerminalSeal};
use crate::persistence::{Inventory, InventoryError, InventoryInconsistency, Stash, StashError};
use crate::Txid;

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BuilderError<E: Error> {
    /// unable to construct consignment: too many terminals provided.
    TooManyTerminals,

    /// unable to construct consignment: history size too large, resulting in
    /// too many transitions.
    TooManyBundles,

    #[display(inner)]
    #[from]
    LeafNotKnown(LeafNotKnown),

    #[display(inner)]
    #[from]
    #[from(InventoryInconsistency)]
    InventoryError(InventoryError<E>),
}

impl<E1: Error, E2: Error> From<StashError<E1>> for BuilderError<E2>
where InventoryError<E2>: From<StashError<E1>>
{
    fn from(err: StashError<E1>) -> Self { Self::InventoryError(err.into()) }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum OutpointFilter {
    All,
    Only(BTreeSet<Outpoint>),
}

impl OutpointFilter {
    pub fn includes(&self, outpoint: Outpoint) -> bool {
        match self {
            OutpointFilter::All => true,
            OutpointFilter::Only(set) => set.contains(&outpoint),
        }
    }
}

#[derive(Debug)]
pub struct ConsignmentBuilder<'inventory, I: Inventory> {
    inventory: &'inventory mut I,
    contract_id: ContractId,
    anchored_bundles: BTreeMap<Txid, AnchoredBundle>,
    terminal: Vec<Terminal>,
    terminal_inputs: Vec<OpId>,
}

impl<'inventory, I: Inventory> ConsignmentBuilder<'inventory, I> {
    pub fn new(contract_id: ContractId, inventory: &'inventory mut I) -> Self {
        ConsignmentBuilder {
            inventory,
            contract_id,
            anchored_bundles: empty![],
            terminal: vec![],
            terminal_inputs: vec![],
        }
    }

    // TODO: Support state extensions
    pub fn process(
        mut self,
        op_ids: impl IntoIterator<Item = OpId>,
        outpoint_filter: &OutpointFilter,
    ) -> Result<Self, BuilderError<I::Error>> {
        let contract_id = self.contract_id;

        for transition_id in op_ids {
            // Ignoring genesis
            if transition_id.as_inner() == contract_id.as_inner() {
                continue;
            }

            let transition = self.inventory.transition(transition_id)?;
            let witness_txid = self.inventory.witness_txid(transition_id)?;

            let bundle = if let Some(anchored_bundle) = self.anchored_bundles.get_mut(&witness_txid)
            {
                &mut anchored_bundle.bundle
            } else {
                let anchor = self.inventory.anchor(witness_txid)?;
                let bundle = self.inventory.bundle(contract_id, witness_txid)?.clone();
                let anchor = anchor.to_merkle_proof(contract_id)?;
                let anchored_bundle = AnchoredBundle { anchor, bundle };
                self.anchored_bundles.insert(witness_txid, anchored_bundle);
                &mut self
                    .anchored_bundles
                    .get_mut(&witness_txid)
                    .expect("stdlib is broken")
                    .bundle
            };

            let bundle_id = bundle.bundle_id();
            for (_, assignments) in transition.assignments.iter() {
                for seal in assignments.filter_revealed_seals() {
                    let outpoint = seal.outpoint_or(witness_txid);
                    let seal_endpoint = TerminalSeal::from(seal);
                    if outpoint_filter.includes(outpoint) {
                        self.terminal.push(Terminal::with(bundle_id, seal_endpoint));
                        self.terminal_inputs
                            .extend(transition.prev_outs().into_iter().map(|out| out.op));
                    }
                }
            }

            bundle
                .reveal_transition(transition)
                .map_err(InventoryInconsistency::from)?;
        }

        Ok(self)
    }

    pub fn build(mut self) -> Result<Self, BuilderError<I::Error>> {
        // Collect all transitions between endpoints and genesis independently from
        // their type
        loop {
            let op_ids = self.terminal_inputs;
            self.terminal_inputs = vec![];
            self = self.process(op_ids, &OutpointFilter::All)?;
            if self.terminal_inputs.is_empty() {
                break;
            }
        }
        Ok(self)
    }

    pub fn finish<const TYPE: bool>(self) -> Result<Consignment<TYPE>, BuilderError<I::Error>> {
        let genesis = self.inventory.genesis(self.contract_id)?.clone();
        let schema_ifaces = self.inventory.schema(genesis.schema_id)?.clone();
        let mut consignment = Consignment::<TYPE>::new(schema_ifaces.schema, genesis);
        consignment.terminals =
            Confined::try_from_iter(self.terminal).map_err(|_| BuilderError::TooManyTerminals)?;
        consignment.bundles = Confined::try_from_iter(self.anchored_bundles.into_values())
            .map_err(|_| BuilderError::TooManyBundles)?;

        Ok(consignment)
    }
}
