// RGB wallet library for smart contracts on Bitcoin & Lightning network
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

use std::collections::{BTreeMap, HashMap};
use std::error::Error;

use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bp::seals::txout::CloseMethod;
use bp::Outpoint;
use rgb::{AssignmentType, ContractId, GraphSeal, Opout};
use rgbstd::containers::{Bindle, BuilderSeal, Transfer};
use rgbstd::interface::{BuilderError, ContractSuppl, TypedState, VelocityClass};
use rgbstd::persistence::{ConsignerError, Inventory, InventoryError, Stash};

use crate::invoice::Beneficiary;
use crate::psbt::{DbcPsbtError, PsbtDbc, RgbExt, RgbPsbtError};
use crate::RgbInvoice;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum PayError<E1: Error, E2: Error>
where E1: From<E2>
{
    /// not enough PSBT output found to put all required state (can't add
    /// assignment {1} for {0}-velocity state).
    #[display(doc_comments)]
    NoBlankChange(VelocityClass, AssignmentType),

    /// PSBT lacks beneficiary output matching the invoice.
    #[display(doc_comments)]
    NoBeneficiaryOutput,

    /// state provided via PSBT inputs is not sufficient to cover invoice state
    /// requirements.
    InsufficientState,

    #[from]
    Inventory(InventoryError<E1>),

    #[from]
    Builder(BuilderError),

    #[from]
    Consigner(ConsignerError<E1, E2>),

    #[from]
    RgbPsbt(RgbPsbtError),

    #[from]
    DbcPsbt(DbcPsbtError),
}

pub trait InventoryWallet: Inventory {
    /// # Assumptions
    ///
    /// 1. If PSBT output has BIP32 derivation information it belongs to our
    /// wallet - except when it matches address from the invoice.
    fn pay(
        &mut self,
        invoice: RgbInvoice,
        psbt: &mut Psbt,
        method: CloseMethod,
    ) -> Result<Bindle<Transfer>, PayError<Self::Error, <Self::Stash as Stash>::Error>>
    where
        Self::Error: From<<Self::Stash as Stash>::Error>,
    {
        // 1. Prepare the data
        let contract_id = invoice.contract;
        let mut main_builder = self.transition_builder(contract_id, invoice.iface.clone())?;

        let (beneficiary_output, beneficiary) = match invoice.beneficiary {
            Beneficiary::BlindedSeal(seal) => {
                let seal = BuilderSeal::Concealed(seal);
                (None, seal)
            }
            Beneficiary::WitnessUtxo(addr) => {
                let vout = psbt
                    .unsigned_tx
                    .output
                    .iter()
                    .enumerate()
                    .find(|(_, txout)| txout.script_pubkey == addr.script_pubkey())
                    .map(|(no, _)| no as u32)
                    .ok_or(PayError::NoBeneficiaryOutput)?;
                let seal = BuilderSeal::Revealed(GraphSeal::new_vout(method, vout));
                (Some(vout), seal)
            }
        };
        let prev_outputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .map(|outpoint| Outpoint::new(outpoint.txid.to_byte_array().into(), outpoint.vout))
            .collect::<Vec<_>>();

        // Classify PSBT outputs which can be used for assignments
        let mut out_classes = HashMap::<VelocityClass, Vec<u32>>::new();
        for (no, outp) in psbt.outputs.iter().enumerate() {
            if beneficiary_output == Some(no as u32) {
                continue;
            }
            if let Some(class) = outp
                // NB: Here we assume that if output has derivation information it belongs to our wallet.
                .bip32_derivation
                .first_key_value()
                .and_then(|(_, src)| src.1.into_iter().rev().skip(1).next())
                .copied()
                .map(u32::from)
                .and_then(|index| u8::try_from(index).ok())
                .and_then(|index| VelocityClass::try_from(index).ok())
            {
                out_classes.entry(class).or_default().push(no as u32);
            }
        }
        let mut out_classes = out_classes
            .into_iter()
            .map(|(class, indexes)| (class, indexes.into_iter().cycle()))
            .collect::<HashMap<_, _>>();
        let mut output_for_assignment = |suppl: Option<&ContractSuppl>,
                                         assignment_type: AssignmentType|
         -> Result<BuilderSeal<GraphSeal>, PayError<_, _>> {
            let velocity = suppl
                .and_then(|suppl| suppl.owned_state.get(&assignment_type))
                .map(|s| s.velocity_class)
                .unwrap_or_default();
            let vout = out_classes
                .get_mut(&velocity)
                .and_then(|iter| iter.next())
                .ok_or(PayError::NoBlankChange(velocity, assignment_type))?;
            let seal = GraphSeal::new_vout(method, vout);
            Ok(BuilderSeal::Revealed(seal))
        };

        // 2. Prepare and self-consume transition
        if let Some(op_name) = invoice.operation {
            main_builder = main_builder.set_transition_type(op_name)?;
        }
        let assignment_name = invoice
            .assignment
            .as_ref()
            .or_else(|| main_builder.default_assignment().ok())
            .ok_or(BuilderError::NoDefaultAssignment)?;
        let assignment_id = main_builder
            .assignments_type(assignment_name)
            .ok_or(BuilderError::InvalidStateType(assignment_name.clone()))?;
        // TODO: select supplement basing on the signer trust level
        let suppl = self
            .contract_suppl(contract_id)
            .and_then(|set| set.first())
            .cloned();
        let mut sum_inputs = 0u64;
        for (opout, state) in self.state_for_outpoints(contract_id, prev_outputs.iter().copied())? {
            main_builder = main_builder.add_input(opout)?;
            if opout.ty != assignment_id {
                let seal = output_for_assignment(suppl.as_ref(), opout.ty)?;
                main_builder = main_builder
                    .add_input(opout)?
                    .add_raw_state(opout.ty, seal, state)?;
            } else if let TypedState::Amount(value) = state {
                sum_inputs += value;
            }
        }
        // Add change
        if sum_inputs > invoice.value {
            let seal = output_for_assignment(suppl.as_ref(), assignment_id)?;
            let change = TypedState::Amount(sum_inputs - invoice.value);
            main_builder = main_builder.add_raw_state(assignment_id, seal, change)?;
        } else if sum_inputs < invoice.value {
            return Err(PayError::InsufficientState);
        }
        let transition = main_builder
            .add_raw_state(assignment_id, beneficiary, TypedState::Amount(invoice.value))?
            .complete_transition()?;

        // 3. Prepare and self-consume other transitions
        let mut spent_state = HashMap::<ContractId, BTreeMap<Opout, TypedState>>::new();
        for outpoint in prev_outputs {
            for id in self.contracts_by_outpoints([outpoint])? {
                if id == contract_id {
                    continue;
                }
                spent_state
                    .entry(id)
                    .or_default()
                    .extend(self.state_for_outpoints(id, [outpoint])?);
            }
        }
        // Construct blank transitions, self-consume them
        let mut other_transitions = Vec::with_capacity(spent_state.len());
        for (id, opouts) in spent_state {
            let mut blank_builder = self
                .transition_builder(id, invoice.iface.clone())?
                .do_blank_transition()?;
            // TODO: select supplement basing on the signer trust level
            let suppl = self.contract_suppl(id).and_then(|set| set.first());

            for (opout, state) in opouts {
                let seal = output_for_assignment(suppl, opout.ty)?;
                blank_builder = blank_builder
                    .add_input(opout)?
                    .add_raw_state(opout.ty, seal, state)?;
            }

            other_transitions.push(blank_builder.complete_transition()?);
        }

        // 4. Add transitions to PSBT
        psbt.push_rgb_transition(transition)?;
        for transition in other_transitions {
            psbt.push_rgb_transition(transition)?;
        }
        // Here we assume the provided PSBT is final: its inputs and outputs will not be
        // modified after calling this method.
        let bundles = psbt.rgb_bundles()?;
        // TODO: Make it two-staged, such that PSBT editing will be allowed by other
        //       participants as required for multiparty protocols like coinjoin.
        psbt.rgb_bundle_to_lnpbp4()?;
        psbt.dbc_conclude(method)?;
        // TODO: Ensure that with PSBTv2 we remove flag allowing PSBT modification.

        // 4. Prepare transfer
        let witness_txid = psbt.unsigned_tx.txid();
        for (id, bundle) in bundles {
            self.consume_transition_bundle(id, &bundle, witness_txid.to_byte_array().into())?;
        }
        let transfer = self.transfer(contract_id, [beneficiary])?;

        Ok(transfer)
    }
}

impl<I> InventoryWallet for I where I: Inventory {}
