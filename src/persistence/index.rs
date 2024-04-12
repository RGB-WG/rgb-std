// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
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
use std::fmt::Debug;

use rgb::{
    validation, BundleId, ContractId, GraphSeal, OpId, Opout, Transition, TransitionBundle, XChain,
    XOutpoint, XOutputSeal, XWitnessId,
};

use crate::containers::{BundledWitness, Contract, SealWitness, Transfer};
use crate::interface::{ContractIface, IfaceRef};
use crate::persistence::PersistedState;
use crate::resolvers::ResolveHeight;
use crate::SecretSeal;

pub trait IndexProvider: Debug + IndexReadProvider + IndexWriteProvider {}

pub trait IndexReadProvider {
    type Error: Error;

    fn contract_iface(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
    ) -> Result<ContractIface, Self::Error>;

    fn contracts_by_outputs(
        &self,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<BTreeSet<ContractId>, Self::Error>;

    fn public_opouts(&self, contract_id: ContractId) -> Result<BTreeSet<Opout>, Self::Error>;

    fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<BTreeSet<Opout>, Self::Error>;

    fn opouts_by_terminals(
        &self,
        terminals: impl IntoIterator<Item = XChain<SecretSeal>>,
    ) -> Result<BTreeSet<Opout>, Self::Error>;

    fn state_for_outpoints(
        &self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<XOutpoint>>,
    ) -> Result<BTreeMap<(Opout, XOutputSeal), PersistedState>, Self::Error>;

    fn op_bundle_id(&self, opid: OpId) -> Result<BundleId, Self::Error>;

    fn bundled_witness(&self, bundle_id: BundleId) -> Result<BundledWitness, Self::Error>;

    fn transition(&self, opid: OpId) -> Result<&Transition, Self::Error>;

    fn seal_secrets(&self) -> Result<BTreeSet<XChain<GraphSeal>>, Self::Error>;
}

pub trait IndexWriteProvider {
    type Error: Error;

    fn import_contract<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, Self::Error>
    where
        R::Error: 'static;

    fn accept_transfer<R: ResolveHeight>(
        &mut self,
        transfer: Transfer,
        resolver: &mut R,
        force: bool,
    ) -> Result<validation::Status, Self::Error>
    where
        R::Error: 'static;

    /// # Safety
    ///
    /// Calling this method may lead to including into the stash asset
    /// information which may be invalid.
    fn import_contract_force<R: ResolveHeight>(
        &mut self,
        contract: Contract,
        resolver: &mut R,
    ) -> Result<validation::Status, Self::Error>
    where
        R::Error: 'static;

    fn consume_witness(&mut self, witness: SealWitness) -> Result<(), Self::Error>;

    fn consume_bundle(
        &mut self,
        contract_id: ContractId,
        bundle: TransitionBundle,
        witness_id: XWitnessId,
    ) -> Result<(), Self::Error>;

    fn store_seal_secret(&mut self, seal: XChain<GraphSeal>) -> Result<(), Self::Error>;
}
