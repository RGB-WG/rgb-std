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

use rgb::{validation, ContractId, SubSchema};

use crate::containers::{Bindle, Cert, ContentId, Contract};
use crate::interface::{ContractIface, Iface, IfaceId, IfaceImpl};

pub trait Inventory {
    type ImportError: std::error::Error;
    type ConsignError: std::error::Error;
    type InternalError: std::error::Error;

    fn import_sigs<I>(&mut self, content_id: ContentId, sigs: I) -> Result<(), Self::ImportError>
    where
        I: IntoIterator<Item = Cert>,
        I::IntoIter: ExactSizeIterator<Item = Cert>;

    fn import_schema(
        &mut self,
        schema: impl Into<Bindle<SubSchema>>,
    ) -> Result<validation::Status, Self::ImportError>;

    fn import_iface(
        &mut self,
        iface: impl Into<Bindle<Iface>>,
    ) -> Result<validation::Status, Self::ImportError>;

    fn import_iface_impl(
        &mut self,
        iimpl: impl Into<Bindle<IfaceImpl>>,
    ) -> Result<validation::Status, Self::ImportError>;

    fn import_contract(
        &mut self,
        iimpl: impl Into<Bindle<Contract>>,
    ) -> Result<validation::Status, Self::ImportError>;

    fn export_contract(
        &mut self,
        contract_id: ContractId,
    ) -> Result<Bindle<Contract>, Self::InternalError>;

    fn contract_iface(
        &mut self,
        contract_id: ContractId,
        iface_id: IfaceId,
    ) -> Result<ContractIface, Self::InternalError>;

    /*
    fn consign(&mut self) -> Result<Transfer, Self::ConsignError>;

    fn accept<const TYPE: bool>(
        &mut self,
        consignment: Consignment<TYPE>,
    ) -> Result<(), Self::ImportError>;
     */
}
