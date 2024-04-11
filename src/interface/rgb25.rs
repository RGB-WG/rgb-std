// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2023-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
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

#![allow(unused_braces)]

use std::fmt::Debug;
use std::str::FromStr;

use bp::dbc::Method;
use chrono::Utc;
use invoice::{Amount, Precision};
use rgb::{AltLayer1, AssetTag, BlindingFactor, GenesisSeal};
use strict_encoding::InvalidIdent;
use strict_types::TypeLib;

use super::{
    BuilderError, ContractBuilder, Iface, IfaceClass, IssuerClass, SchemaIssuer, TxOutpoint,
};
use crate::containers::Contract;
use crate::interface::rgb20::{
    burnable, fungible, named_asset, renameable, reservable, AllocationError,
};
use crate::interface::{ContractIface, IfaceId, IfaceWrapper};
use crate::persistence::PersistedState;
use crate::stl::{rgb_contract_stl, AssetTerms, Attachment, Details, Name, RicardianContract};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub struct Features {
    pub renaming: bool,
    pub reserves: bool,
    pub burnable: bool,
}

impl Features {
    pub fn none() -> Self {
        Features {
            renaming: false,
            reserves: false,
            burnable: false,
        }
    }
    pub fn all() -> Self {
        Features {
            renaming: true,
            reserves: true,
            burnable: true,
        }
    }
}

#[derive(Wrapper, WrapperMut, Clone, Eq, PartialEq, Debug)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
pub struct Rgb25(ContractIface);

impl From<ContractIface> for Rgb25 {
    fn from(iface: ContractIface) -> Self {
        if iface.iface.iface_id != Rgb25::IFACE_ID {
            panic!("the provided interface is not RGB25 interface");
        }
        Self(iface)
    }
}

impl IfaceWrapper for Rgb25 {
    const IFACE_NAME: &'static str = "RGB25";
    const IFACE_ID: IfaceId = IfaceId::from_array([
        0x81, 0x5e, 0x45, 0x56, 0x55, 0x4b, 0x4a, 0x06, 0x9d, 0x9b, 0x54, 0x2d, 0x2b, 0x29, 0xbc,
        0xbd, 0x61, 0x43, 0xdd, 0x8f, 0xc7, 0x58, 0x64, 0x07, 0xc5, 0x95, 0x2d, 0x67, 0x9a, 0xec,
        0xc6, 0xe4,
    ]);
}

impl IfaceClass for Rgb25 {
    type Features = Features;
    fn iface(features: Features) -> Iface {
        let mut iface = named_asset().expect_extended(fungible(), "RGB25Base");
        if features.renaming {
            iface = iface.expect_extended(renameable(), "RGB25Renameable");
        }
        if features.reserves {
            iface = iface.expect_extended(reservable(), "RGB25Reservable");
        }
        if features.burnable {
            iface = iface.expect_extended(burnable(), "RGB25Burnable");
        }
        if features == Features::all() {
            iface.name = Self::IFACE_NAME.into();
        }
        iface
    }
    fn stl() -> TypeLib { rgb_contract_stl() }
}

impl Rgb25 {
    pub fn name(&self) -> Name {
        let strict_val = &self
            .0
            .global("name")
            .expect("RGB25 interface requires global `name`")[0];
        Name::from_strict_val_unchecked(strict_val)
    }

    pub fn details(&self) -> Option<Details> {
        let strict_val = &self
            .0
            .global("details")
            .expect("RGB25 interface requires global `details`");
        if strict_val.len() == 0 {
            None
        } else {
            Some(Details::from_strict_val_unchecked(&strict_val[0]))
        }
    }

    pub fn precision(&self) -> Precision {
        let strict_val = &self
            .0
            .global("precision")
            .expect("RGB25 interface requires global `precision`")[0];
        Precision::from_strict_val_unchecked(strict_val)
    }

    pub fn total_issued_supply(&self) -> Amount {
        self.0
            .global("issuedSupply")
            .expect("RGB25 interface requires global `issuedSupply`")
            .iter()
            .map(Amount::from_strict_val_unchecked)
            .sum()
    }

    pub fn total_burned_supply(&self) -> Amount {
        self.0
            .global("burnedSupply")
            .unwrap_or_default()
            .iter()
            .map(Amount::from_strict_val_unchecked)
            .sum()
    }

    pub fn contract_terms(&self) -> AssetTerms {
        let strict_val = &self
            .0
            .global("terms")
            .expect("RGB25 interface requires global `terms`")[0];
        AssetTerms::from_strict_val_unchecked(strict_val)
    }
}

#[derive(Clone, Debug)]
pub struct Issue {
    builder: ContractBuilder,
    issued: Amount,
    terms: AssetTerms,
    deterministic: bool,
}

impl Issue {
    fn testnet_int(
        issuer: SchemaIssuer<Rgb25>,
        name: &str,
        precision: Precision,
    ) -> Result<Self, InvalidIdent> {
        let terms = AssetTerms {
            text: RicardianContract::default(),
            media: None,
        };

        let (schema, main_iface_impl, features) = issuer.into_split();
        let builder = ContractBuilder::testnet(Rgb25::iface(features), schema, main_iface_impl)
            .expect("schema interface mismatch")
            .add_global_state("name", Name::try_from(name.to_owned())?)
            .expect("invalid RGB25 schema (name mismatch)")
            .add_global_state("name", precision)
            .expect("invalid RGB25 schema (precision mismatch)");

        Ok(Self {
            builder,
            terms,
            issued: Amount::ZERO,
            deterministic: false,
        })
    }

    pub fn testnet<C: IssuerClass<IssuingIface = Rgb25>>(
        name: &str,
        precision: Precision,
        features: Features,
    ) -> Result<Self, InvalidIdent> {
        Self::testnet_int(C::issuer(features), name, precision)
    }

    pub fn testnet_with(
        issuer: SchemaIssuer<Rgb25>,
        name: &str,
        precision: Precision,
    ) -> Result<Self, InvalidIdent> {
        Self::testnet_int(issuer, name, precision)
    }

    pub fn testnet_det<C: IssuerClass<IssuingIface = Rgb25>>(
        name: &str,
        precision: Precision,
        features: Features,
        asset_tag: AssetTag,
    ) -> Result<Self, InvalidIdent> {
        let mut me = Self::testnet_int(C::issuer(features), name, precision)?;
        me.builder = me
            .builder
            .add_asset_tag("assetOwner", asset_tag)
            .expect("invalid RGB25 schema (assetOwner mismatch)");
        me.deterministic = true;
        Ok(me)
    }

    pub fn support_liquid(mut self) -> Self {
        self.builder = self
            .builder
            .add_layer1(AltLayer1::Liquid)
            .expect("only one layer1 can be added");
        self
    }

    pub fn add_details(mut self, details: &str) -> Result<Self, InvalidIdent> {
        self.builder = self
            .builder
            .add_global_state("details", Details::try_from(details.to_owned())?)
            .expect("invalid RGB25 schema (details mismatch)");
        Ok(self)
    }

    pub fn add_terms(
        mut self,
        contract: &str,
        media: Option<Attachment>,
    ) -> Result<Self, InvalidIdent> {
        let terms = RicardianContract::from_str(contract)?;
        self.terms = AssetTerms { text: terms, media };
        Ok(self)
    }

    pub fn allocate<O: TxOutpoint>(
        mut self,
        method: Method,
        beneficiary: O,
        amount: Amount,
    ) -> Result<Self, AllocationError> {
        debug_assert!(
            !self.deterministic,
            "for creating deterministic contracts please use allocate_det method"
        );

        let beneficiary = beneficiary.map_to_xchain(|outpoint| {
            GenesisSeal::new_random(method, outpoint.txid, outpoint.vout)
        });
        self.issued
            .checked_add_assign(amount)
            .ok_or(AllocationError::AmountOverflow)?;
        self.builder =
            self.builder
                .add_fungible_state("assetOwner", beneficiary, amount.value())?;
        Ok(self)
    }

    pub fn allocate_all<O: TxOutpoint>(
        mut self,
        method: Method,
        allocations: impl IntoIterator<Item = (O, Amount)>,
    ) -> Result<Self, AllocationError> {
        for (beneficiary, amount) in allocations {
            self = self.allocate(method, beneficiary, amount)?;
        }
        Ok(self)
    }

    /// Add asset allocation in a deterministic way.
    pub fn allocate_det<O: TxOutpoint>(
        mut self,
        method: Method,
        beneficiary: O,
        seal_blinding: u64,
        amount: Amount,
        amount_blinding: BlindingFactor,
    ) -> Result<Self, AllocationError> {
        debug_assert!(
            self.deterministic,
            "to add asset allocation in deterministic way the contract builder has to be created \
             using `*_det` constructor"
        );

        let tag = self
            .builder
            .asset_tag("assetOwner")
            .expect("internal library error: asset tag is unassigned");
        let beneficiary = beneficiary.map_to_xchain(|outpoint| {
            GenesisSeal::with_blinding(method, outpoint.txid, outpoint.vout, seal_blinding)
        });
        self.issued
            .checked_add_assign(amount)
            .ok_or(AllocationError::AmountOverflow)?;
        self.builder = self.builder.add_owned_state_det(
            "assetOwner",
            beneficiary,
            PersistedState::Amount(amount, amount_blinding, tag),
        )?;
        Ok(self)
    }

    // TODO: implement when bulletproofs are supported
    /*
    pub fn conceal_allocations(mut self) -> Self {

    }
     */

    #[allow(clippy::result_large_err)]
    pub fn issue_contract(self) -> Result<Contract, BuilderError> {
        debug_assert!(
            !self.deterministic,
            "to add asset allocation in deterministic way you must use issue_contract_det method"
        );
        self.issue_contract_det(Utc::now().timestamp())
    }

    #[allow(clippy::result_large_err)]
    pub fn issue_contract_det(self, timestamp: i64) -> Result<Contract, BuilderError> {
        debug_assert!(
            self.deterministic,
            "to add asset allocation in deterministic way the contract builder has to be created \
             using `*_det` constructor"
        );
        self.issue_contract_int(timestamp)
    }

    #[allow(clippy::result_large_err)]
    fn issue_contract_int(self, timestamp: i64) -> Result<Contract, BuilderError> {
        self.builder
            .add_global_state("issuedSupply", self.issued)
            .expect("invalid RGB25 schema (issued supply mismatch)")
            .add_global_state("terms", self.terms)
            .expect("invalid RGB25 schema (contract terms mismatch)")
            .issue_contract_det(timestamp)
    }

    // TODO: Add secondary issuance and other methods
}

#[cfg(test)]
mod test {
    use armor::AsciiArmor;

    use super::*;

    const RGB25: &str = include_str!("../../tests/data/rgb25.rgba");

    #[test]
    fn iface_id_all() {
        let iface_id = Rgb25::iface(Features::all()).iface_id();
        eprintln!("{:#04x?}", iface_id.to_byte_array());
        assert_eq!(Rgb25::IFACE_ID, iface_id);
    }

    #[test]
    fn iface_bindle() {
        assert_eq!(format!("{}", Rgb25::iface(Features::all()).to_ascii_armored_string()), RGB25);
    }

    #[test]
    fn iface_check() {
        if let Err(err) = Rgb25::iface(Features::all()).check() {
            for e in err {
                eprintln!("- {e}");
            }
            panic!("invalid RGB25 interface definition");
        }
    }
}
