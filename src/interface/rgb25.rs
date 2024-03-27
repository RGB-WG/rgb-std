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
use rgb::{AltLayer1, AssetTag, BlindingFactor, GenesisSeal, Occurrences, Types};
use strict_encoding::{InvalidIdent, Variant};
use strict_types::TypeLib;

use super::{
    AssignIface, BuilderError, ContractBuilder, GenesisIface, GlobalIface, Iface, IfaceClass,
    IssuerClass, Modifier, OwnedIface, Req, SchemaIssuer, TransitionIface, TxOutpoint, VerNo,
};
use crate::containers::Contract;
use crate::interface::rgb20::AllocationError;
use crate::interface::{ContractIface, IfaceId, IfaceWrapper};
use crate::persistence::PersistedState;
use crate::stl::{
    rgb_contract_stl, AssetTerms, Attachment, Details, Name, RicardianContract, StandardTypes,
};

pub const LIB_NAME_RGB25: &str = "RGB25";

const SUPPLY_MISMATCH: u8 = 1;
const NON_EQUAL_AMOUNTS: u8 = 2;
const INVALID_PROOF: u8 = 3;
const INSUFFICIENT_RESERVES: u8 = 4;
const INSUFFICIENT_COVERAGE: u8 = 5;

fn rgb25() -> Iface {
    let types = StandardTypes::new();

    Iface {
        version: VerNo::V1,
        name: tn!("RGB25"),
        inherits: none!(),
        global_state: tiny_bmap! {
            fname!("name") => GlobalIface::required(types.get("RGBContract.Name")),
            fname!("details") => GlobalIface::optional(types.get("RGBContract.Details")),
            fname!("precision") => GlobalIface::required(types.get("RGBContract.Precision")),
            fname!("terms") => GlobalIface::required(types.get("RGBContract.AssetTerms")),
            fname!("issuedSupply") => GlobalIface::required(types.get("RGBContract.Amount")),
            fname!("burnedSupply") => GlobalIface::none_or_many(types.get("RGBContract.Amount")),
        },
        assignments: tiny_bmap! {
            fname!("assetOwner") => AssignIface::private(OwnedIface::Amount, Req::OneOrMore),
            fname!("burnRight") => AssignIface::public(OwnedIface::Rights, Req::NoneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Final,
            metadata: Some(types.get("RGBContract.IssueMeta")),
            globals: tiny_bmap! {
                fname!("name") => Occurrences::Once,
                fname!("details") => Occurrences::NoneOrOnce,
                fname!("precision") => Occurrences::Once,
                fname!("terms") => Occurrences::Once,
                fname!("issuedSupply") => Occurrences::Once,
            },
            assignments: tiny_bmap! {
                fname!("assetOwner") => Occurrences::OnceOrMore,
            },
            valencies: none!(),
            errors: tiny_bset! {
                SUPPLY_MISMATCH,
                INVALID_PROOF,
                INSUFFICIENT_RESERVES
            },
        },
        transitions: tiny_bmap! {
            fname!("transfer") => TransitionIface {
                modifier: Modifier::Final,
                optional: false,
                metadata: None,
                globals: none!(),
                inputs: tiny_bmap! {
                    fname!("assetOwner") => Occurrences::OnceOrMore,
                },
                assignments: tiny_bmap! {
                    fname!("assetOwner") => Occurrences::OnceOrMore,
                },
                valencies: none!(),
                errors: tiny_bset! {
                    NON_EQUAL_AMOUNTS
                },
                default_assignment: Some(fname!("assetOwner")),
            },
            fname!("burn") => TransitionIface {
                modifier: Modifier::Final,
                optional: true,
                metadata: Some(types.get("RGBContract.BurnMeta")),
                globals: tiny_bmap! {
                    fname!("burnedSupply") => Occurrences::Once,
                },
                inputs: tiny_bmap! {
                    fname!("burnRight") => Occurrences::Once,
                },
                assignments: tiny_bmap! {
                    fname!("burnRight") => Occurrences::NoneOrOnce,
                },
                valencies: none!(),
                errors: tiny_bset! {
                    SUPPLY_MISMATCH,
                    INVALID_PROOF,
                    INSUFFICIENT_COVERAGE
                },
                default_assignment: None,
            },
        },
        extensions: none!(),
        errors: tiny_bmap! {
            Variant::named(SUPPLY_MISMATCH, vname!("supplyMismatch"))
                => tiny_s!("supply specified as a global parameter doesn't match the issued supply allocated to the asset owners"),

            Variant::named(NON_EQUAL_AMOUNTS, vname!("nonEqualAmounts"))
                => tiny_s!("the sum of spent assets doesn't equal to the sum of assets in outputs"),

            Variant::named(INVALID_PROOF, vname!("invalidProof"))
                => tiny_s!("the provided proof is invalid"),

            Variant::named(INSUFFICIENT_RESERVES, vname!("insufficientReserves"))
                => tiny_s!("reserve is insufficient to cover the issued assets"),

            Variant::named(INSUFFICIENT_COVERAGE, vname!("insufficientCoverage"))
                => tiny_s!("the claimed amount of burned assets is not covered by the assets in the operation inputs"),
        },
        default_operation: Some(fname!("transfer")),
        types: Types::Strict(types.type_system()),
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
    const IFACE_NAME: &'static str = LIB_NAME_RGB25;
    const IFACE_ID: IfaceId = IfaceId::from_array([
        0xa3, 0x99, 0x9c, 0x09, 0xc3, 0x9a, 0xfd, 0x72, 0xd0, 0xdb, 0x4f, 0x39, 0x0a, 0xeb, 0xc7,
        0xe8, 0xc9, 0x7d, 0x9c, 0x95, 0x4c, 0x7c, 0xca, 0x33, 0x8d, 0x06, 0xca, 0x37, 0x26, 0x2e,
        0xc6, 0xee,
    ]);
}

impl IfaceClass for Rgb25 {
    fn iface() -> Iface { rgb25() }
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

    pub fn contract_data(&self) -> AssetTerms {
        let strict_val = &self
            .0
            .global("data")
            .expect("RGB25 interface requires global `data`")[0];
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

        let (schema, main_iface_impl) = issuer.into_split();
        let builder = ContractBuilder::testnet(rgb25(), schema, main_iface_impl)
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
    ) -> Result<Self, InvalidIdent> {
        Self::testnet_int(C::issuer(), name, precision)
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
        asset_tag: AssetTag,
    ) -> Result<Self, InvalidIdent> {
        let mut me = Self::testnet_int(C::issuer(), name, precision)?;
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
            .add_global_state("data", self.terms)
            .expect("invalid RGB25 schema (contract data mismatch)")
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
    fn iface_id() {
        eprintln!("{:#04x?}", rgb25().iface_id().to_byte_array());
        assert_eq!(Rgb25::IFACE_ID, rgb25().iface_id());
    }

    #[test]
    fn iface_creation() { rgb25(); }

    #[test]
    fn iface_bindle() {
        assert_eq!(format!("{}", rgb25().to_ascii_armored_string()), RGB25);
    }

    #[test]
    fn iface_check() {
        if let Err(err) = rgb25().check() {
            for e in err {
                eprintln!("{e}");
            }
            panic!("invalid RGB25 interface definition");
        }
    }
}
