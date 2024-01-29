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

use std::collections::HashMap;
use std::str::FromStr;

use bp::bc::stl::bp_tx_stl;
use bp::dbc::Method;
use invoice::{Amount, Precision};
use rgb::{AssetTag, BlindingFactor, GenesisSeal, WitnessId, XOutpoint};
use strict_encoding::InvalidIdent;
use strict_types::{CompileError, LibBuilder, TypeLib};

use super::{
    AssignIface, BuilderError, ContractBuilder, ContractClass, GenesisIface, GlobalIface, Iface,
    IfaceOp, OwnedIface, Req, StateChange, TransitionIface, VerNo, WitnessFilter,
};
use crate::containers::Contract;
use crate::interface::{
    ArgSpec, ContractIface, FungibleAllocation, IfaceId, IfaceWrapper, OutpointFilter,
};
use crate::persistence::PersistedState;
use crate::stl::{
    rgb_contract_stl, Attachment, ContractData, DivisibleAssetSpec, RicardianContract,
    StandardTypes, Timestamp,
};

pub const LIB_NAME_RGB20: &str = "RGB20";
/// Strict types id for the library providing data types for RGB20 interface.
pub const LIB_ID_RGB20: &str =
    "urn:ubideco:stl:GVz4mvYE94aQ9q2HPtV9VuoppcDdduP54BMKffF7YoFH#prince-scarlet-ringo";

const SUPPLY_MISMATCH: u8 = 1;
const NON_EQUAL_AMOUNTS: u8 = 2;
const INVALID_PROOF: u8 = 3;
const INSUFFICIENT_RESERVES: u8 = 4;
const INSUFFICIENT_COVERAGE: u8 = 5;
const ISSUE_EXCEEDS_ALLOWANCE: u8 = 6;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB20, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
pub enum Error {
    #[strict_type(dumb)]
    SupplyMismatch = SUPPLY_MISMATCH,
    NonEqualAmounts = NON_EQUAL_AMOUNTS,
    InvalidProof = INVALID_PROOF,
    InsufficientReserves = INSUFFICIENT_RESERVES,
    InsufficientCoverage = INSUFFICIENT_COVERAGE,
    IssueExceedsAllowance = ISSUE_EXCEEDS_ALLOWANCE,
}

fn _rgb20_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB20), tiny_bset! {
        bp_tx_stl().to_dependency(),
        rgb_contract_stl().to_dependency()
    })
    .transpile::<Error>()
    .compile()
}

/// Generates strict type library providing data types for RGB20 interface.
pub fn rgb20_stl() -> TypeLib { _rgb20_stl().expect("invalid strict type RGB20 library") }

pub fn rgb20() -> Iface {
    let types = StandardTypes::with(rgb20_stl());

    Iface {
        version: VerNo::V1,
        name: tn!("RGB20"),
        global_state: tiny_bmap! {
            fname!("spec") => GlobalIface::required(types.get("RGBContract.DivisibleAssetSpec")),
            fname!("data") => GlobalIface::required(types.get("RGBContract.ContractData")),
            fname!("created") => GlobalIface::required(types.get("RGBContract.Timestamp")),
            fname!("issuedSupply") => GlobalIface::one_or_many(types.get("RGBContract.Amount")),
            fname!("burnedSupply") => GlobalIface::none_or_many(types.get("RGBContract.Amount")),
            fname!("replacedSupply") => GlobalIface::none_or_many(types.get("RGBContract.Amount")),
        },
        assignments: tiny_bmap! {
            fname!("inflationAllowance") => AssignIface::public(OwnedIface::Amount, Req::NoneOrMore),
            fname!("updateRight") => AssignIface::public(OwnedIface::Rights, Req::Optional),
            fname!("burnEpoch") => AssignIface::public(OwnedIface::Rights, Req::Optional),
            fname!("burnRight") => AssignIface::public(OwnedIface::Rights, Req::NoneOrMore),
            fname!("assetOwner") => AssignIface::private(OwnedIface::Amount, Req::NoneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            metadata: Some(types.get("RGBContract.IssueMeta")),
            global: tiny_bmap! {
                fname!("spec") => ArgSpec::required(),
                fname!("data") => ArgSpec::required(),
                fname!("created") => ArgSpec::required(),
                fname!("issuedSupply") => ArgSpec::required(),
            },
            assignments: tiny_bmap! {
                fname!("assetOwner") => ArgSpec::many(),
                fname!("inflationAllowance") => ArgSpec::many(),
                fname!("updateRight") => ArgSpec::optional(),
                fname!("burnEpoch") => ArgSpec::optional(),
            },
            valencies: none!(),
            errors: tiny_bset! {
                SUPPLY_MISMATCH,
                INVALID_PROOF,
                INSUFFICIENT_RESERVES
            },
        },
        transitions: tiny_bmap! {
            tn!("Transfer") => TransitionIface {
                optional: false,
                metadata: None,
                globals: none!(),
                inputs: tiny_bmap! {
                    fname!("previous") => ArgSpec::from_non_empty("assetOwner"),
                },
                assignments: tiny_bmap! {
                    fname!("beneficiary") => ArgSpec::from_non_empty("assetOwner"),
                },
                valencies: none!(),
                errors: tiny_bset! {
                    NON_EQUAL_AMOUNTS
                },
                default_assignment: Some(fname!("beneficiary")),
            },
            tn!("Issue") => TransitionIface {
                optional: true,
                metadata: Some(types.get("RGBContract.IssueMeta")),
                globals: tiny_bmap! {
                    fname!("issuedSupply") => ArgSpec::required(),
                },
                inputs: tiny_bmap! {
                    fname!("used") => ArgSpec::from_non_empty("inflationAllowance"),
                },
                assignments: tiny_bmap! {
                    fname!("beneficiary") => ArgSpec::from_many("assetOwner"),
                    fname!("future") => ArgSpec::from_many("inflationAllowance"),
                },
                valencies: none!(),
                errors: tiny_bset! {
                    SUPPLY_MISMATCH,
                    INVALID_PROOF,
                    ISSUE_EXCEEDS_ALLOWANCE,
                    INSUFFICIENT_RESERVES
                },
                default_assignment: Some(fname!("beneficiary")),
            },
            tn!("OpenEpoch") => TransitionIface {
                optional: true,
                metadata: None,
                globals: none!(),
                inputs: tiny_bmap! {
                    fname!("used") => ArgSpec::from_required("burnEpoch"),
                },
                assignments: tiny_bmap! {
                    fname!("next") => ArgSpec::from_optional("burnEpoch"),
                    fname!("burnRight") => ArgSpec::required()
                },
                valencies: none!(),
                errors: none!(),
                default_assignment: Some(fname!("burnRight")),
            },
            tn!("Burn") => TransitionIface {
                optional: true,
                metadata: Some(types.get("RGBContract.BurnMeta")),
                globals: tiny_bmap! {
                    fname!("burnedSupply") => ArgSpec::required(),
                },
                inputs: tiny_bmap! {
                    fname!("used") => ArgSpec::from_required("burnRight"),
                },
                assignments: tiny_bmap! {
                    fname!("future") => ArgSpec::from_optional("burnRight"),
                },
                valencies: none!(),
                errors: tiny_bset! {
                    SUPPLY_MISMATCH,
                    INVALID_PROOF,
                    INSUFFICIENT_COVERAGE
                },
                default_assignment: None,
            },
            tn!("Replace") => TransitionIface {
                optional: true,
                metadata: Some(types.get("RGBContract.BurnMeta")),
                globals: tiny_bmap! {
                    fname!("replacedSupply") => ArgSpec::required(),
                },
                inputs: tiny_bmap! {
                    fname!("used") => ArgSpec::from_required("burnRight"),
                },
                assignments: tiny_bmap! {
                    fname!("beneficiary") => ArgSpec::from_many("assetOwner"),
                    fname!("future") => ArgSpec::from_optional("burnRight"),
                },
                valencies: none!(),
                errors: tiny_bset! {
                    NON_EQUAL_AMOUNTS,
                    SUPPLY_MISMATCH,
                    INVALID_PROOF,
                    INSUFFICIENT_COVERAGE
                },
                default_assignment: Some(fname!("beneficiary")),
            },
            tn!("Rename") => TransitionIface {
                optional: true,
                metadata: None,
                globals: tiny_bmap! {
                    fname!("new") => ArgSpec::from_required("spec"),
                },
                inputs: tiny_bmap! {
                    fname!("used") => ArgSpec::from_required("updateRight"),
                },
                assignments: tiny_bmap! {
                    fname!("future") => ArgSpec::from_optional("updateRight"),
                },
                valencies: none!(),
                errors: none!(),
                default_assignment: Some(fname!("future")),
            },
        },
        extensions: none!(),
        error_type: types.get("RGB20.Error"),
        default_operation: Some(tn!("Transfer")),
        type_system: types.type_system(),
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_ID_RGB20, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AmountChange {
    #[display("-{0}")]
    #[strict_type(tag = 0xFF)]
    Dec(Amount),

    #[display("0")]
    #[strict_type(tag = 0, dumb)]
    Zero,

    #[display("+{0}")]
    #[strict_type(tag = 0x01)]
    Inc(Amount),
}

impl StateChange for AmountChange {
    type State = Amount;

    fn from_spent(state: Self::State) -> Self { AmountChange::Dec(state) }

    fn from_received(state: Self::State) -> Self { AmountChange::Inc(state) }

    fn merge_spent(&mut self, sub: Self::State) {
        *self = match self {
            AmountChange::Dec(neg) => AmountChange::Dec(*neg + sub),
            AmountChange::Zero => AmountChange::Dec(sub),
            AmountChange::Inc(pos) if *pos > sub => AmountChange::Inc(*pos - sub),
            AmountChange::Inc(pos) if *pos == sub => AmountChange::Zero,
            AmountChange::Inc(pos) if *pos < sub => AmountChange::Dec(sub - *pos),
            AmountChange::Inc(_) => unreachable!(),
        };
    }

    fn merge_received(&mut self, add: Self::State) {
        *self = match self {
            AmountChange::Inc(pos) => AmountChange::Inc(*pos + add),
            AmountChange::Zero => AmountChange::Inc(add),
            AmountChange::Dec(neg) if *neg > add => AmountChange::Dec(*neg - add),
            AmountChange::Dec(neg) if *neg == add => AmountChange::Zero,
            AmountChange::Dec(neg) if *neg < add => AmountChange::Inc(add - *neg),
            AmountChange::Dec(_) => unreachable!(),
        };
    }
}

#[derive(Wrapper, WrapperMut, Clone, Eq, PartialEq, Debug)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
pub struct Rgb20(ContractIface);

impl From<ContractIface> for Rgb20 {
    fn from(iface: ContractIface) -> Self {
        if iface.iface.iface_id != Rgb20::IFACE_ID {
            panic!("the provided interface is not RGB20 interface");
        }
        Self(iface)
    }
}

impl IfaceWrapper for Rgb20 {
    const IFACE_NAME: &'static str = LIB_NAME_RGB20;
    const IFACE_ID: IfaceId = IfaceId::from_array([
        0x3f, 0x19, 0x01, 0x8c, 0xd5, 0x20, 0xec, 0xac, 0x51, 0xa4, 0x3e, 0x21, 0xf2, 0x3e, 0xd2,
        0xc3, 0xdb, 0x18, 0x2f, 0x60, 0x57, 0x9d, 0x1c, 0x35, 0x3e, 0xda, 0x20, 0xf2, 0x75, 0x83,
        0xde, 0x82,
    ]);
}

impl Rgb20 {
    pub fn spec(&self) -> DivisibleAssetSpec {
        let strict_val = &self
            .0
            .global("spec")
            .expect("RGB20 interface requires global state `spec`")[0];
        DivisibleAssetSpec::from_strict_val_unchecked(strict_val)
    }

    pub fn created(&self) -> Timestamp {
        let strict_val = &self
            .0
            .global("created")
            .expect("RGB20 interface requires global state `created`")[0];
        Timestamp::from_strict_val_unchecked(strict_val)
    }

    pub fn balance(&self, filter: impl OutpointFilter) -> Amount {
        self.allocations(filter)
            .map(|alloc| alloc.state)
            .sum::<Amount>()
    }

    pub fn allocations<'c>(
        &'c self,
        filter: impl OutpointFilter + 'c,
    ) -> impl Iterator<Item = FungibleAllocation> + 'c {
        self.0
            .fungible("assetOwner", filter)
            .expect("RGB20 interface requires `assetOwner` state")
    }

    pub fn contract_data(&self) -> ContractData {
        let strict_val = &self
            .0
            .global("data")
            .expect("RGB20 interface requires global `data`")[0];
        ContractData::from_strict_val_unchecked(strict_val)
    }

    pub fn total_issued_supply(&self) -> Amount {
        self.0
            .global("issuedSupply")
            .expect("RGB20 interface requires global `issuedSupply`")
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

    pub fn total_replaced_supply(&self) -> Amount {
        self.0
            .global("replacedSupply")
            .unwrap_or_default()
            .iter()
            .map(Amount::from_strict_val_unchecked)
            .sum()
    }

    pub fn total_supply(&self) -> Amount { self.total_issued_supply() - self.total_burned_supply() }

    pub fn transfer_history(
        &self,
        witness_filter: impl WitnessFilter + Copy,
        outpoint_filter: impl OutpointFilter + Copy,
    ) -> HashMap<WitnessId, IfaceOp<AmountChange>> {
        self.0
            .fungible_ops("assetOwner", witness_filter, outpoint_filter)
            .expect("state name is not correct")
    }
}

#[derive(Clone, Debug)]
pub struct Rgb20Contract(ContractBuilder);

impl Rgb20Contract {
    pub fn testnet<C: ContractClass>(
        ticker: &str,
        name: &str,
        details: Option<&str>,
        precision: Precision,
    ) -> Result<Self, InvalidIdent> {
        let rgb20 = rgb20();

        let spec = DivisibleAssetSpec::with(ticker, name, precision, details)?;
        let contract_data = ContractData {
            terms: RicardianContract::default(),
            media: None,
        };

        let builder = ContractBuilder::testnet(rgb20, C::schema(), C::main_iface_impl())
            .expect("schema interface mismatch")
            .add_global_state("spec", spec)
            .expect("invalid RGB20 schema (token specification mismatch)")
            .add_global_state("data", contract_data)
            .expect("invalid RGB20 schema (contract data mismatch)");
        Ok(Self(builder))
    }

    pub fn testnet_det<C: ContractClass>(
        ticker: &str,
        name: &str,
        details: Option<&str>,
        precision: Precision,
        timestamp: Timestamp,
        asset_tag: AssetTag,
    ) -> Result<Self, InvalidIdent> {
        let mut builder = Self::testnet::<C>(ticker, name, details, precision)?;
        builder.0 = builder
            .0
            .add_global_state("created", timestamp)
            .expect("invalid RGB20 schema (creation timestamp mismatch)")
            .add_asset_tag("assetOwner", asset_tag)
            .expect("invalid RGB20 schema (assetOwner mismatch)");
        Ok(builder)
    }

    pub fn add_terms(
        mut self,
        contract: &str,
        media: Option<Attachment>,
    ) -> Result<Self, InvalidIdent> {
        let terms = RicardianContract::from_str(contract)?;
        let contract_data = ContractData { terms, media };
        self.0 = self
            .0
            .add_global_state("data", contract_data)
            .expect("invalid RGB20 schema (contract data mismatch)");
        Ok(self)
    }

    pub fn allocate(mut self, method: Method, beneficiary: XOutpoint, amount: Amount) -> Self {
        let beneficiary = beneficiary
            .map(|outpoint| GenesisSeal::new_random(method, outpoint.txid, outpoint.vout));
        self.0 = self
            .0
            .add_fungible_state("assetOwner", beneficiary, amount.value())
            .expect("invalid RGB20 schema (assetOwner mismatch)");
        self
    }

    pub fn allocate_all(
        mut self,
        method: Method,
        allocations: impl IntoIterator<Item = (XOutpoint, Amount)>,
    ) -> Self {
        for (beneficiary, amount) in allocations {
            self = self.allocate(method, beneficiary, amount);
        }
        self
    }

    /// Add asset allocation in a deterministic way.
    pub fn allocate_det(
        mut self,
        method: Method,
        beneficiary: XOutpoint,
        seal_blinding: u64,
        amount: Amount,
        amount_blinding: BlindingFactor,
    ) -> Self {
        let tag = self.0.asset_tag("assetOwner").expect(
            "to add asset allocation in deterministic way the contract builder has to be created \
             using `*_det` constructor",
        );
        let beneficiary = beneficiary.map(|outpoint| {
            GenesisSeal::with_blinding(method, outpoint.txid, outpoint.vout, seal_blinding)
        });
        self.0 = self
            .0
            .add_owned_state_det(
                "assetOwner",
                beneficiary,
                PersistedState::Amount(amount, amount_blinding, tag),
            )
            .expect("invalid RGB20 schema (assetOwner mismatch)");
        self
    }

    // TODO: implement when bulletproofs are supported
    /*
    pub fn conceal_allocations(mut self) -> Self {

    }
     */

    pub fn issue_contract(self) -> Result<Contract, BuilderError> {
        // TODO: Compute sum of all allocations and add to the issue amount
        self.0.issue_contract()
    }

    // TODO: Add secondary issuance and other methods
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::containers::BindleContent;

    const RGB20: &str = include_str!("../../tests/data/rgb20.rgba");

    #[test]
    fn lib_id() {
        let lib = rgb20_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB20);
    }

    #[test]
    fn iface_id() {
        assert_eq!(Rgb20::IFACE_ID, rgb20().iface_id());
    }

    #[test]
    fn iface_creation() { rgb20(); }

    #[test]
    fn iface_bindle() {
        assert_eq!(format!("{}", rgb20().bindle()), RGB20);
    }
}
