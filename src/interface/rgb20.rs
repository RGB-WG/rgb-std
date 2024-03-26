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

use std::collections::HashMap;
use std::str::FromStr;

use bp::dbc::Method;
use invoice::{Amount, Precision};
use rgb::{AltLayer1, AssetTag, BlindingFactor, GenesisSeal, Occurrences, Types, WitnessId};
use strict_encoding::InvalidIdent;
use strict_types::TypeLib;

use super::{
    AssignIface, BuilderError, ContractBuilder, GenesisIface, GlobalIface, Iface, IfaceClass,
    IfaceOp, IssuerClass, Modifier, OwnedIface, Req, RightsAllocation, SchemaIssuer, StateChange,
    TransitionIface, VerNo, WitnessFilter,
};
use crate::containers::Contract;
use crate::interface::builder::TxOutpoint;
use crate::interface::{ContractIface, FungibleAllocation, IfaceId, IfaceWrapper, OutpointFilter};
use crate::persistence::PersistedState;
use crate::stl::{
    rgb_contract_stl, AssetSpec, AssetTerms, Attachment, RicardianContract, StandardTypes,
};
use crate::LIB_NAME_RGB_STD;

pub const LIB_NAME_RGB20: &str = "RGB20";

const BASE_IFACE_ID: IfaceId = IfaceId::from_array([
    0xa9, 0xc9, 0xe4, 0xe7, 0x72, 0xda, 0x9f, 0x7b, 0x49, 0x33, 0x1b, 0x1c, 0x02, 0x3c, 0x06, 0x61,
    0x6f, 0x5c, 0xf6, 0xb4, 0x88, 0x22, 0xd5, 0x7d, 0xe8, 0x1d, 0x47, 0x5c, 0xe0, 0xd3, 0xef, 0xbc,
]);

const INFLATIBLE_IFACE_ID: IfaceId = IfaceId::from_array([
    0x6e, 0x6b, 0x06, 0x00, 0x79, 0x06, 0xaf, 0xa2, 0xa1, 0x1d, 0x31, 0xe5, 0xd1, 0x0e, 0xfa, 0xf0,
    0x53, 0x53, 0xcd, 0xf5, 0x1e, 0x58, 0x3c, 0x13, 0x4b, 0xec, 0x62, 0xa8, 0x0d, 0x83, 0x4b, 0xc5,
]);

pub fn base() -> Iface {
    let types = StandardTypes::new();
    Iface {
        version: VerNo::V1,
        name: tn!("RGB20Base"),
        inherits: none!(),
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        global_state: tiny_bmap! {
            fname!("spec") => GlobalIface::required(types.get("RGBContract.AssetSpec")),
            fname!("terms") => GlobalIface::required(types.get("RGBContract.AssetTerms")),
            fname!("issuedSupply") => GlobalIface::required(types.get("RGBContract.Amount")),
        },
        assignments: tiny_bmap! {
            fname!("assetOwner") => AssignIface::private(OwnedIface::Amount, Req::NoneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Abstract,
            metadata: Some(types.get("RGBContract.IssueMeta")),
            globals: tiny_bmap! {
                fname!("spec") => Occurrences::Once,
                fname!("terms") => Occurrences::Once,
                fname!("issuedSupply") => Occurrences::Once,
            },
            assignments: tiny_bmap! {
                fname!("assetOwner") => Occurrences::NoneOrMore,
            },
            valencies: none!(),
            errors: tiny_bset! {
                vname!("supplyMismatch"),
                vname!("invalidProof"),
                vname!("insufficientReserves")
            },
        },
        transitions: tiny_bmap! {
            fname!("transfer") => TransitionIface {
                modifier: Modifier::Abstract,
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
                    vname!("nonEqualAmounts")
                },
                default_assignment: Some(fname!("assetOwner")),
            },
        },
        extensions: none!(),
        errors: tiny_bmap! {
            vname!("supplyMismatch")
                => tiny_s!("supply specified as a global parameter doesn't match the issued supply allocated to the asset owners"),

            vname!("nonEqualAmounts")
                => tiny_s!("the sum of spent assets doesn't equal to the sum of assets in outputs"),

            vname!("invalidProof")
                => tiny_s!("the provided proof is invalid"),

            vname!("insufficientReserves")
                => tiny_s!("reserve is insufficient to cover the issued assets"),
        },
        default_operation: Some(fname!("transfer")),
        types: Types::Strict(types.type_system()),
    }
}

pub fn fixed() -> Iface {
    Iface {
        version: VerNo::V1,
        name: tn!("RGB20Fixed"),
        inherits: tiny_bset![BASE_IFACE_ID],
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        global_state: none!(),
        assignments: tiny_bmap! {
            fname!("assetOwner") => AssignIface::private(OwnedIface::Amount, Req::OneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Override,
            metadata: None,
            globals: none!(),
            assignments: tiny_bmap! {
                fname!("assetOwner") => Occurrences::OnceOrMore,
            },
            valencies: none!(),
            errors: tiny_bset! {
                vname!("supplyMismatch"),
                vname!("invalidProof"),
                vname!("insufficientReserves")
            },
        },
        transitions: none!(),
        extensions: none!(),
        errors: none!(),
        default_operation: None,
        types: StandardTypes::new().type_system().into(),
    }
}

pub fn inflatible() -> Iface {
    let types = StandardTypes::new();
    Iface {
        version: VerNo::V1,
        inherits: tiny_bset![BASE_IFACE_ID],
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        name: tn!("RGB20Inflatible"),
        global_state: tiny_bmap! {
            fname!("issuedSupply") => GlobalIface::one_or_many(types.get("RGBContract.Amount")),
        },
        assignments: tiny_bmap! {
            fname!("inflationAllowance") => AssignIface::public(OwnedIface::Amount, Req::NoneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Abstract,
            metadata: Some(types.get("RGBContract.IssueMeta")),
            globals: none!(),
            assignments: tiny_bmap! {
                fname!("inflationAllowance") => Occurrences::OnceOrMore,
            },
            valencies: none!(),
            errors: none!(),
        },
        transitions: tiny_bmap! {
            fname!("issue") => TransitionIface {
                modifier: Modifier::Abstract,
                optional: false,
                metadata: Some(types.get("RGBContract.IssueMeta")),
                globals: tiny_bmap! {
                    fname!("issuedSupply") => Occurrences::Once,
                },
                inputs: tiny_bmap! {
                    fname!("inflationAllowance") => Occurrences::OnceOrMore,
                },
                assignments: tiny_bmap! {
                    fname!("assetOwner") => Occurrences::NoneOrMore,
                    fname!("inflationAllowance") => Occurrences::NoneOrMore,
                },
                valencies: none!(),
                errors: tiny_bset! {
                    vname!("supplyMismatch"),
                    vname!("invalidProof"),
                    vname!("issueExceedsAllowance"),
                    vname!("insufficientReserves")
                },
                default_assignment: Some(fname!("assetOwner")),
            },
        },
        extensions: none!(),
        default_operation: None,
        errors: tiny_bmap! {
            vname!("issueExceedsAllowance")
                => tiny_s!("you try to issue more assets than allowed by the contract terms"),
        },
        types: Types::Strict(types.type_system()),
    }
}

pub fn renamable() -> Iface {
    Iface {
        version: VerNo::V1,
        inherits: tiny_bset![BASE_IFACE_ID],
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        name: tn!("RGB20Renamable"),
        global_state: none!(),
        assignments: tiny_bmap! {
            fname!("updateRight") => AssignIface::public(OwnedIface::Rights, Req::Required),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Override,
            metadata: None,
            globals: none!(),
            assignments: tiny_bmap! {
                fname!("updateRight") => Occurrences::Once,
            },
            valencies: none!(),
            errors: none!(),
        },
        transitions: tiny_bmap! {
            fname!("rename") => TransitionIface {
                modifier: Modifier::Final,
                optional: false,
                metadata: None,
                globals: tiny_bmap! {
                    fname!("spec") => Occurrences::Once,
                },
                inputs: tiny_bmap! {
                    fname!("updateRight") => Occurrences::Once,
                },
                assignments: tiny_bmap! {
                    fname!("updateRight") => Occurrences::NoneOrOnce,
                },
                valencies: none!(),
                errors: none!(),
                default_assignment: Some(fname!("updateRight")),
            },
        },
        extensions: none!(),
        default_operation: None,
        errors: none!(),
        types: StandardTypes::new().type_system().into(),
    }
}

pub fn burnable() -> Iface {
    let types = StandardTypes::new();
    Iface {
        version: VerNo::V1,
        inherits: tiny_bset![BASE_IFACE_ID],
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        name: tn!("RGB20Burnable"),
        global_state: tiny_bmap! {
            fname!("burnedSupply") => GlobalIface::none_or_many(types.get("RGBContract.Amount")),
        },
        assignments: tiny_bmap! {
            fname!("burnRight") => AssignIface::public(OwnedIface::Rights, Req::OneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Override,
            metadata: None,
            globals: none!(),
            assignments: tiny_bmap! {
                fname!("burnRight") => Occurrences::OnceOrMore,
            },
            valencies: none!(),
            errors: none!(),
        },
        transitions: tiny_bmap! {
            fname!("burn") => TransitionIface {
                modifier: Modifier::Final,
                optional: false,
                metadata: Some(types.get("RGBContract.BurnMeta")),
                globals: tiny_bmap! {
                    fname!("burnedSupply") => Occurrences::Once,
                },
                inputs: tiny_bmap! {
                    fname!("burnRight") => Occurrences::Once,
                },
                assignments: tiny_bmap! {
                    fname!("burnRight") => Occurrences::NoneOrMore,
                },
                valencies: none!(),
                errors: tiny_bset! {
                    vname!("supplyMismatch"),
                    vname!("invalidProof"),
                    vname!("insufficientCoverage")
                },
                default_assignment: None,
            },
        },
        extensions: none!(),
        default_operation: None,
        errors: tiny_bmap! {
            vname!("insufficientCoverage")
                => tiny_s!("the claimed amount of burned assets is not covered by the assets in the operation inputs"),
        },
        types: Types::Strict(types.type_system()),
    }
}

pub fn replacable() -> Iface {
    let types = StandardTypes::new();
    Iface {
        version: VerNo::V1,
        inherits: tiny_bset![INFLATIBLE_IFACE_ID],
        developer: none!(), // TODO: Add LNP/BP Standards Association
        timestamp: 1711405444,
        name: tn!("RGB20Replacable"),
        global_state: tiny_bmap! {
            fname!("burnedSupply") => GlobalIface::none_or_many(types.get("RGBContract.Amount")),
            fname!("replacedSupply") => GlobalIface::none_or_many(types.get("RGBContract.Amount")),
        },
        assignments: tiny_bmap! {
            fname!("burnEpoch") => AssignIface::public(OwnedIface::Rights, Req::OneOrMore),
            fname!("burnRight") => AssignIface::public(OwnedIface::Rights, Req::NoneOrMore),
        },
        valencies: none!(),
        genesis: GenesisIface {
            modifier: Modifier::Override,
            metadata: None,
            globals: none!(),
            assignments: tiny_bmap! {
                fname!("burnEpoch") => Occurrences::Once,
            },
            valencies: none!(),
            errors: none!(),
        },
        transitions: tiny_bmap! {
            fname!("openEpoch") => TransitionIface {
                modifier: Modifier::Final,
                optional: false,
                metadata: None,
                globals: none!(),
                inputs: tiny_bmap! {
                    fname!("burnEpoch") => Occurrences::Once,
                },
                assignments: tiny_bmap! {
                    fname!("burnEpoch") => Occurrences::NoneOrOnce,
                    fname!("burnRight") => Occurrences::Once,
                },
                valencies: none!(),
                errors: none!(),
                default_assignment: Some(fname!("burnRight")),
            },
            fname!("burn") => TransitionIface {
                modifier: Modifier::Final,
                optional: false,
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
                    vname!("supplyMismatch"),
                    vname!("invalidProof"),
                    vname!("insufficientCoverage")
                },
                default_assignment: None,
            },
            fname!("replace") => TransitionIface {
                modifier: Modifier::Final,
                optional: false,
                metadata: Some(types.get("RGBContract.BurnMeta")),
                globals: tiny_bmap! {
                    fname!("replacedSupply") => Occurrences::Once,
                },
                inputs: tiny_bmap! {
                    fname!("burnRight") => Occurrences::Once,
                },
                assignments: tiny_bmap! {
                    fname!("assetOwner") => Occurrences::NoneOrMore,
                    fname!("burnRight") => Occurrences::NoneOrOnce,
                },
                valencies: none!(),
                errors: tiny_bset! {
                    vname!("nonEqualAmounts"),
                    vname!("supplyMismatch"),
                    vname!("invalidProof"),
                    vname!("insufficientCoverage")
                },
                default_assignment: Some(fname!("assetOwner")),
            },
        },
        extensions: none!(),
        default_operation: None,
        errors: tiny_bmap! {
            vname!("insufficientCoverage")
                => tiny_s!("the claimed amount of burned assets is not covered by the assets in the operation inputs"),
        },
        types: Types::Strict(types.type_system()),
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub enum Inflation {
    #[default]
    Fixed,
    Burnable,
    Inflatible,
    InflatibleBurnable,
    Replaceable,
}

impl Inflation {
    pub fn is_fixed(self) -> bool { self == Self::Fixed }
    pub fn is_inflatible(self) -> bool {
        self == Self::Inflatible || self == Self::InflatibleBurnable || self == Self::Replaceable
    }
    pub fn is_replacable(self) -> bool { self == Self::Replaceable }
    pub fn is_burnable(self) -> bool { self == Self::Burnable || self == Self::Replaceable }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub struct Features {
    renaming: bool,
    inflation: Inflation,
}

impl Features {
    pub fn none() -> Self {
        Features {
            renaming: false,
            inflation: Inflation::Fixed,
        }
    }
    pub fn all() -> Self {
        Features {
            renaming: true,
            inflation: Inflation::Replaceable,
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
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
        0x37, 0x2c, 0x73, 0x56, 0xdb, 0x37, 0xdb, 0x90, 0xe8, 0xdb, 0xf3, 0x6e, 0x05, 0xcf, 0x1f,
        0xad, 0x5b, 0x96, 0x82, 0x9f, 0x36, 0x86, 0x26, 0x1a, 0x2a, 0x3e, 0x09, 0x17, 0x70, 0xaf,
        0x40, 0x9a,
    ]);
}

impl IfaceClass for Rgb20 {
    type Features = Features;
    fn iface(features: Features) -> Iface {
        let mut iface = base();
        if features.renaming {
            iface = iface.expect_extended(renamable());
        }
        if features.inflation.is_fixed() {
            iface = iface.expect_extended(fixed());
        }
        if features.inflation.is_inflatible() {
            iface = iface.expect_extended(inflatible());
        }
        if features.inflation.is_replacable() {
            iface = iface.expect_extended(replacable());
        } else if features.inflation.is_burnable() {
            iface = iface.expect_extended(burnable());
        }
        iface.name = tn!("RGB20");
        iface
    }
    fn stl() -> TypeLib { rgb_contract_stl() }
}

impl Rgb20 {
    pub fn testnet<C: IssuerClass<IssuingIface = Self>>(
        ticker: &str,
        name: &str,
        details: Option<&str>,
        precision: Precision,
        features: Features,
    ) -> Result<PrimaryIssue, InvalidIdent> {
        PrimaryIssue::testnet::<C>(ticker, name, details, precision, features)
    }

    pub fn testnet_det<C: IssuerClass<IssuingIface = Self>>(
        ticker: &str,
        name: &str,
        details: Option<&str>,
        precision: Precision,
        features: Features,
        asset_tag: AssetTag,
    ) -> Result<PrimaryIssue, InvalidIdent> {
        PrimaryIssue::testnet_det::<C>(ticker, name, details, precision, features, asset_tag)
    }

    pub fn spec(&self) -> AssetSpec {
        let strict_val = &self
            .0
            .global("spec")
            .expect("RGB20 interface requires global state `spec`")[0];
        AssetSpec::from_strict_val_unchecked(strict_val)
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

    pub fn inflation_allowance_allocations<'c>(
        &'c self,
        filter: impl OutpointFilter + 'c,
    ) -> impl Iterator<Item = FungibleAllocation> + 'c {
        self.0
            .fungible("inflationAllowance", filter)
            .expect("RGB20 interface requires `inflationAllowance` state")
    }

    pub fn update_right<'c>(
        &'c self,
        filter: impl OutpointFilter + 'c,
    ) -> impl Iterator<Item = RightsAllocation> + 'c {
        self.0
            .rights("updateRight", filter)
            .expect("RGB20 interface requires `updateRight` state")
    }

    pub fn burn_epoch<'c>(
        &'c self,
        filter: impl OutpointFilter + 'c,
    ) -> impl Iterator<Item = RightsAllocation> + 'c {
        self.0
            .rights("burnEpoch", filter)
            .expect("RGB20 interface requires `burnEpoch` state")
    }

    pub fn burn_right<'c>(
        &'c self,
        filter: impl OutpointFilter + 'c,
    ) -> impl Iterator<Item = RightsAllocation> + 'c {
        self.0
            .rights("burnRight", filter)
            .expect("RGB20 interface requires `updateRight` state")
    }

    pub fn contract_data(&self) -> AssetTerms {
        let strict_val = &self
            .0
            .global("data")
            .expect("RGB20 interface requires global `data`")[0];
        AssetTerms::from_strict_val_unchecked(strict_val)
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

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum AllocationError {
    /// contract genesis doesn't support allocating to liquid seals; request
    /// liquid support first.
    NoLiquidSupport,
    /// overflow in the amount of the issued assets: the total amount must not
    /// exceed 2^64.
    AmountOverflow,
}

impl From<BuilderError> for AllocationError {
    fn from(err: BuilderError) -> Self {
        match err {
            BuilderError::InvalidLayer1(_) => AllocationError::NoLiquidSupport,
            _ => panic!("invalid RGB20 schema (assetOwner mismatch)"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PrimaryIssue {
    builder: ContractBuilder,
    issued: Amount,
    terms: AssetTerms,
    deterministic: bool,
}

impl PrimaryIssue {
    fn testnet_int(
        issuer: SchemaIssuer<Rgb20>,
        ticker: &str,
        name: &str,
        details: Option<&str>,
        precision: Precision,
    ) -> Result<Self, InvalidIdent> {
        let spec = AssetSpec::with(ticker, name, precision, details)?;
        let terms = AssetTerms {
            text: RicardianContract::default(),
            media: None,
        };

        let (schema, main_iface_impl, features) = issuer.into_split();
        let builder = ContractBuilder::testnet(Rgb20::iface(features), schema, main_iface_impl)
            .expect("schema interface mismatch")
            .add_global_state("spec", spec)
            .expect("invalid RGB20 schema (token specification mismatch)");

        Ok(Self {
            builder,
            terms,
            issued: Amount::ZERO,
            deterministic: false,
        })
    }

    pub fn testnet<C: IssuerClass<IssuingIface = Rgb20>>(
        ticker: &str,
        name: &str,
        details: Option<&str>,
        precision: Precision,
        features: Features,
    ) -> Result<Self, InvalidIdent> {
        Self::testnet_int(C::issuer(features), ticker, name, details, precision)
    }

    pub fn testnet_with(
        issuer: SchemaIssuer<Rgb20>,
        ticker: &str,
        name: &str,
        details: Option<&str>,
        precision: Precision,
    ) -> Result<Self, InvalidIdent> {
        Self::testnet_int(issuer, ticker, name, details, precision)
    }

    pub fn testnet_det<C: IssuerClass<IssuingIface = Rgb20>>(
        ticker: &str,
        name: &str,
        details: Option<&str>,
        precision: Precision,
        features: Features,
        asset_tag: AssetTag,
    ) -> Result<Self, InvalidIdent> {
        let mut me = Self::testnet_int(C::issuer(features), ticker, name, details, precision)?;
        me.builder = me
            .builder
            .add_asset_tag("assetOwner", asset_tag)
            .expect("invalid RGB20 schema (assetOwner mismatch)");
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
            !self.deterministic,
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
        self.builder
            .add_global_state("issuedSupply", self.issued)
            .expect("invalid RGB20 schema (issued supply mismatch)")
            .add_global_state("data", self.terms)
            .expect("invalid RGB20 schema (contract data mismatch)")
            .issue_contract()
    }

    // TODO: Add secondary issuance and other methods
}

#[cfg(test)]
mod test {
    use armor::AsciiArmor;

    use super::*;

    const RGB20: &str = include_str!("../../tests/data/rgb20.rgba");

    #[test]
    fn iface_id_all() {
        let iface_id = Rgb20::iface(Features::all()).iface_id();
        eprintln!("{:#04x?}", iface_id.to_byte_array());
        assert_eq!(Rgb20::IFACE_ID, iface_id);
    }

    #[test]
    fn iface_id_base() {
        let iface_id = base().iface_id();
        eprintln!("{:#04x?}", iface_id.to_byte_array());
        assert_eq!(BASE_IFACE_ID, iface_id);
    }

    #[test]
    fn iface_id_inflatible() {
        let iface_id = inflatible().iface_id();
        eprintln!("{:#04x?}", iface_id.to_byte_array());
        assert_eq!(INFLATIBLE_IFACE_ID, iface_id);
    }

    #[test]
    fn iface_bindle() {
        assert_eq!(format!("{}", Rgb20::iface(Features::all()).to_ascii_armored_string()), RGB20);
    }

    #[test]
    fn iface_check() {
        // TODO: test other features
        if let Err(err) = Rgb20::iface(Features::all()).check() {
            for e in err {
                eprintln!("{e}");
            }
            panic!("invalid RGB20 interface definition");
        }
    }
}
