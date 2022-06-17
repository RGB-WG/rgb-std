// RGB Standard Library: high-level API to RGB smart contracts.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! RGB20 schemata defining fungible asset smart contract prototypes.

use std::str::FromStr;

use stens::{PrimitiveType, StructField, TypeRef, TypeSystem};

use crate::schema::{
    DiscreteFiniteFieldFormat, GenesisSchema, Occurrences, Schema, SchemaId, StateSchema,
    TransitionSchema,
};
use crate::script::OverrideRules;
use crate::vm::embedded::constants::*;
use crate::ValidationScript;

/// Schema identifier for full RGB20 fungible asset
pub const SCHEMA_ID_BECH32: &'static str =
    "rgbsh15xhulxp3lqnsucradxu6tu2y3sezhy5k9nwtfwjkpq0t72zn465skh7jnz";

/// Schema identifier for full RGB20 fungible asset subschema prohibiting burn &
/// replace operations
pub const SUBSCHEMA_ID_BECH32: &'static str =
    "rgbsh1kmlp0fj9s5wvdagd6kelz8kmgnhq4zjqsck94868muf2apdetktqkkq2jj";

/// Field types for RGB20 schemata
///
/// Subset of known RGB schema pre-defined types applicable to fungible assets.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    /// Asset ticker
    ///
    /// Used within context of genesis or renomination state transition
    Ticker = FIELD_TYPE_TICKER,

    /// Asset name
    ///
    /// Used within context of genesis or renomination state transition
    Name = FIELD_TYPE_NAME,

    /// Text of the asset contract
    ///
    /// Used within context of genesis or renomination state transition
    RicardianContract = FIELD_TYPE_CONTRACT_TEXT,

    /// Decimal precision
    Precision = FIELD_TYPE_PRECISION,

    /// Supply issued with the genesis, secondary issuance or burn & replace
    /// state transition
    IssuedSupply = FIELD_TYPE_ISSUED_SUPPLY,

    /// Supply burned with the burn or burn & replace state transition
    BurnedSupply = FIELD_TYPE_BURN_SUPPLY,

    /// Timestamp for genesis
    Timestamp = FIELD_TYPE_TIMESTAMP,

    /// UTXO containing the burned asset
    BurnUtxo = FIELD_TYPE_BURN_UTXO,

    /// Proofs of the burned supply
    HistoryProof = FIELD_TYPE_HISTORY_PROOF,

    /// Media format for the information proving burned supply
    HistoryProofFormat = FIELD_TYPE_HISTORY_PROOF_FORMAT,
}

impl From<FieldType> for crate::schema::FieldType {
    #[inline]
    fn from(ft: FieldType) -> Self { ft as crate::schema::FieldType }
}

/// Owned right types used by RGB20 schemata
///
/// Subset of known RGB schema pre-defined types applicable to fungible assets.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightType {
    /// Inflation control right (secondary issuance right)
    Inflation = STATE_TYPE_INFLATION_RIGHT,

    /// Asset ownership right
    Assets = STATE_TYPE_OWNERSHIP_RIGHT,

    /// Right to open a new burn & replace epoch
    OpenEpoch = STATE_TYPE_ISSUE_EPOCH_RIGHT,

    /// Right to perform burn or burn & replace operation
    BurnReplace = STATE_TYPE_ISSUE_REPLACEMENT_RIGHT,

    /// Right to perform asset renomination
    Renomination = STATE_TYPE_RENOMINATION_RIGHT,
}

impl From<OwnedRightType> for crate::schema::OwnedRightType {
    #[inline]
    fn from(t: OwnedRightType) -> Self { t as crate::schema::OwnedRightType }
}

/// State transition types defined by RGB20 schemata
///
/// Subset of known RGB schema pre-defined types applicable to fungible assets.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    /// Secondary issuance
    Issue = TRANSITION_TYPE_ISSUE_FUNGIBLE,

    /// Asset transfer
    Transfer = TRANSITION_TYPE_VALUE_TRANSFER,

    /// Opening of the new burn & replace asset epoch
    Epoch = TRANSITION_TYPE_ISSUE_EPOCH,

    /// Asset burn operation
    Burn = TRANSITION_TYPE_ISSUE_BURN,

    /// Burning and replacement (re-issuance) of the asset
    BurnAndReplace = TRANSITION_TYPE_ISSUE_REPLACE,

    /// Renomination (change in the asset name, ticker, contract text of
    /// decimal precision).
    Renomination = TRANSITION_TYPE_RENOMINATION,

    /// Operation splitting rights assigned to the same UTXO
    RightsSplit = TRANSITION_TYPE_RIGHTS_SPLIT,
}

impl From<TransitionType> for crate::schema::TransitionType {
    #[inline]
    fn from(t: TransitionType) -> Self { t as crate::schema::TransitionType }
}

fn type_system() -> TypeSystem {
    type_system! {
        "OutPoint" :: {
            StructField::new("Txid"),
            StructField::primitive(PrimitiveType::U16),
        },
        "Txid" :: { StructField::array(PrimitiveType::U8, 32) }
    }
}

fn genesis() -> GenesisSchema {
    use Occurrences::*;

    GenesisSchema {
        metadata: type_map! {
            FieldType::Ticker => Once,
            FieldType::Name => Once,
            FieldType::RicardianContract => NoneOrOnce,
            FieldType::Precision => Once,
            FieldType::Timestamp => Once,
            // We need this field in order to be able to verify pedersen
            // commitments
            FieldType::IssuedSupply => Once
        },
        owned_rights: type_map! {
            OwnedRightType::Inflation => NoneOrMore,
            OwnedRightType::OpenEpoch => NoneOrOnce,
            OwnedRightType::Assets => NoneOrMore,
            OwnedRightType::Renomination => NoneOrOnce
        },
        public_rights: none!(),
    }
}

fn issue() -> TransitionSchema {
    use Occurrences::*;

    TransitionSchema {
        metadata: type_map! {
            // We need this field in order to be able to verify pedersen
            // commitments
            FieldType::IssuedSupply => Once
        },
        closes: type_map! {
            OwnedRightType::Inflation => OnceOrMore
        },
        owned_rights: type_map! {
            OwnedRightType::Inflation => NoneOrMore,
            OwnedRightType::OpenEpoch => NoneOrOnce,
            OwnedRightType::Assets => NoneOrMore
        },
        public_rights: none!(),
    }
}

fn burn() -> TransitionSchema {
    use Occurrences::*;

    TransitionSchema {
        metadata: type_map! {
            FieldType::BurnedSupply => Once,
            // Normally issuer should aggregate burned assets into a
            // single UTXO; however if burn happens as a result of
            // mistake this will be impossible, so we allow to have
            // multiple burned UTXOs as a part of a single operation
            FieldType::BurnUtxo => OnceOrMore,
            FieldType::HistoryProofFormat => Once,
            FieldType::HistoryProof => NoneOrMore
        },
        closes: type_map! {
            OwnedRightType::BurnReplace => Once
        },
        owned_rights: type_map! {
            OwnedRightType::BurnReplace => NoneOrOnce
        },
        public_rights: none!(),
    }
}

fn renomination() -> TransitionSchema {
    use Occurrences::*;

    TransitionSchema {
        metadata: type_map! {
            FieldType::Ticker => NoneOrOnce,
            FieldType::Name => NoneOrOnce,
            FieldType::RicardianContract => NoneOrOnce,
            FieldType::Precision => NoneOrOnce
        },
        closes: type_map! {
            OwnedRightType::Renomination => Once
        },
        owned_rights: type_map! {
            OwnedRightType::Renomination => NoneOrOnce
        },
        public_rights: none!(),
    }
}

/// Builds & returns complete RGB20 schema (root schema object)
pub fn schema() -> Schema {
    use Occurrences::*;

    // TODO #33: Consider using data containers + state extensions for
    //       providing issuer-created asset meta-information

    Schema {
        rgb_features: none!(),
        root_id: none!(),
        genesis: genesis(),
        type_system: type_system(),
        extensions: none!(),
        transitions: type_map! {
            TransitionType::Issue => issue(),
            TransitionType::Transfer => TransitionSchema {
                metadata: none!(),
                closes: type_map! {
                    OwnedRightType::Assets => OnceOrMore
                },
                owned_rights: type_map! {
                    OwnedRightType::Assets => NoneOrMore
                },
                public_rights: none!()
            },
            TransitionType::Epoch => TransitionSchema {
                metadata: none!(),
                closes: type_map! {
                    OwnedRightType::OpenEpoch => Once
                },
                owned_rights: type_map! {
                    OwnedRightType::OpenEpoch => NoneOrOnce,
                    OwnedRightType::BurnReplace => NoneOrOnce
                },
                public_rights: none!()
            },
            TransitionType::Burn => burn(),
            TransitionType::BurnAndReplace => TransitionSchema {
                metadata: type_map! {
                    FieldType::BurnedSupply => Once,
                    // Normally issuer should aggregate burned assets into a
                    // single UTXO; however if burn happens as a result of
                    // mistake this will be impossible, so we allow to have
                    // multiple burned UTXOs as a part of a single operation
                    FieldType::BurnUtxo => OnceOrMore,
                    // We need this field in order to be able to verify pedersen
                    // commitments
                    FieldType::IssuedSupply => Once,
                    FieldType::HistoryProofFormat => Once,
                    FieldType::HistoryProof => NoneOrMore
                },
                closes: type_map! {
                    OwnedRightType::BurnReplace => Once
                },
                owned_rights: type_map! {
                    OwnedRightType::BurnReplace => NoneOrOnce,
                    OwnedRightType::Assets => OnceOrMore
                },
                public_rights: none!()
            },
            TransitionType::Renomination => renomination(),
            // Allows split of rights if they were occasionally allocated to the
            // same UTXO, for instance both assets and issuance right. Without
            // this type of transition either assets or inflation rights will be
            // lost.
            TransitionType::RightsSplit => TransitionSchema {
                metadata: type_map! {},
                closes: type_map! {
                    OwnedRightType::Inflation => NoneOrMore,
                    OwnedRightType::Assets => NoneOrMore,
                    OwnedRightType::OpenEpoch => NoneOrOnce,
                    OwnedRightType::BurnReplace => NoneOrMore,
                    OwnedRightType::Renomination => NoneOrOnce
                },
                owned_rights: type_map! {
                    OwnedRightType::Inflation => NoneOrMore,
                    OwnedRightType::Assets => NoneOrMore,
                    OwnedRightType::OpenEpoch => NoneOrOnce,
                    OwnedRightType::BurnReplace => NoneOrMore,
                    OwnedRightType::Renomination => NoneOrOnce
                },
                public_rights: none!()
            }
        },
        field_types: type_map! {
            // Rational: if we will use just 26 letters of English alphabet (and
            // we are not limited by them), we will have 26^8 possible tickers,
            // i.e. > 208 trillions, which is sufficient amount
            FieldType::Ticker => TypeRef::ascii_string(),
            FieldType::Name => TypeRef::ascii_string(),
            // Contract text may contain URL, text or text representation of
            // Ricardian contract, up to 64kb. If the contract doesn't fit, a
            // double SHA256 hash and URL should be used instead, pointing to
            // the full contract text, where hash must be represented by a
            // hexadecimal string, optionally followed by `\n` and text URL
            // TODO #33: Consider using data container instead of the above ^^^
            FieldType::RicardianContract => TypeRef::ascii_string(),
            FieldType::Precision => TypeRef::u8(),
            // We need this b/c allocated amounts are hidden behind Pedersen
            // commitments
            FieldType::IssuedSupply => TypeRef::u64(),
            // Supply in either burn or burn-and-replace procedure
            FieldType::BurnedSupply => TypeRef::u64(),
            // While UNIX timestamps allow negative numbers; in context of RGB
            // Schema, assets can't be issued in the past before RGB or Bitcoin
            // even existed; so we prohibit all the dates before RGB release
            // This timestamp is equal to 10/10/2020 @ 2:37pm (UTC)
            FieldType::Timestamp => TypeRef::i64(),
            FieldType::HistoryProof => TypeRef::bytes(),
            FieldType::BurnUtxo => TypeRef::new("OutPoint")
        },
        owned_right_types: type_map! {
            // How much issuer can issue tokens on this path. If there is no
            // limit, than `core::u64::MAX` / sum(inflation_assignments)
            // must be used, as this will be a de-facto limit to the
            // issuance
            OwnedRightType::Inflation => StateSchema::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
            OwnedRightType::Assets => StateSchema::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
            OwnedRightType::OpenEpoch => StateSchema::Declarative,
            OwnedRightType::BurnReplace => StateSchema::Declarative,
            OwnedRightType::Renomination => StateSchema::Declarative
        },
        public_right_types: none!(),
        script: ValidationScript::Embedded,
        override_rules: OverrideRules::AllowAnyVm,
    }
}

/// Provides the only defined RGB20 subschema, which prohibits replace procedure
/// and allows only burn operations
pub fn subschema() -> Schema {
    use Occurrences::*;

    // TODO #33: Consider using data containers + state extensions for
    //       providing issuer-created asset meta-information
    // TODO #33: Consider adding Ricardian contracts to secondary issues and
    //       transfers

    Schema {
        rgb_features: none!(),
        root_id: SchemaId::from_str(SCHEMA_ID_BECH32)
            .expect("Broken root schema ID for RGB20 sub-schema"),
        type_system: type_system(),
        genesis: genesis(),
        extensions: none!(),
        transitions: type_map! {
            TransitionType::Issue => issue(),
            TransitionType::Transfer => TransitionSchema {
                metadata: none!(),
                closes: type_map! {
                    OwnedRightType::Assets => OnceOrMore
                },
                owned_rights: type_map! {
                    OwnedRightType::Assets => NoneOrMore
                },
                public_rights: none!()
            },
            TransitionType::Epoch => TransitionSchema {
                metadata: none!(),
                closes: type_map! {
                    OwnedRightType::OpenEpoch => Once
                },
                owned_rights: type_map! {
                    OwnedRightType::BurnReplace => NoneOrOnce
                },
                public_rights: none!()
            },
            TransitionType::Burn => burn(),
            TransitionType::Renomination => renomination(),
            // Allows split of rights if they were occasionally allocated to the
            // same UTXO, for instance both assets and issuance right. Without
            // this type of transition either assets or inflation rights will be
            // lost.
            TransitionType::RightsSplit => TransitionSchema {
                metadata: type_map! {},
                closes: type_map! {
                    OwnedRightType::Inflation => NoneOrMore,
                    OwnedRightType::Assets => NoneOrMore,
                    OwnedRightType::BurnReplace => NoneOrMore,
                    OwnedRightType::Renomination => NoneOrOnce
                },
                owned_rights: type_map! {
                    OwnedRightType::Inflation => NoneOrMore,
                    OwnedRightType::Assets => NoneOrMore,
                    OwnedRightType::BurnReplace => NoneOrMore,
                    OwnedRightType::Renomination => NoneOrOnce
                },
                public_rights: none!()
            }
        },
        field_types: type_map! {
            // Rational: if we will use just 26 letters of English alphabet (and
            // we are not limited by them), we will have 26^8 possible tickers,
            // i.e. > 208 trillions, which is sufficient amount
            FieldType::Ticker => TypeRef::ascii_string(),
            FieldType::Name => TypeRef::ascii_string(),
            // Contract text may contain URL, text or text representation of
            // Ricardian contract, up to 64kb. If the contract doesn't fit, a
            // double SHA256 hash and URL should be used instead, pointing to
            // the full contract text, where hash must be represented by a
            // hexadecimal string, optionally followed by `\n` and text URL
            // TODO #33: Consider using data container instead of the above ^^^
            FieldType::RicardianContract => TypeRef::ascii_string(),
            FieldType::Precision => TypeRef::u8(),
            // We need this b/c allocated amounts are hidden behind Pedersen
            // commitments
            FieldType::IssuedSupply => TypeRef::u64(),
            // Supply in either burn or burn-and-replace procedure
            FieldType::BurnedSupply => TypeRef::u64(),
            // While UNIX timestamps allow negative numbers; in context of RGB
            // Schema, assets can't be issued in the past before RGB or Bitcoin
            // even existed; so we prohibit all the dates before RGB release
            // This timestamp is equal to 10/10/2020 @ 2:37pm (UTC)
            FieldType::Timestamp => TypeRef::i64(),
            FieldType::BurnUtxo => TypeRef::new("OutPoint")
        },
        owned_right_types: type_map! {
            // How much issuer can issue tokens on this path. If there is no
            // limit, than `core::u64::MAX` / sum(inflation_assignments)
            // must be used, as this will be a de-facto limit to the
            // issuance
            OwnedRightType::Inflation => StateSchema::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
            OwnedRightType::Assets => StateSchema::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
            OwnedRightType::OpenEpoch => StateSchema::Declarative,
            OwnedRightType::BurnReplace => StateSchema::Declarative,
            OwnedRightType::Renomination => StateSchema::Declarative
        },
        public_right_types: none!(),
        script: ValidationScript::Embedded,
        override_rules: OverrideRules::AllowAnyVm,
    }
}

#[cfg(test)]
mod test {
    use lnpbp_bech32::Bech32ZipString;
    use strict_encoding::{StrictDecode, StrictEncode};

    use super::*;
    use crate::schema::SchemaVerify;
    use crate::Validity;

    #[test]
    fn schema_id() {
        let id = schema().schema_id();
        println!("{}", id);
        assert_eq!(id.to_string(), SCHEMA_ID_BECH32);
        assert_eq!(
            id.to_string(),
            "rgbsh15xhulxp3lqnsucradxu6tu2y3sezhy5k9nwtfwjkpq0t72zn465skh7jnz"
        );
    }

    #[test]
    fn subschema_id() {
        let id = subschema().schema_id();
        println!("{}", id);
        assert_eq!(id.to_string(), SUBSCHEMA_ID_BECH32);
        assert_eq!(
            id.to_string(),
            "rgbsh1kmlp0fj9s5wvdagd6kelz8kmgnhq4zjqsck94868muf2apdetktqkkq2jj"
        );
    }

    #[test]
    fn schema_strict_encode() {
        let data = schema()
            .strict_serialize()
            .expect("RGB-20 schema serialization failed");

        let bech32data = data.bech32_zip_string();
        println!("{}", bech32data);

        let schema20 =
            Schema::strict_deserialize(data).expect("RGB-20 schema deserialization failed");

        assert_eq!(schema(), schema20);
        assert_eq!(format!("{:#?}", schema()), format!("{:#?}", schema20));
        assert_eq!(
            bech32data,
            "z1qxz4zwcjsgcpqlgy7rf7z7qpd7jg23as58gsveeufmgquxkq3dus9clwfwppgw3y\
            kdhn07mehdynpwcv2mv9l27r5579wp3xgxrw8tfuq8g5558vnzu4dk9uzvz68y92yvf\
            ajk5pk3f73f0wfvuysxnjw8qs44pzphgx4kgzmgskas6nfgaj8kk3qe8cque4kxs504\
            ujapue65adwxswq5y7ruflv6w8rree8k0qk9jy5llk4w5ekv9077mzza5h3cwjx0geq\
            etruqmt8d4fllvsylc3mem2fju9htru38j8lhay557304elluqqlsesrx"
        );
    }

    #[test]
    fn subschema_verify() {
        assert_eq!(
            subschema().schema_verify(&schema()).validity(),
            Validity::Valid
        );
    }
}
