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

use amplify::confinement::SmallBlob;
use amplify::ByteArray;
use bp::{Outpoint, Txid};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::StrictVal;

use super::LIB_NAME_RGB_CONTRACT;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT, dumb = ProofOfReserves::new(strict_dumb!(), strict_dumb!()))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct ProofOfReserves {
    pub utxo: Outpoint,
    pub proof: SmallBlob,
}
impl StrictSerialize for ProofOfReserves {}
impl StrictDeserialize for ProofOfReserves {}

impl ProofOfReserves {
    pub fn new(utxo: Outpoint, proof: SmallBlob) -> ProofOfReserves {
        ProofOfReserves { utxo, proof }
    }

    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let utxo = value.unwrap_struct("utxo");
        let txid_array: [u8; 32] = utxo
            .unwrap_struct("txid")
            .unwrap_bytes()
            .try_into()
            .expect("invalid txid");
        let txid = Txid::from_byte_array(txid_array);
        let vout: u32 = utxo.unwrap_struct("vout").unwrap_num().unwrap_uint();
        let utxo = Outpoint::new(txid, vout);

        let proof =
            SmallBlob::from_collection_unsafe(value.unwrap_struct("proof").unwrap_bytes().into());

        Self { utxo, proof }
    }
}
