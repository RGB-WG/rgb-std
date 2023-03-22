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

use std::convert::Infallible;

use amplify::confinement;
use amplify::confinement::{LargeOrdMap, SmallOrdMap, TinyOrdMap};
use bp::dbc::anchor::MergeError;
use commit_verify::mpc;
use commit_verify::mpc::{MerkleBlock, UnrelatedProof};
use rgb::{
    Anchor, AnchorId, AnchoredBundle, BundleId, ContractId, Extension, Genesis, OpId, Operation,
    SchemaId, TransitionBundle,
};

use crate::accessors::{MergeReveal, MergeRevealError};
use crate::containers::{Consignment, ContentId, ContentSigs};
use crate::interface::{rgb20, Iface, IfaceId, IfacePair, SchemaIfaces};
use crate::persistence::{Stash, StashError, StashInconsistency};
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum ConsumeError {
    #[from]
    Confinement(confinement::Error),

    #[from]
    Anchor(UnrelatedProof),

    #[from]
    Merge(MergeError),

    #[from]
    MergeReveal(MergeRevealError),
}

/// Hoard is an in-memory stash useful for WASM implementations.
#[derive(Clone, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, dumb = Hoard::preset())]
pub struct Hoard {
    pub(super) schemata: TinyOrdMap<SchemaId, SchemaIfaces>,
    pub(super) ifaces: TinyOrdMap<IfaceId, Iface>,
    pub(super) geneses: TinyOrdMap<ContractId, Genesis>,
    pub(super) bundles: LargeOrdMap<BundleId, TransitionBundle>,
    pub(super) extensions: LargeOrdMap<OpId, Extension>,
    pub(super) anchors: LargeOrdMap<AnchorId, Anchor<mpc::MerkleBlock>>,
    pub(super) sigs: SmallOrdMap<ContentId, ContentSigs>,
}

impl Hoard {
    pub fn preset() -> Self {
        let rgb20 = rgb20();
        let rgb20_id = rgb20.iface_id();
        Hoard {
            schemata: none!(),
            ifaces: tiny_bmap! {
                rgb20_id => rgb20,
            },
            geneses: none!(),
            bundles: none!(),
            extensions: none!(),
            anchors: none!(),
            sigs: none!(),
        }
    }

    // TODO: Move into Stash trait and re-implement using trait accessor methods
    pub fn consume<const TYPE: bool>(
        &mut self,
        consignment: Consignment<TYPE>,
    ) -> Result<(), ConsumeError> {
        let contract_id = consignment.contract_id();
        let schema_id = consignment.schema_id();

        let iimpls = match self.schemata.get_mut(&schema_id) {
            Some(si) => &mut si.iimpls,
            None => {
                self.schemata
                    .insert(schema_id, SchemaIfaces::new(consignment.schema))?;
                &mut self
                    .schemata
                    .get_mut(&schema_id)
                    .expect("just inserted")
                    .iimpls
            }
        };

        for (iface_id, IfacePair { iface, iimpl }) in consignment.ifaces {
            if !self.ifaces.contains_key(&iface_id) {
                self.ifaces.insert(iface_id, iface)?;
            };
            // TODO: Update for newer implementations
            if !iimpls.contains_key(&iface_id) {
                iimpls.insert(iface_id, iimpl)?;
            };
        }

        match self.geneses.get_mut(&contract_id) {
            Some(genesis) => *genesis = genesis.clone().merge_reveal(consignment.genesis)?,
            None => {
                self.geneses.insert(contract_id, consignment.genesis)?;
            }
        }

        for extension in consignment.extensions {
            let opid = extension.id();
            match self.extensions.get_mut(&opid) {
                Some(e) => *e = e.clone().merge_reveal(extension)?,
                None => {
                    self.extensions.insert(opid, extension)?;
                }
            }
        }

        for AnchoredBundle { anchor, bundle } in consignment.bundles {
            let bundle_id = bundle.bundle_id();
            let anchor = anchor.into_merkle_block(contract_id, bundle_id.into())?;
            let anchor_id = anchor.anchor_id();
            match self.anchors.get_mut(&anchor_id) {
                Some(a) => *a = a.clone().merge_reveal(anchor)?,
                None => {
                    self.anchors.insert(anchor_id, anchor)?;
                }
            }
            match self.bundles.get_mut(&bundle_id) {
                Some(b) => *b = b.clone().merge_reveal(bundle)?,
                None => {
                    self.bundles.insert(bundle_id, bundle)?;
                }
            }
        }

        // TODO: Import content signatures

        Ok(())
    }
}

impl Stash for Hoard {
    // With in-memory data we have no connectivity or I/O errors
    type Error = Infallible;

    fn iface_by_name(&self, name: &str) -> Result<&Iface, StashError<Self::Error>> {
        self.ifaces
            .values()
            .find(|iface| iface.name.as_str() == name)
            .ok_or_else(|| StashInconsistency::IfaceNameAbsent(name.to_owned()).into())
    }
    fn iface_by_id(&self, id: IfaceId) -> Result<&Iface, StashError<Self::Error>> {
        self.ifaces
            .get(&id)
            .ok_or_else(|| StashInconsistency::IfaceAbsent(id).into())
    }

    fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, StashError<Self::Error>> {
        self.schemata
            .get(&schema_id)
            .ok_or_else(|| StashInconsistency::SchemaAbsent(schema_id).into())
    }

    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, StashError<Self::Error>> {
        self.geneses
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id).into())
    }

    fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, StashError<Self::Error>> {
        self.bundles
            .get(&bundle_id)
            .ok_or(StashInconsistency::BundleAbsent(bundle_id).into())
    }

    fn extension(&self, op_id: OpId) -> Result<&Extension, StashError<Self::Error>> {
        self.extensions
            .get(&op_id)
            .ok_or(StashInconsistency::OperationAbsent(op_id).into())
    }

    fn anchor(&self, anchor_id: AnchorId) -> Result<&Anchor<MerkleBlock>, StashError<Self::Error>> {
        self.anchors
            .get(&anchor_id)
            .ok_or(StashInconsistency::AnchorAbsent(anchor_id).into())
    }
}
