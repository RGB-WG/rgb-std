#![cfg(not(target_arch = "wasm32"))]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_types;

mod utils;

use std::num::NonZeroU64;

use bp::Tx;
use rgb::WitnessStatus;
use rgbcore::ContractApi;
use single_use_seals::SealWitness;
use strict_encoding::StrictDumb;

use crate::utils::setup;

#[test]
fn no_reorgs() { setup("NoReorgs"); }

#[test]
fn single_rollback() {
    let mut contract = setup("SingleRollback");
    let wid = contract.witness_ids().nth(50).unwrap();
    contract.sync([(wid, WitnessStatus::Archived)]).unwrap();
    // Idempotence
    contract.sync([(wid, WitnessStatus::Archived)]).unwrap();
}

#[test]
fn double_rollback() {
    let mut contract = setup("DoubleRollback");
    let wid1 = contract.witness_ids().nth(50).unwrap();
    let wid2 = contract.witness_ids().nth(60).unwrap();
    contract
        .sync([(wid1, WitnessStatus::Archived), (wid2, WitnessStatus::Archived)])
        .unwrap();
}

#[test]
fn rollback_forward() {
    let mut contract = setup("RollbackForward");
    let wid = contract.witness_ids().nth(50).unwrap();
    contract.sync([(wid, WitnessStatus::Archived)]).unwrap();
    contract.sync([(wid, WitnessStatus::Offchain)]).unwrap();
    // Idempotence
    contract
        .sync([(wid, WitnessStatus::Archived), (wid, WitnessStatus::Offchain)])
        .unwrap();
}

#[test]
fn rbf() {
    let mut contract = setup("Rbf");

    let old_txid = contract.witness_ids().nth(50).unwrap();
    let opid = contract.ops_by_witness_id(old_txid).next().unwrap();

    let tx = Tx::strict_dumb();
    let rbf_txid = tx.txid();
    contract.apply_witness(opid, SealWitness::new(tx, strict_dumb!()));

    contract
        .sync([
            (old_txid, WitnessStatus::Archived),
            (rbf_txid, WitnessStatus::Mined(NonZeroU64::new(100).unwrap())),
        ])
        .unwrap();
}
