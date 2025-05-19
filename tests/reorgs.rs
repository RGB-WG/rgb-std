#![cfg(not(target_arch = "wasm32"))]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_types;

use std::collections::BTreeSet;
use std::fs;
use std::num::NonZeroU64;
use std::path::PathBuf;

use amplify::none;
use bp::seals::{Anchor, TxoSeal, WTxoSeal};
use bp::{LockTime, Tx};
use commit_verify::{Digest, DigestExt, Sha256};
use hypersonic::CallParams;
use rand::prelude::SliceRandom;
use rand::rng;
use rgb::{
    Assignment, CellAddr, Contract, CoreParams, CreateParams, Issuer, NamedState, Outpoint, PileFs,
    WitnessStatus,
};
use rgbcore::{ContractApi, RgbSealDef};
use single_use_seals::SealWitness;
use sonic_persist_fs::StockFs;
use strict_encoding::{vname, StrictDumb};

fn setup(name: &str) -> Contract<StockFs, PileFs<TxoSeal>> {
    let mut noise_engine = Sha256::new();
    noise_engine.input_raw(b"test");

    let issuer = Issuer::load("tests/data/Test.issuer").unwrap();

    let mut params = CreateParams::new_bitcoin_testnet(issuer.codex.codex_id(), "Test");
    for _ in 0..20 {
        params.push_owned_unlocked(
            "amount",
            Assignment::new_internal(Outpoint::strict_dumb(), 100u64),
        );
    }

    let contract_path = PathBuf::from(format!("tests/data/{name}.contract"));
    if contract_path.exists() {
        fs::remove_dir_all(&contract_path).expect("Unable to remove a contract file");
    }
    fs::create_dir_all(&contract_path).expect("Unable to create a contract folder");
    let mut contract =
        Contract::issue(issuer, params.transform(noise_engine.clone()), |_| Ok(contract_path))
            .unwrap();
    let opid = contract.articles().genesis_opid();

    let owned = &contract.state_all().main.destructible;
    assert_eq!(owned.len(), 1);
    let owned = owned.get("amount").unwrap();
    assert_eq!(owned.len(), 20);
    let mut prev = vec![];
    for (addr, val) in owned {
        assert_eq!(val, &svnum!(100u64));
        assert_eq!(addr.opid, opid);
        prev.push(*addr);
    }
    assert_eq!(prev.len(), 20);

    let mut no = 0;
    let mut next_seal = || -> WTxoSeal {
        no += 1;
        WTxoSeal::vout_no_fallback(no.into(), noise_engine.clone(), no as u64)
    };

    let params = CallParams {
        core: CoreParams { method: vname!("transfer"), global: none!(), owned: none!() },
        using: none!(),
        reading: none!(),
    };
    let mut tx = Tx::strict_dumb();
    let anchor = Anchor::strict_dumb();
    for round in 0u16..10 {
        // shuffle outputs to create twisted DAG
        prev.shuffle(&mut rng());
        let mut iter = prev.into_iter();
        let mut new_prev = vec![];
        while let Some((first, second)) = iter.next().zip(iter.next()) {
            let mut params = params.clone();
            params.using.insert(first, None);
            params.using.insert(second, None);
            let seals = small_bmap![0 => next_seal(), 1 => next_seal()];
            let amount = 100u64 - round as u64;
            params.core.owned.push(NamedState::new_unlocked(
                "amount",
                seals[&0].auth_token(),
                amount,
            ));
            params.core.owned.push(NamedState::new_unlocked(
                "amount",
                seals[&1].auth_token(),
                amount,
            ));
            let op = contract.call(params, seals).unwrap();
            let opid = op.opid();
            new_prev.push(CellAddr::new(opid, 0));
            new_prev.push(CellAddr::new(opid, 1));

            tx.lock_time = LockTime::from_consensus_u32(tx.lock_time.into_consensus_u32() + 1);
            contract.apply_witness(opid, SealWitness::new(tx.clone(), anchor.clone()));
        }
        prev = new_prev;
    }

    let owned = &contract.state_all().main.destructible;
    assert_eq!(owned.len(), 1);
    assert_eq!(prev.len(), 20);
    let owned = owned.get("amount").unwrap();
    assert_eq!(owned.len(), 20);
    for (_, val) in owned.iter() {
        assert_eq!(val, &svnum!(91u64));
    }
    assert_eq!(owned.keys().collect::<BTreeSet<_>>(), prev.iter().collect::<BTreeSet<_>>());

    contract
}

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
