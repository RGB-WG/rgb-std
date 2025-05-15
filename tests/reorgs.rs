#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_types;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use amplify::none;
use bp::seals::{TxoSeal, WTxoSeal};
use commit_verify::{Digest, DigestExt, Sha256};
use hypersonic::persistance::StockFs;
use hypersonic::CallParams;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use rgb::{
    Assignment, CellAddr, Contract, CoreParams, CreateParams, NamedState, Outpoint, PileFs, Schema,
};
use rgbcore::RgbSealDef;
use strict_encoding::{vname, StrictDumb};

fn setup(name: &str) -> Contract<StockFs, PileFs<TxoSeal>> {
    let mut noise_engine = Sha256::new();
    noise_engine.input_raw(b"test");

    let issuer = Schema::load("tests/data/Test.issuer").unwrap();

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
    let opid = contract.articles().issue.genesis_opid();

    let owned = &contract.state_all().main.owned;
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
    for round in 0u16..10 {
        // shuffle outputs to create twisted DAG
        prev.shuffle(&mut thread_rng());
        let mut iter = prev.into_iter();
        let mut new_prev = vec![];
        while let Some((first, second)) = iter.next().zip(iter.next()) {
            let mut params = params.clone();
            params.using.insert(first, svnum!(0u64));
            params.using.insert(second, svnum!(0u64));
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
        }
        prev = new_prev;
    }

    let owned = &contract.state_all().main.owned;
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
