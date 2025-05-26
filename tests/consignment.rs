#![cfg(not(target_arch = "wasm32"))]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_types;

mod utils;

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::fs;
use std::path::PathBuf;

use bp::seals::TxoSeal;
use rgb::{Consensus, Contracts, Operation, StockpileDir};

use crate::utils::setup;

#[test]
#[should_panic(expected = "single-use seals are not closed properly with witness")]
fn export_import_contract() {
    let contract = setup("Consign");

    let filename = "tests/data/imex.rgb";

    let terminals = contract.full_state().raw.auth.keys().collect::<Vec<_>>();

    fs::remove_file(filename).ok();
    contract.consign_to_file(filename, terminals).unwrap();

    let dir = PathBuf::from("tests/data/storage");
    fs::remove_dir_all(&dir).ok();
    fs::create_dir_all(&dir).ok();
    let stockpile = StockpileDir::<TxoSeal>::load(dir, Consensus::Bitcoin, true).unwrap();
    let mut contracts = Contracts::<_, HashMap<_, _>, HashMap<_, _>>::load(stockpile);

    let resolver = |_: &Operation| -> BTreeMap<_, _> { bmap![] };

    contracts
        .consume_from_file(false, filename, resolver, |_, _, _| -> Result<_, Infallible> {
            unreachable!()
        })
        .unwrap_err();

    contracts
        .consume_from_file(true, filename, resolver, |_, _, _| -> Result<_, Infallible> {
            unreachable!()
        })
        .unwrap();

    contracts
        .consume_from_file(false, filename, resolver, |_, _, _| -> Result<_, Infallible> {
            unreachable!()
        })
        .unwrap();
}
