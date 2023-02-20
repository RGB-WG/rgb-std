#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

// CORE LIB:
// issue    :: Schema, Metadata, {GlobalState}, {Assignments} -> Genesis
//
// STD LIB:
// import   :: Stash, (Schema | Interface) -> Stash
// state    :: Inventory, ContractId -> ContractState
// interpret :: ContractState, Interface -> InterpretedState
//
// issue    :: Schema, State, Interface -> Consignment -- calls `core::issue` internally
// extract  :: Inventory, ContractId, Interface -> Consignment -- used for contract transfer
//
// compose  :: Inventory, ContractId, Interface, [Outpoint] -> Consignment -- base for state transfer describing existing state
// transfer :: Consignment, (...) -> StateTransition            -- prepares state transition
// preserve :: Stash, [Outpoint], StateTransition -> [StateTransition] -- creates blank state transitions
// consign  :: Stash, StateTransition -> Consignment            -- extracts history data
//
// reveal   :: Consignment, RevealInfo -> Consignment -- removes blinding from known UTXOs
// validate :: Consignment -> (Validity, ContractUpdate)
// enclose  :: Inventory, Disclosure -> Inventory !!
// consume  :: Inventory, Consignment -> Inventory !! -- for both transfers and contracts
//
// endpoints :: Consignment -> [Outpoint] -- used to construct initial PSBT

// WALLET LIB:
// embed     :: Psbt, ContractId -> Psbt -- adds contract information to PSBT
// commit    :: Psbt, ContractId, Transition -> Psbt -- adds transition information to the PSBT
// bundle    :: Psbt -> Psbt -- takes individual transitions and bundles them together
// finalize  :: Psbt -> Psbt -- should be performed by BP; converts individual commitments into tapret

mod containers;
mod state;
