use crate::persistence::Inventory;
use rgb::contract::{ContractId, XOutputSeal, XChain};
use bp::seals::SecretSeal;

pub fn test_transfer(
    contract_id: ContractId,
    outputs: impl AsRef<[XOutputSeal]>,
    secret_seals: impl AsRef<[XChain<SecretSeal>]>,
)