/// Allocation map using unique set of seal definitions
pub type SealValueMap = BTreeMap<seal::Revealed, ValueAtom>;

/// Allocation map using unique set of blinded consignment endpoints
pub type EndpointValueMap = BTreeMap<SealEndpoint, ValueAtom>;
