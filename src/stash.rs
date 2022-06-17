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

pub trait StashExt {
    /// When we need to send over to somebody else an update (like we have
    /// transferred him some state, for instance an asset) for each transfer we
    /// ask [`Stash`] to create a new [`Consignment`] for the given set of seals
    /// (`endpoints`) under some specific [`ContractId`], starting from a graph
    /// vertex `node`. If the node is state transition, we must also include
    /// `anchor` information.
    fn consign(
        &self,
        contract_id: ContractId,
        bundle: TransitionBundle,
        anchor: Option<&Anchor<lnpbp4::MerkleProof>>,
        endpoints: &BTreeSet<SealEndpoint>,
    ) -> Result<Consignment, Self::Error>;

    /// When we have received data from other peer (which usually relate to our
    /// newly owned state, like assets) we do `accept` a [`Consignment`],
    /// and it gets into the known data.
    fn accept(
        &mut self,
        consignment: &Consignment,
        known_seals: &[seal::Revealed],
    ) -> Result<(), Self::Error>;

    /// Acquire knowledge from a given disclosure (**enclose** procedure)
    fn enclose(&mut self, disclosure: &Disclosure) -> Result<(), Self::Error>;
}