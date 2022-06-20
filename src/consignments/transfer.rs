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

// TODO #60: Implement different conceal procedures for the consignments

use std::collections::{BTreeMap, BTreeSet};

use commit_verify::CommitConceal;
use rgb_core::{seal, ConcealSeals, ConcealState, Node, SealEndpoint, TransitionBundle};

use super::StateTransfer;

impl StateTransfer {
    pub fn finalize(&mut self, expose: &BTreeSet<SealEndpoint>) -> usize {
        let concealed_endpoints = expose
            .iter()
            .map(SealEndpoint::commit_conceal)
            .collect::<Vec<_>>();

        let mut removed_endpoints = vec![];
        self.endpoints = self
            .endpoints
            .clone()
            .into_iter()
            .filter(|(_, endpoint)| {
                if expose.contains(endpoint) {
                    true
                } else {
                    removed_endpoints.push(*endpoint);
                    false
                }
            })
            .collect();
        let seals_to_conceal = removed_endpoints
            .iter()
            .map(SealEndpoint::commit_conceal)
            .collect::<Vec<_>>();

        let mut count = 0usize;
        self.anchored_bundles = self
            .anchored_bundles
            .iter()
            .map(|(anchor, bundle)| {
                let bundle = bundle
                    .revealed_iter()
                    .map(|(transition, inputs)| {
                        let mut transition = transition.clone();
                        count += transition.conceal_state_except(&concealed_endpoints)
                            + transition.conceal_seals(&seals_to_conceal);
                        (transition, inputs.clone())
                    })
                    .collect::<BTreeMap<_, _>>();
                (anchor.clone(), TransitionBundle::from(bundle))
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("size of the original collection not changed");

        count = self
            .state_extensions
            .iter_mut()
            .fold(count, |count, extension| {
                count + extension.conceal_state_except(&concealed_endpoints)
            });

        count
    }

    /// Reveals previously known seal information (replacing blind UTXOs with
    /// unblind ones). Function is used when a peer receives consignments
    /// containing concealed seals for the outputs owned by the peer
    pub fn reveal_seals<'a>(
        &mut self,
        known_seals: impl Iterator<Item = &'a seal::Revealed> + Clone,
    ) -> usize {
        let mut counter = 0;
        for (_, bundle) in self.anchored_bundles.iter_mut() {
            *bundle = bundle
                .revealed_iter()
                .map(|(transition, inputs)| {
                    let mut transition = transition.clone();
                    for (_, assignment) in transition.owned_rights_mut().iter_mut() {
                        counter += assignment.reveal_seals(known_seals.clone());
                    }
                    (transition, inputs.clone())
                })
                .collect::<BTreeMap<_, _>>()
                .into();
        }
        for extension in self.state_extensions.iter_mut() {
            for (_, assignment) in extension.owned_rights_mut().iter_mut() {
                counter += assignment.reveal_seals(known_seals.clone())
            }
        }
        counter
    }
}

/*
#[cfg(test)]
pub(crate) mod test {
    use crate::test::schema;

    static CONSIGNMENT: [u8; 1496] = include!("../test/consignments.in");

    pub(crate) fn consignments() -> FullConsignment {
        FullConsignment::strict_decode(&CONSIGNMENT[..]).unwrap()
    }

    struct TestResolver;

    impl ResolveTx for TestResolver {
        fn resolve_tx(&self, txid: Txid) -> Result<bitcoin::Transaction, TxResolverError> {
            eprintln!("Validating txid {}", txid);
            Err(TxResolverError { txid, err: None })
        }
    }

    #[test]
    fn test_consignment_validation() {
        let consignments = consignments();
        let schema = schema();
        let status = consignments.validate(&schema, None, TestResolver);
        println!("{}", status);
    }
}
*/
