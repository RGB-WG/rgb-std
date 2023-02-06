#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum RevealError {
    /// the provided state transition is not a part of the bundle
    UnrelatedTransition,
}

pub type AnchoredBundle<'me> = (&'me Anchor<mpc::MerkleProof>, &'me TransitionBundle);

impl TransitionBundle {
    pub fn node_ids(&self) -> BTreeSet<NodeId> {
        self.concealed
            .keys()
            .copied()
            .chain(self.revealed.keys().map(Transition::node_id))
            .collect()
    }

    pub fn contains_id(&self, node_id: NodeId) -> bool {
        self.is_concealed(node_id) || self.is_revealed(node_id)
    }

    pub fn inputs_for(&self, node_id: NodeId) -> Option<&BTreeSet<u16>> {
        self.revealed
            .iter()
            .find_map(
                |(ts, inputs)| {
                    if ts.node_id() == node_id {
                        Some(inputs)
                    } else {
                        None
                    }
                },
            )
            .or_else(|| self.concealed.get(&node_id))
    }

    pub fn is_revealed(&self, node_id: NodeId) -> bool {
        self.revealed.keys().any(|ts| ts.node_id() == node_id)
    }

    pub fn is_concealed(&self, node_id: NodeId) -> bool { self.concealed.contains_key(&node_id) }

    pub fn reveal_transition(&mut self, transition: Transition) -> Result<bool, RevealError> {
        let id = transition.node_id();
        if let Some(inputs) = self.concealed.remove(&id) {
            self.revealed.insert(transition, inputs);
            Ok(true)
        } else if self.revealed.contains_key(&transition) {
            Ok(false)
        } else {
            Err(RevealError::UnrelatedTransition)
        }
    }

    pub fn known_node_ids(&self) -> BTreeSet<NodeId> {
        self.known_transitions().map(Transition::node_id).collect()
    }
}
