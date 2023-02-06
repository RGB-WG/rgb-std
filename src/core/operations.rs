trait NodeExt {
    fn node_outputs(&self, witness_txid: Txid) -> BTreeMap<NodeOutpoint, Outpoint> {
        let node_id = self.node_id();
        let mut res: BTreeMap<NodeOutpoint, Outpoint> = bmap! {};
        for (ty, assignments) in self.owned_rights() {
            for (seal, node_output) in assignments.revealed_seal_outputs() {
                let outpoint = seal.outpoint_or(witness_txid);
                let node_outpoint = NodeOutpoint::new(node_id, *ty, node_output);
                res.insert(node_outpoint, outpoint);
            }
        }
        res
    }

    #[inline]
    fn revealed_seals(&self) -> Result<Vec<seal::Revealed>, ConfidentialDataError> {
        let unfiltered = self
            .owned_rights()
            .iter()
            .map(|(_, assignment)| assignment.revealed_seals())
            .collect::<Vec<_>>();
        if unfiltered.contains(&Err(ConfidentialDataError)) {
            return Err(ConfidentialDataError);
        }
        Ok(unfiltered
            .into_iter()
            .filter_map(Result::ok)
            .flat_map(Vec::into_iter)
            .collect())
    }

    #[inline]
    fn revealed_seals_by_type(
        &self,
        assignment_type: OwnedRightType,
    ) -> Result<Vec<seal::Revealed>, ConfidentialDataError> {
        Ok(self
            .owned_rights_by_type(assignment_type)
            .map(TypedState::revealed_seals)
            .transpose()?
            .unwrap_or_default())
    }

    #[inline]
    fn filter_revealed_seals(&self) -> Vec<seal::Revealed> {
        self.owned_rights()
            .iter()
            .flat_map(|(_, assignment)| assignment.filter_revealed_seals())
            .collect()
    }

    #[inline]
    fn filter_revealed_seals_by_type(
        &self,
        assignment_type: OwnedRightType,
    ) -> Vec<seal::Revealed> {
        self.owned_rights_by_type(assignment_type)
            .map(TypedState::filter_revealed_seals)
            .unwrap_or_else(Vec::new)
    }

    #[inline]
    fn field_types(&self) -> Vec<FieldType> { self.global_state().keys().copied().collect() }

    #[inline]
    fn redeemed_types(&self) -> Vec<PublicRightType> {
        self.redeemed()
            .values()
            .flat_map(|v| v.iter())
            .copied()
            .collect()
    }

    #[inline]
    fn prev_op_by_valency(&self, t: PublicRightType) -> Vec<OpId> {
        self.redeemed()
            .iter()
            .filter(|(_, t2)| t2.contains(&t))
            .map(|(node_id, _)| *node_id)
            .collect()
    }

    /// For genesis and public state extensions always returns an empty list.
    /// While public state extension do have parent nodes, they do not contain
    /// indexed rights.
    #[inline]
    fn prev_assignments(&self) -> Vec<PrevAssignment> {
        self.prev_state()
            .iter()
            .flat_map(|(node_id, map)| {
                let node_id = *node_id;
                map.iter()
                    .flat_map(|(ty, vec)| vec.iter().map(|no| (*ty, *no)))
                    .map(move |(ty, no)| PrevAssignment {
                        op: node_id,
                        ty,
                        no,
                    })
            })
            .collect()
    }

    #[inline]
    fn prev_assignments_by_type(&self, t: OwnedRightType) -> Vec<PrevAssignment> {
        self.prev_assignments_by_types(&[t])
    }

    fn prev_assignments_by_types(&self, types: &[OwnedRightType]) -> Vec<PrevAssignment> {
        self.prev_state()
            .iter()
            .flat_map(|(node_id, map)| {
                let node_id = *node_id;
                map.iter()
                    .filter(|(t, _)| types.contains(*t))
                    .flat_map(|(ty, vec)| vec.iter().map(|no| (*ty, *no)))
                    .map(move |(ty, no)| PrevAssignment {
                        op: node_id,
                        ty,
                        no,
                    })
            })
            .collect()
    }

    #[inline]
    fn prev_state_types(&self) -> Vec<OwnedRightType> {
        self.prev_state()
            .values()
            .flat_map(|v| v.keys())
            .copied()
            .collect()
    }

    #[inline]
    fn owned_state_types(&self) -> BTreeSet<OwnedRightType> {
        self.owned_state().keys().cloned().collect()
    }
}
