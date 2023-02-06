#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// some of the requested data are confidential, when they must be present in
/// revealed form.
pub struct ConfidentialDataError;

/// Errors retrieving state data.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StateRetrievalError {
    /// the requested state has a mismatched data type.
    StateTypeMismatch,

    /// some of the requested data are confidential, when they must be present
    /// in revealed form.
    #[from(ConfidentialDataError)]
    ConfidentialData,
}

impl TypedState {
    pub fn revealed_seal_outputs(&self) -> Vec<(seal::Revealed, u16)> {
        match self {
            TypedState::Declarative(s) => s
                .iter()
                .map(AssignedState::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
            TypedState::Fungible(s) => s
                .iter()
                .map(AssignedState::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
            TypedState::Structured(s) => s
                .iter()
                .map(AssignedState::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
            TypedState::Attachment(s) => s
                .iter()
                .map(AssignedState::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
        }
    }

    pub fn filter_revealed_seals(&self) -> Vec<seal::Revealed> {
        match self {
            TypedState::Declarative(s) => s
                .iter()
                .filter_map(AssignedState::<_>::revealed_seal)
                .collect(),
            TypedState::Fungible(s) => s
                .iter()
                .filter_map(AssignedState::<_>::revealed_seal)
                .collect(),
            TypedState::Structured(s) => s
                .iter()
                .filter_map(AssignedState::<_>::revealed_seal)
                .collect(),
            TypedState::Attachment(s) => s
                .iter()
                .filter_map(AssignedState::<_>::revealed_seal)
                .collect(),
        }
    }

    pub fn revealed_seals(&self) -> Result<Vec<seal::Revealed>, ConfidentialDataError> {
        let list: Vec<_> = match self {
            TypedState::Declarative(s) => s.iter().map(AssignedState::<_>::revealed_seal).collect(),
            TypedState::Fungible(s) => s.iter().map(AssignedState::<_>::revealed_seal).collect(),
            TypedState::Structured(s) => s.iter().map(AssignedState::<_>::revealed_seal).collect(),
            TypedState::Attachment(s) => s.iter().map(AssignedState::<_>::revealed_seal).collect(),
        };
        let len = list.len();
        let filtered: Vec<seal::Revealed> = list.into_iter().flatten().collect();
        if len != filtered.len() {
            return Err(ConfidentialDataError);
        }
        Ok(filtered)
    }

    pub fn revealed_fungible_state(&self) -> Result<Vec<&value::Revealed>, StateRetrievalError> {
        let list = match self {
            TypedState::Fungible(s) => s.iter().map(AssignedState::<_>::as_revealed_state),
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&value::Revealed> = list.flatten().collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        Ok(filtered)
    }

    pub fn revealed_structured_state(&self) -> Result<Vec<&data::Revealed>, StateRetrievalError> {
        let list = match self {
            TypedState::Structured(s) => s.iter().map(AssignedState::<_>::as_revealed_state),
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&data::Revealed> = list.flatten().collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        Ok(filtered)
    }

    pub fn revealed_attachments(&self) -> Result<Vec<&attachment::Revealed>, StateRetrievalError> {
        let list = match self {
            TypedState::Attachment(s) => s.iter().map(AssignedState::<_>::as_revealed_state),
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&attachment::Revealed> = list.flatten().collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        Ok(filtered)
    }

    pub fn filter_revealed_fungible_state(&self) -> Vec<&value::Revealed> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(s) => s
                .iter()
                .filter_map(AssignedState::<_>::as_revealed_state)
                .collect(),
            TypedState::Structured(_) => vec![],
            TypedState::Attachment(_) => vec![],
        }
    }

    pub fn filter_revealed_structured_state(&self) -> Vec<&data::Revealed> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(_) => vec![],
            TypedState::Structured(s) => s
                .iter()
                .filter_map(AssignedState::<_>::as_revealed_state)
                .collect(),
            TypedState::Attachment(_) => vec![],
        }
    }

    pub fn filter_revealed_attachments(&self) -> Vec<&attachment::Revealed> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(_) => vec![],
            TypedState::Structured(_) => vec![],
            TypedState::Attachment(s) => s
                .iter()
                .filter_map(AssignedState::<_>::as_revealed_state)
                .collect(),
        }
    }

    pub fn to_confidential_fungible_state(&self) -> Vec<value::Confidential> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(s) => s
                .iter()
                .map(AssignedState::<_>::to_confidential_state)
                .collect(),
            TypedState::Structured(_) => vec![],
            TypedState::Attachment(_) => vec![],
        }
    }

    pub fn to_confidential_structured_state(&self) -> Vec<data::Confidential> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(_) => vec![],
            TypedState::Structured(s) => s
                .iter()
                .map(AssignedState::<_>::to_confidential_state)
                .collect(),
            TypedState::Attachment(_) => vec![],
        }
    }

    pub fn to_confidential_attachments(&self) -> Vec<attachment::Confidential> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(_) => vec![],
            TypedState::Structured(_) => vec![],
            TypedState::Attachment(s) => s
                .iter()
                .map(AssignedState::<_>::to_confidential_state)
                .collect(),
        }
    }

    #[inline]
    pub fn revealed_fungible_assignments(
        &self,
    ) -> Result<Vec<(seal::Revealed, &value::Revealed)>, StateRetrievalError> {
        match self {
            TypedState::Fungible(vec) => {
                let unfiltered: Vec<_> = vec
                    .iter()
                    .filter_map(|assignment| {
                        assignment.revealed_seal().and_then(|seal| {
                            assignment.as_revealed_state().map(|state| (seal, state))
                        })
                    })
                    .collect();
                if unfiltered.len() != vec.len() {
                    Err(StateRetrievalError::ConfidentialData)
                } else {
                    Ok(unfiltered)
                }
            }
            _ => Err(StateRetrievalError::StateTypeMismatch),
        }
    }

    #[inline]
    pub fn revealed_structured_assignments(
        &self,
    ) -> Result<Vec<(seal::Revealed, &data::Revealed)>, StateRetrievalError> {
        match self {
            TypedState::Structured(vec) => {
                let unfiltered: Vec<_> = vec
                    .iter()
                    .filter_map(|assignment| {
                        assignment.revealed_seal().and_then(|seal| {
                            assignment.as_revealed_state().map(|state| (seal, state))
                        })
                    })
                    .collect();
                if unfiltered.len() != vec.len() {
                    Err(StateRetrievalError::ConfidentialData)
                } else {
                    Ok(unfiltered)
                }
            }
            _ => Err(StateRetrievalError::StateTypeMismatch),
        }
    }

    #[inline]
    pub fn revealed_attachment_assignments(
        &self,
    ) -> Result<Vec<(seal::Revealed, &attachment::Revealed)>, StateRetrievalError> {
        match self {
            TypedState::Attachment(vec) => {
                let unfiltered: Vec<_> = vec
                    .iter()
                    .filter_map(|assignment| {
                        assignment.revealed_seal().and_then(|seal| {
                            assignment.as_revealed_state().map(|state| (seal, state))
                        })
                    })
                    .collect();
                if unfiltered.len() != vec.len() {
                    Err(StateRetrievalError::ConfidentialData)
                } else {
                    Ok(unfiltered)
                }
            }
            _ => Err(StateRetrievalError::StateTypeMismatch),
        }
    }
}
