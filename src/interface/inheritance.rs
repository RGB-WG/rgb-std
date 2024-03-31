// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use rgb::{
    AssignmentType, ExtensionType, GlobalStateType, OpFullType, OpSchema, Schema, TransitionType,
    ValencyType,
};
use strict_types::SemId;

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(doc_comments)]
pub enum InheritanceFailure {
    /// invalid schema - no match with root schema requirements for global state
    /// type #{0}.
    GlobalStateMismatch(GlobalStateType),
    /// invalid schema - no match with root schema requirements for assignment
    /// type #{0}.
    AssignmentTypeMismatch(AssignmentType),
    /// invalid schema - no match with root schema requirements for valency
    /// type #{0}.
    ValencyTypeMismatch(ValencyType),
    /// invalid schema - no match with root schema requirements for transition
    /// type #{0}.
    TransitionTypeMismatch(TransitionType),
    /// invalid schema - no match with root schema requirements for extension
    /// type #{0}.
    ExtensionTypeMismatch(ExtensionType),

    /// invalid schema - no match with root schema requirements for metadata
    /// type (required {expected}, found {actual}).
    OpMetaMismatch {
        op_type: OpFullType,
        expected: SemId,
        actual: SemId,
    },
    /// invalid schema - no match with root schema requirements for global state
    /// type #{1} used in {0}.
    OpGlobalStateMismatch(OpFullType, GlobalStateType),
    /// invalid schema - no match with root schema requirements for input
    /// type #{1} used in {0}.
    OpInputMismatch(OpFullType, AssignmentType),
    /// invalid schema - no match with root schema requirements for redeem
    /// type #{1} used in {0}.
    OpRedeemMismatch(OpFullType, ValencyType),
    /// invalid schema - no match with root schema requirements for assignment
    /// type #{1} used in {0}.
    OpAssignmentsMismatch(OpFullType, AssignmentType),
    /// invalid schema - no match with root schema requirements for valency
    /// type #{1} used in {0}.
    OpValencyMismatch(OpFullType, ValencyType),
}

pub trait CheckInheritance {
    fn check_inheritance(&self, root: &Self) -> Result<(), Vec<InheritanceFailure>>;
}

impl CheckInheritance for Schema {
    fn check_inheritance(&self, root: &Schema) -> Result<(), Vec<InheritanceFailure>> {
        let mut status = vec![];

        for (global_type, data_format) in &self.global_types {
            match root.global_types.get(global_type) {
                None => status.push(InheritanceFailure::GlobalStateMismatch(*global_type)),
                Some(root_data_format) if root_data_format != data_format => {
                    status.push(InheritanceFailure::GlobalStateMismatch(*global_type))
                }
                _ => {}
            };
        }

        for (assignments_type, state_schema) in &self.owned_types {
            match root.owned_types.get(assignments_type) {
                None => status.push(InheritanceFailure::AssignmentTypeMismatch(*assignments_type)),
                Some(root_state_schema) if root_state_schema != state_schema => {
                    status.push(InheritanceFailure::AssignmentTypeMismatch(*assignments_type))
                }
                _ => {}
            };
        }

        for valencies_type in &self.valency_types {
            if !root.valency_types.contains(valencies_type) {
                status.push(InheritanceFailure::ValencyTypeMismatch(*valencies_type));
            }
        }

        self.genesis
            .check_schema_op_inheritance(OpFullType::Genesis, &root.genesis)
            .map_err(|e| status.extend(e))
            .ok();

        for (type_id, transition_schema) in &self.transitions {
            if let Some(root_transition_schema) = root.transitions.get(type_id) {
                transition_schema
                    .check_schema_op_inheritance(
                        OpFullType::StateTransition(*type_id),
                        root_transition_schema,
                    )
                    .map_err(|e| status.extend(e))
                    .ok();
            } else {
                status.push(InheritanceFailure::TransitionTypeMismatch(*type_id));
            }
        }
        for (type_id, extension_schema) in &self.extensions {
            if let Some(root_extension_schema) = root.extensions.get(type_id) {
                extension_schema
                    .check_schema_op_inheritance(
                        OpFullType::StateExtension(*type_id),
                        root_extension_schema,
                    )
                    .map_err(|e| status.extend(e))
                    .ok();
            } else {
                status.push(InheritanceFailure::ExtensionTypeMismatch(*type_id));
            }
        }

        if status.is_empty() {
            Ok(())
        } else {
            Err(status)
        }
    }
}

/// Trait used for internal schema validation against some root schema
pub(crate) trait CheckSchemaOpInheritance {
    fn check_schema_op_inheritance(
        &self,
        op_type: OpFullType,
        root: &Self,
    ) -> Result<(), Vec<InheritanceFailure>>;
}

impl<T> CheckSchemaOpInheritance for T
where T: OpSchema
{
    fn check_schema_op_inheritance(
        &self,
        op_type: OpFullType,
        root: &Self,
    ) -> Result<(), Vec<InheritanceFailure>> {
        let mut status = vec![];

        if self.metadata() != root.metadata() {
            status.push(InheritanceFailure::OpMetaMismatch {
                op_type,
                expected: root.metadata(),
                actual: self.metadata(),
            });
        }

        for (type_id, occ) in self.globals() {
            match root.globals().get(type_id) {
                None => status.push(InheritanceFailure::OpGlobalStateMismatch(op_type, *type_id)),
                Some(root_occ) if occ != root_occ => {
                    status.push(InheritanceFailure::OpGlobalStateMismatch(op_type, *type_id))
                }
                _ => {}
            };
        }

        if let Some(inputs) = self.inputs() {
            let root_inputs = root.inputs().expect("generic guarantees");
            for (type_id, occ) in inputs {
                match root_inputs.get(type_id) {
                    None => status.push(InheritanceFailure::OpInputMismatch(op_type, *type_id)),
                    Some(root_occ) if occ != root_occ => {
                        status.push(InheritanceFailure::OpInputMismatch(op_type, *type_id))
                    }
                    _ => {}
                };
            }
        }

        for (type_id, occ) in self.assignments() {
            match root.assignments().get(type_id) {
                None => status.push(InheritanceFailure::OpAssignmentsMismatch(op_type, *type_id)),
                Some(root_occ) if occ != root_occ => {
                    status.push(InheritanceFailure::OpAssignmentsMismatch(op_type, *type_id))
                }
                _ => {}
            };
        }

        if let Some(redeems) = self.redeems() {
            let root_redeems = root.redeems().expect("generic guarantees");
            for type_id in redeems {
                if !root_redeems.contains(type_id) {
                    status.push(InheritanceFailure::OpRedeemMismatch(op_type, *type_id));
                }
            }
        }

        for type_id in self.valencies() {
            if !root.valencies().contains(type_id) {
                status.push(InheritanceFailure::OpValencyMismatch(op_type, *type_id));
            }
        }

        if status.is_empty() {
            Ok(())
        } else {
            Err(status)
        }
    }
}
