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

use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use rgb::Occurrences;
use strict_encoding::{FieldName, TypeName};

use crate::interface::{
    ExtensionIface, GenesisIface, Iface, Modifier, OpName, OwnedIface, TransitionIface,
};

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("{iface} {err}")]
pub struct InheritError {
    err: ExtensionError,
    iface: TypeName,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ExtensionError {
    /// too many global state types defined.
    GlobalOverflow,
    /// global state '{0}' has different data type from the parent interface.
    GlobalType(FieldName),
    /// global state '{0}' has fewer occurrences than in the parent interface.
    GlobalOcc(FieldName),
    /// too many assignment types defined.
    AssignmentOverflow,
    /// assignment '{0}' has different data type from the parent interface.
    AssignmentType(FieldName),
    /// assignment '{0}' has fewer occurrences than in the parent interface.
    AssignmentOcc(FieldName),
    /// global state '{0}' has lower visibility than in the parent interface.
    AssignmentPublic(FieldName),
    /// too many valency types defined.
    ValencyOverflow,
    /// valency '{0}' has fewer occurrences than in the parent interface.
    ValencyOcc(FieldName),
    /// too many state transitions.
    TransitionOverflow,
    /// too many state extensions.
    ExtensionOverflow,
    /// too many error types defined.
    ErrorOverflow,
    /// inherited interface tries to override the parent default operation.
    DefaultOverride,
    /// {0} in the parent interface is final and can't be overridden.
    OpFinal(OpName),
    /// {0} must use `override` keyword to modify the parent version.
    OpNoOverride(OpName),
    /// {0} overrides parent metadata type.
    OpMetadata(OpName),
    /// too many {1} types defined in {0}.
    OpOverflow(OpName, &'static str),
    /// {0} tries to override the parent default assignment.
    OpDefaultOverride(OpName),
    /// {0} tries to override '{2}' {1}.
    OpOcc(OpName, &'static str, FieldName),
    /// interface can't inherit from the given parents since the number of data
    /// types used by all of them exceeds maximum number.
    TypesOverflow,
    /// too deep inheritance; it is not allowed for any interface to have more
    /// than 255 parents it inherits from, including all grandparents.
    InheritanceOverflow,
}

impl OwnedIface {
    pub fn is_superset(self, other: OwnedIface) -> bool {
        if self == Self::Any {
            return true;
        }
        if self == Self::AnyData && matches!(other, Self::Data(_)) {
            return true;
        }
        self == other
    }
}

impl Modifier {
    pub fn is_final(self) -> bool { self == Self::Final }
    pub fn can_be_overriden_by(self, other: Modifier) -> bool {
        match (self, other) {
            (Self::Abstract | Self::Override, Self::Override | Self::Final) => true,
            _ => false,
        }
    }
}

impl Iface {
    pub fn expect_inherit(
        name: impl Into<TypeName>,
        ifaces: impl IntoIterator<Item = Iface>,
    ) -> Iface {
        let name = name.into();
        match Self::inherit(name.clone(), ifaces) {
            Ok(iface) => iface,
            Err(msgs) => {
                eprintln!("Unable to construct interface {name}:");
                for msg in msgs {
                    eprintln!("- {msg}")
                }
                panic!();
            }
        }
    }

    pub fn inherit(
        name: impl Into<TypeName>,
        ifaces: impl IntoIterator<Item = Iface>,
    ) -> Result<Iface, Vec<InheritError>> {
        let mut iter = ifaces.into_iter();
        let mut iface = iter
            .next()
            .expect("at least one interface must be provided for the inheritance");
        for ext in iter {
            let name = ext.name.clone();
            iface = iface.extended(ext).map_err(|err| {
                err.into_iter()
                    .map(|e| InheritError {
                        err: e,
                        iface: name.clone(),
                    })
                    .collect::<Vec<_>>()
            })?;
        }
        iface.name = name.into();
        Ok(iface)
    }

    pub fn expect_extended(self, ext: Iface) -> Iface {
        let name = self.name.clone();
        match self.extended(ext) {
            Ok(iface) => iface,
            Err(msgs) => {
                eprintln!("Unable to inherit from {name}:");
                for msg in msgs {
                    eprintln!("- {msg}")
                }
                panic!();
            }
        }
    }

    pub fn extended(mut self, ext: Iface) -> Result<Iface, Vec<ExtensionError>> {
        let parent_id = ext.iface_id();

        let mut errors = vec![];
        self.name = ext.name;

        for (name, e) in ext.global_state {
            match self.global_state.get_mut(&name) {
                None => {
                    if self
                        .global_state
                        .insert(name, e)
                        .map_err(|_| errors.push(ExtensionError::GlobalOverflow))
                        .is_err()
                    {
                        break;
                    }
                }
                Some(orig) => {
                    if orig.sem_id.is_some() && e.sem_id != orig.sem_id {
                        errors.push(ExtensionError::GlobalType(name));
                    } else if orig.required > e.required || orig.multiple > e.multiple {
                        errors.push(ExtensionError::GlobalOcc(name));
                    } else {
                        *orig = e;
                    }
                }
            }
        }

        for (name, e) in ext.assignments {
            match self.assignments.get_mut(&name) {
                None => {
                    if self
                        .assignments
                        .insert(name, e)
                        .map_err(|_| errors.push(ExtensionError::AssignmentOverflow))
                        .is_err()
                    {
                        break;
                    }
                }
                Some(orig) => {
                    if !orig.owned_state.is_superset(e.owned_state) {
                        errors.push(ExtensionError::AssignmentType(name));
                    } else if orig.required > e.required || orig.multiple > e.multiple {
                        errors.push(ExtensionError::AssignmentOcc(name));
                    } else if orig.public > e.public {
                        errors.push(ExtensionError::AssignmentPublic(name));
                    } else {
                        *orig = e;
                    }
                }
            }
        }

        for (name, e) in ext.valencies {
            match self.valencies.get_mut(&name) {
                None => {
                    if self
                        .valencies
                        .insert(name, e)
                        .map_err(|_| errors.push(ExtensionError::ValencyOverflow))
                        .is_err()
                    {
                        break;
                    }
                }
                Some(orig) => {
                    if orig.required > e.required {
                        errors.push(ExtensionError::ValencyOcc(name));
                    } else {
                        *orig = e;
                    }
                }
            }
        }

        self.clone()
            .genesis
            .extended(ext.genesis)
            .map(|genesis| self.genesis = genesis)
            .map_err(|errs| errors.extend(errs))
            .ok();

        for (name, op) in ext.transitions {
            match self.transitions.remove(&name) {
                Ok(None) if op.optional => continue,
                Ok(None) => {
                    if self
                        .transitions
                        .insert(name, op)
                        .map_err(|_| errors.push(ExtensionError::TransitionOverflow))
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Some(orig)) => {
                    orig.extended(op, name.clone())
                        .map(|op| self.transitions.insert(name, op).expect("same size"))
                        .map_err(|errs| errors.extend(errs))
                        .ok();
                }
                Err(_) => unreachable!(),
            }
        }

        for (name, op) in ext.extensions {
            match self.extensions.remove(&name) {
                Ok(None) if op.optional => continue,
                Ok(None) => {
                    if self
                        .extensions
                        .insert(name, op)
                        .map_err(|_| errors.push(ExtensionError::TransitionOverflow))
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Some(orig)) => {
                    orig.extended(op, name.clone())
                        .map(|op| self.extensions.insert(name, op).expect("same size"))
                        .map_err(|errs| errors.extend(errs))
                        .ok();
                }
                Err(_) => unreachable!(),
            }
        }

        // We allow replacing error messages
        self.errors
            .extend(ext.errors)
            .map_err(|_| errors.push(ExtensionError::ErrorOverflow))
            .ok();

        if ext.default_operation.is_some() {
            if self.default_operation.is_some() && self.default_operation != ext.default_operation {
                errors.push(ExtensionError::DefaultOverride);
            } else {
                self.default_operation = ext.default_operation
            }
        }

        if self.types != ext.types {
            self.types
                .extend(ext.types.into_strict())
                .map_err(|_| errors.push(ExtensionError::TypesOverflow))
                .ok();
        }

        self.inherits
            .extend(ext.inherits)
            .and_then(|_| self.inherits.push(parent_id))
            .map_err(|_| errors.push(ExtensionError::InheritanceOverflow))
            .ok();

        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }
}

fn check_occs(
    orig: &mut TinyOrdMap<FieldName, Occurrences>,
    ext: impl IntoIterator<Item = (FieldName, Occurrences)>,
    op: OpName,
    state: &'static str,
    errors: &mut Vec<ExtensionError>,
) {
    for (name, occ) in ext {
        match orig.get_mut(&name) {
            None => {
                if orig
                    .insert(name, occ)
                    .map_err(|_| errors.push(ExtensionError::OpOverflow(op.clone(), state)))
                    .is_err()
                {
                    break;
                }
            }
            Some(orig) => {
                if orig.min_value() > occ.min_value() || orig.max_value() > occ.max_value() {
                    errors.push(ExtensionError::OpOcc(op.clone(), state, name));
                } else {
                    *orig = occ;
                }
            }
        }
    }
}

fn check_presence<T: Ord + ToString>(
    orig: &mut TinyOrdSet<T>,
    ext: impl IntoIterator<Item = T>,
    op: OpName,
    state: &'static str,
    errors: &mut Vec<ExtensionError>,
) {
    for name in ext {
        if orig
            .push(name)
            .map_err(|_| errors.push(ExtensionError::OpOverflow(op.clone(), state)))
            .is_err()
        {
            break;
        }
    }
}

impl GenesisIface {
    pub fn extended(mut self, ext: Self) -> Result<Self, Vec<ExtensionError>> {
        let mut errors = vec![];

        let op = OpName::Genesis;
        if self.modifier.is_final() {
            errors.push(ExtensionError::OpFinal(op.clone()));
        } else if !self.modifier.can_be_overriden_by(ext.modifier) {
            errors.push(ExtensionError::OpNoOverride(op.clone()));
        }
        if self.metadata.is_some() && ext.metadata.is_some() && self.metadata != ext.metadata {
            errors.push(ExtensionError::OpMetadata(op.clone()));
        }

        check_occs(&mut self.globals, ext.globals, op.clone(), "global", &mut errors);
        check_occs(&mut self.assignments, ext.assignments, op.clone(), "assignment", &mut errors);

        check_presence(&mut self.valencies, ext.valencies, op.clone(), "valency", &mut errors);
        check_presence(&mut self.errors, ext.errors, op.clone(), "error", &mut errors);

        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }
}

impl TransitionIface {
    pub fn extended(mut self, ext: Self, op_name: FieldName) -> Result<Self, Vec<ExtensionError>> {
        let mut errors = vec![];

        let op = OpName::Transition(op_name);
        if self.modifier.is_final() {
            errors.push(ExtensionError::OpFinal(op.clone()));
        } else if !self.modifier.can_be_overriden_by(ext.modifier) {
            errors.push(ExtensionError::OpNoOverride(op.clone()));
        }
        self.optional = self.optional.max(ext.optional);
        if self.metadata.is_some() && ext.metadata.is_some() && self.metadata != ext.metadata {
            errors.push(ExtensionError::OpMetadata(op.clone()));
        }

        check_occs(&mut self.globals, ext.globals, op.clone(), "global", &mut errors);
        check_occs(&mut self.assignments, ext.assignments, op.clone(), "assignment", &mut errors);
        check_occs(&mut self.inputs, ext.inputs, op.clone(), "input", &mut errors);

        check_presence(&mut self.valencies, ext.valencies, op.clone(), "valency", &mut errors);
        check_presence(&mut self.errors, ext.errors, op.clone(), "error", &mut errors);

        if ext.default_assignment.is_some() {
            if self.default_assignment.is_some() &&
                self.default_assignment != ext.default_assignment
            {
                errors.push(ExtensionError::OpDefaultOverride(op.clone()));
            } else {
                self.default_assignment = ext.default_assignment
            }
        }

        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }
}

impl ExtensionIface {
    pub fn extended(mut self, ext: Self, op_name: FieldName) -> Result<Self, Vec<ExtensionError>> {
        let mut errors = vec![];

        let op = OpName::Transition(op_name);
        if self.modifier.is_final() {
            errors.push(ExtensionError::OpFinal(op.clone()));
        } else if !self.modifier.can_be_overriden_by(ext.modifier) {
            errors.push(ExtensionError::OpNoOverride(op.clone()));
        }
        self.optional = self.optional.max(ext.optional);
        if self.metadata.is_some() && ext.metadata.is_some() && self.metadata != ext.metadata {
            errors.push(ExtensionError::OpMetadata(op.clone()));
        }

        check_occs(&mut self.globals, ext.globals, op.clone(), "global", &mut errors);
        check_occs(&mut self.assignments, ext.assignments, op.clone(), "assignment", &mut errors);

        check_presence(&mut self.valencies, ext.valencies, op.clone(), "valency", &mut errors);
        check_presence(&mut self.redeems, ext.redeems, op.clone(), "input", &mut errors);
        check_presence(&mut self.errors, ext.errors, op.clone(), "error", &mut errors);

        if ext.default_assignment.is_some() {
            if self.default_assignment.is_some() &&
                self.default_assignment != ext.default_assignment
            {
                errors.push(ExtensionError::OpDefaultOverride(op.clone()));
            } else {
                self.default_assignment = ext.default_assignment
            }
        }

        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }
}
