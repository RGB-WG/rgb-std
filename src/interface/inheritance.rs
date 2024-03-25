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

use amplify::confinement::{TinyOrdMap, TinyOrdSet, TinyString};
use rgb::{Occurrences, Types};
use strict_encoding::{FieldName, TypeName, Variant};

use crate::interface::{
    AssignIface, ExtensionIface, GenesisIface, GlobalIface, Iface, IfaceId, Modifier, OpName,
    OwnedIface, TransitionIface, ValencyIface,
};
use crate::LIB_NAME_RGB_STD;

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
    /// '{0}' can't be overridden.
    OpModifier(OpName),
    /// '{0}' overrides parent metadata type.
    OpMetadata(OpName),
    /// too many {1} types defined in {0}.
    OpOverflow(OpName, &'static str),
    /// {0} can't be optional.
    OpOptional(OpName),
    /// {0} tries to override the parent default assignment.
    OpDefaultOverride(OpName),
    /// {0} tries to override '{2}' {1}.
    OpOcc(OpName, &'static str, FieldName),
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
    pub fn is_superset(self, other: Modifier) -> bool { self <= other }
}

#[derive(Clone, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = IfaceId)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct IfaceExt {
    pub name: TypeName,
    pub global_state: TinyOrdMap<FieldName, GlobalIface>,
    pub assignments: TinyOrdMap<FieldName, AssignIface>,
    pub valencies: TinyOrdMap<FieldName, ValencyIface>,
    pub genesis: GenesisIface,
    pub transitions: TinyOrdMap<FieldName, TransitionIface>,
    pub extensions: TinyOrdMap<FieldName, ExtensionIface>,
    pub default_operation: Option<FieldName>,
    pub errors: TinyOrdMap<Variant, TinyString>,
    pub types: Option<Types>,
}

impl Iface {
    pub fn into_extension(self) -> IfaceExt {
        IfaceExt {
            name: self.name,
            global_state: self.global_state,
            assignments: self.assignments,
            valencies: self.valencies,
            genesis: self.genesis,
            transitions: self.transitions,
            extensions: self.extensions,
            default_operation: self.default_operation,
            errors: self.errors,
            types: None, // TODO: check it
        }
    }

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
            iface = iface.extended(ext.into_extension()).map_err(|err| {
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

    pub fn expect_extended(self, ext: IfaceExt) -> Iface {
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

    pub fn extended(mut self, ext: IfaceExt) -> Result<Iface, Vec<ExtensionError>> {
        let mut errors = vec![];
        self.name = ext.name;

        let mut overflow = false;
        for (name, e) in ext.global_state {
            match self.global_state.get_mut(&name) {
                None if overflow => continue,
                None => {
                    self.global_state
                        .insert(name, e)
                        .map_err(|_| {
                            overflow = true;
                            errors.push(ExtensionError::GlobalOverflow)
                        })
                        .ok();
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

        overflow = false;
        for (name, e) in ext.assignments {
            match self.assignments.get_mut(&name) {
                None if overflow => continue,
                None => {
                    self.assignments
                        .insert(name, e)
                        .map_err(|_| {
                            overflow = true;
                            errors.push(ExtensionError::AssignmentOverflow)
                        })
                        .ok();
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

        overflow = false;
        for (name, e) in ext.valencies {
            match self.valencies.get_mut(&name) {
                None if overflow => continue,
                None => {
                    self.valencies
                        .insert(name, e)
                        .map_err(|_| {
                            overflow = true;
                            errors.push(ExtensionError::ValencyOverflow)
                        })
                        .ok();
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

        overflow = false;
        for (name, op) in ext.transitions {
            match self.transitions.remove(&name) {
                Ok(None) if overflow => continue,
                Ok(None) => {
                    self.transitions
                        .insert(name, op)
                        .map_err(|_| {
                            overflow = true;
                            errors.push(ExtensionError::TransitionOverflow)
                        })
                        .ok();
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

        overflow = false;
        for (name, op) in ext.extensions {
            match self.extensions.remove(&name) {
                Ok(None) if overflow => continue,
                Ok(None) => {
                    self.extensions
                        .insert(name, op)
                        .map_err(|_| {
                            overflow = true;
                            errors.push(ExtensionError::TransitionOverflow)
                        })
                        .ok();
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

        debug_assert_eq!(ext.types, None, "inheritance with types is not yet supported");

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
    let mut overflow = false;
    for (name, occ) in ext {
        match orig.get_mut(&name) {
            None if overflow => continue,
            None => {
                orig.insert(name, occ)
                    .map_err(|_| {
                        overflow = true;
                        errors.push(ExtensionError::OpOverflow(op.clone(), state))
                    })
                    .ok();
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
    let mut overflow = false;
    for name in ext {
        if overflow {
            continue;
        }
        orig.push(name)
            .map_err(|_| {
                overflow = true;
                errors.push(ExtensionError::OpOverflow(op.clone(), state))
            })
            .ok();
    }
}

impl GenesisIface {
    pub fn extended(mut self, ext: Self) -> Result<Self, Vec<ExtensionError>> {
        let mut errors = vec![];

        let op = OpName::Genesis;
        if !self.modifier.is_superset(ext.modifier) {
            errors.push(ExtensionError::OpModifier(op.clone()));
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
        if !self.modifier.is_superset(ext.modifier) {
            errors.push(ExtensionError::OpModifier(op.clone()));
        }
        if self.optional < ext.optional {
            errors.push(ExtensionError::OpOptional(op.clone()))
        }
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
        if !self.modifier.is_superset(ext.modifier) {
            errors.push(ExtensionError::OpModifier(op.clone()));
        }
        if self.optional < ext.optional {
            errors.push(ExtensionError::OpOptional(op.clone()))
        }
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
