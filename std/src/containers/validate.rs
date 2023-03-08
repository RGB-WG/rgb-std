// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

use rgb::validation::{ResolveTx, Validator, Validity, Warning};

use super::Consignment;

impl<const TYPE: bool> Consignment<TYPE> {
    pub fn validate<R: ResolveTx>(
        mut self,
        resolver: &mut R,
    ) -> Result<Consignment<TYPE>, Consignment<TYPE>> {
        let mut status = Validator::validate(&self, resolver);

        let validity = status.validity();

        if self.transfer != TYPE {
            status.add_warning(Warning::Custom(s!("invalid consignment type")));
        }
        // TODO: check that interface ids match implementations
        // TODO: check bundle ids listed in terminals are present in the consignment
        // TODO: check attach ids from data containers are present in operations

        self.validation_status = Some(status);
        if validity != Validity::Valid {
            Err(self)
        } else {
            Ok(self)
        }
    }
}
