//! # lm-provision-protocol
//!
//! The types that cross the license boundary, and nothing else.
//!
//! The workspace has two sides. The engine — `lm-provision`,
//! [`lm-provision-driver`](https://docs.rs/lm-provision-driver),
//! `lm-provision-mcp` — is dual-licensed MIT / Apache-2.0 and stays
//! that way. The control plane — `lm-provision-host`, an empty
//! scaffold today — is AGPL-3.0-or-later. Both sides read and write
//! the same rows, so the vocabulary they share cannot live on either
//! one: a permissive caller may not link the AGPL crate, and moving
//! the AGPL crate's types into the permissive ones would relicense
//! them by the back door. It lives here, permissive, depended on from
//! both directions.
//!
//! **The license boundary is the crate boundary.** That is the only
//! line a compiler can check, which is why the split was cut before
//! the host implementation exists rather than after — relicensing code
//! that has already taken outside contributions needs a CLA or DCO
//! from every contributor.
//!
//! The shared vocabulary starts as one thing, the apply-ledger row
//! schema and its JSON Lines encoding ([`ledger`]), because that is
//! what both sides touch today: the driver appends a row, the host
//! will take custody of the file. It grows as the host lands —
//! acquisition records are the next wire types with a reader on each
//! side.

#![warn(missing_docs)]

pub mod ledger;
