//! HTTP routes.
//!
//! All endpoints live under `/v1/...`. Authenticated endpoints use a Bearer
//! token that is validated by the [`AuthSession`] extractor.
//!
//! Author: Limmy

pub mod auth;
pub mod blobs;
pub mod devices;
pub mod misc;
pub mod objects;

mod session;

pub use session::AuthSession;
