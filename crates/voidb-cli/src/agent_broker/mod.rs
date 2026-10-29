//! Short-lived local authorization broker for agent-initiated VoidB commands.
//!
//! The broker holds the master password only in process memory. Agents receive
//! a profile-, plugin-, capability-, and time-scoped grant that lets the
//! broker execute a narrow set of VoidB commands and return their already
//! redacted output. A finite use budget is optional. The master password is
//! never returned through this API.

#![cfg_attr(not(unix), allow(unused_imports))]

use std::time::Duration;

mod audit;
mod commands;
mod jit;
mod ledger;
mod runtime;
mod session;
mod wire;

#[cfg(test)]
mod tests;

pub use commands::{handle_early, take_broker_child_password};

const GRANT_VERSION: u32 = 1;
const BROKER_READY_TIMEOUT: Duration = Duration::from_secs(3);
const BROKER_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const BROKER_CHILD_ENV: &str = "VOIDB_INTERNAL_BROKER_CHILD";
const AGENT_CLIENT_ID_ENV: &str = "VOIDB_AGENT_CLIENT_ID";
const AGENT_TASK_ID_ENV: &str = "VOIDB_AGENT_TASK_ID";
const AGENT_INSTANCE_ID_ENV: &str = "VOIDB_AGENT_INSTANCE_ID";
const AGENT_THREAD_ID_ENV: &str = "VOIDB_AGENT_THREAD_ID";

#[cfg(all(test, feature = "full"))]
use crate::builtin::invoke::resolved_authorization_capabilities;
#[cfg(all(test, feature = "full"))]
use audit::{AgentSessionAuditContext, build_agent_session_audit_event};
#[cfg(all(test, feature = "full"))]
use ledger::AgentGrantFile;
#[cfg(all(test, feature = "full"))]
use runtime::{broker_session_error, session_call_allowed, session_open_allowed};

#[cfg(all(test, feature = "full"))]
#[path = "../data_search_live_session_conformance.rs"]
mod data_search_live_session_conformance;
