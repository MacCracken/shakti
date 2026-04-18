//! Shakti — AGNOS privilege escalation tool
//!
//! Library crate providing policy evaluation, environment sanitization,
//! command validation, and timestamp management for privilege escalation.

pub mod api;
pub mod audit;
pub mod auth;
pub mod env;
pub mod policy;
pub mod timestamp;
pub mod validate;

// Re-export primary API at crate root for ergonomic access.
pub use env::{SAFE_ENV_VARS, UNSAFE_ENV_VARS, sanitize_environment};
pub use policy::{
    AuthzResult, DEFAULT_POLICY_PATH, MAX_COMMAND_LEN, PolicyDefaults, PolicyRule, PolicyWarning,
    SudoPolicy, check_authorization, lint_policy, load_policy, parse_policy,
};
pub use timestamp::{
    DEFAULT_TIMESTAMP_DIR, DEFAULT_TIMESTAMP_TTL_SECS, check_timestamp, invalidate_timestamp,
    timestamp_path, update_timestamp,
};

/// Maximum authentication attempts before lockout.
pub const MAX_AUTH_ATTEMPTS: u32 = 3;
pub use validate::{command_matches, resolve_command, validate_command, validate_username};

pub use audit::{AuditAction, audit_log, init_tracing};
pub use auth::authenticate;

// Consumer API re-exports
pub use api::{AuthMode, Evaluation, ShaktiConfig, evaluate, evaluate_with_policy};
