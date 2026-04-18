//! Environment sanitization for privilege escalation.

use std::collections::HashSet;
use std::env;

use crate::policy::SudoPolicy;

/// Environment variables that are always removed before exec.
pub const UNSAFE_ENV_VARS: &[&str] = &[
    // Dynamic linker — all LD_* are dangerous
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DYNAMIC_WEAK",
    "LD_BIND_NOW",
    "LD_AOUT_LIBRARY_PATH",
    "LD_AOUT_PRELOAD",
    "LD_ORIGIN_PATH",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV",
    "LD_USE_LOAD_BIAS",
    "LD_HWCAP_MASK",
    "LD_TRACE_LOADED_OBJECTS",
    "LD_WARN",
    "LD_VERBOSE",
    "LD_TRACE_PRELINKING",
    // DNS/locale hijacking
    "LOCALDOMAIN",
    "RES_OPTIONS",
    "HOSTALIASES",
    "NLSPATH",
    "PATH_LOCALE",
    "GCONV_PATH",
    // Shell injection vectors
    "IFS",
    "ENV",
    "BASH_ENV",
    "CDPATH",
    "GLOBIGNORE",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "PROMPT_COMMAND",
    "INPUTRC",
    // Interpreter code injection
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PERL5LIB",
    "PERL5OPT",
    "PERLLIB",
    "PERL_MM_OPT",
    "RUBYLIB",
    "RUBYOPT",
    "GEM_HOME",
    "GEM_PATH",
    "BUNDLE_GEMFILE",
    "NODE_PATH",
    "NODE_OPTIONS",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    "LUA_PATH",
    "LUA_CPATH",
    "PHPRC",
];

/// Environment variables preserved by default.
pub const SAFE_ENV_VARS: &[&str] = &[
    "TERM",
    "COLORTERM",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "DISPLAY",
    "XAUTHORITY",
];

/// Build a sanitized environment for the target command.
#[must_use]
#[allow(clippy::vec_init_then_push)]
pub fn sanitize_environment(
    policy: &SudoPolicy,
    caller_user: &str,
    target_user: &str,
    target_home: &str,
    target_shell: &str,
) -> Vec<(String, String)> {
    let mut result: Vec<(String, String)> = Vec::new();

    // Always set these
    result.push(("USER".to_string(), target_user.to_string()));
    result.push(("LOGNAME".to_string(), target_user.to_string()));
    result.push(("HOME".to_string(), target_home.to_string()));
    result.push(("SHELL".to_string(), target_shell.to_string()));
    result.push((
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    ));
    result.push(("SUDO_USER".to_string(), caller_user.to_string()));
    result.push(("SUDO_UID".to_string(), nix::unistd::getuid().to_string()));
    result.push(("SUDO_GID".to_string(), nix::unistd::getgid().to_string()));

    // Preserve safe vars from current environment
    let keep_set: HashSet<&str> = SAFE_ENV_VARS
        .iter()
        .copied()
        .chain(policy.defaults.env_keep.iter().map(|s| s.as_str()))
        .collect();

    for (key, value) in env::vars() {
        // Block all LD_* regardless of explicit list — the linker namespace is unbounded
        if key.starts_with("LD_") {
            continue;
        }
        // Block BASH_FUNC_* — exported bash functions (ShellShock attack vector)
        if key.starts_with("BASH_FUNC_") {
            continue;
        }
        if keep_set.contains(key.as_str()) && !UNSAFE_ENV_VARS.contains(&key.as_str()) {
            result.push((key, value));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_policy;

    #[test]
    fn test_sanitize_environment() {
        let policy = parse_policy("").unwrap();
        let env = sanitize_environment(&policy, "alice", "root", "/root", "/bin/bash");

        let env_map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(env_map["USER"], "root");
        assert_eq!(env_map["LOGNAME"], "root");
        assert_eq!(env_map["HOME"], "/root");
        assert_eq!(env_map["SHELL"], "/bin/bash");
        assert_eq!(env_map["SUDO_USER"], "alice");
        assert!(env_map.contains_key("PATH"));
    }

    #[test]
    fn test_sanitize_environment_no_unsafe_vars() {
        let policy = parse_policy("").unwrap();
        let env = sanitize_environment(&policy, "alice", "root", "/root", "/bin/bash");

        let keys: HashSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        for var in UNSAFE_ENV_VARS {
            assert!(
                !keys.contains(var),
                "Unsafe var {} should not be in env",
                var
            );
        }
    }

    #[test]
    fn test_sanitize_environment_with_env_keep() {
        let policy = parse_policy(
            r#"
[defaults]
env_keep = ["EDITOR"]
"#,
        )
        .unwrap();
        assert!(policy.defaults.env_keep.contains(&"EDITOR".to_string()));
    }

    #[test]
    fn test_sanitize_environment_blocks_unknown_ld_vars() {
        let policy = parse_policy(
            r#"
[defaults]
env_keep = ["LD_FUTURE_EXPLOIT"]
"#,
        )
        .unwrap();

        // SAFETY: test runs are single-threaded for this test
        unsafe { std::env::set_var("LD_FUTURE_EXPLOIT", "gotcha") };
        let env = sanitize_environment(&policy, "alice", "root", "/root", "/bin/bash");
        let keys: HashSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            !keys.contains("LD_FUTURE_EXPLOIT"),
            "LD_* prefix catch-all should block even env_keep'd LD_ vars"
        );
        // SAFETY: test cleanup
        unsafe { std::env::remove_var("LD_FUTURE_EXPLOIT") };
    }

    #[test]
    fn test_unsafe_env_vars_contains_ld_preload() {
        assert!(UNSAFE_ENV_VARS.contains(&"LD_PRELOAD"));
        assert!(UNSAFE_ENV_VARS.contains(&"LD_LIBRARY_PATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"BASH_ENV"));
        assert!(UNSAFE_ENV_VARS.contains(&"IFS"));
    }

    #[test]
    fn test_safe_env_vars() {
        assert!(SAFE_ENV_VARS.contains(&"TERM"));
        assert!(SAFE_ENV_VARS.contains(&"LANG"));
        assert!(SAFE_ENV_VARS.contains(&"TZ"));
    }

    #[test]
    fn test_unsafe_env_vars_ld_extras() {
        assert!(UNSAFE_ENV_VARS.contains(&"LD_HWCAP_MASK"));
        assert!(UNSAFE_ENV_VARS.contains(&"LD_TRACE_LOADED_OBJECTS"));
        assert!(UNSAFE_ENV_VARS.contains(&"LD_WARN"));
        assert!(UNSAFE_ENV_VARS.contains(&"LD_VERBOSE"));
        assert!(UNSAFE_ENV_VARS.contains(&"LD_TRACE_PRELINKING"));
    }

    #[test]
    fn test_unsafe_env_vars_interpreters() {
        assert!(UNSAFE_ENV_VARS.contains(&"PYTHONPATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"PYTHONSTARTUP"));
        assert!(UNSAFE_ENV_VARS.contains(&"PERL5LIB"));
        assert!(UNSAFE_ENV_VARS.contains(&"PERL_MM_OPT"));
        assert!(UNSAFE_ENV_VARS.contains(&"RUBYLIB"));
        assert!(UNSAFE_ENV_VARS.contains(&"GEM_HOME"));
        assert!(UNSAFE_ENV_VARS.contains(&"GEM_PATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"BUNDLE_GEMFILE"));
        assert!(UNSAFE_ENV_VARS.contains(&"NODE_PATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"NODE_OPTIONS"));
        assert!(UNSAFE_ENV_VARS.contains(&"CLASSPATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"JAVA_TOOL_OPTIONS"));
        assert!(UNSAFE_ENV_VARS.contains(&"LUA_PATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"LUA_CPATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"PHPRC"));
    }

    #[test]
    fn test_unsafe_env_vars_shell_extras() {
        assert!(UNSAFE_ENV_VARS.contains(&"INPUTRC"));
    }

    #[test]
    fn test_sanitize_environment_blocks_bash_func() {
        let policy = parse_policy("").unwrap();

        // SAFETY: test runs are single-threaded for this test
        unsafe { std::env::set_var("BASH_FUNC_exploit%%", "() { evil; }") };
        let env = sanitize_environment(&policy, "alice", "root", "/root", "/bin/bash");
        let keys: HashSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            !keys.contains("BASH_FUNC_exploit%%"),
            "BASH_FUNC_* prefix should be blocked (ShellShock)"
        );
        // SAFETY: test cleanup
        unsafe { std::env::remove_var("BASH_FUNC_exploit%%") };
    }

    #[test]
    fn test_sanitize_environment_actually_removes_set_unsafe_vars() {
        // Set a representative subset of unsafe vars and verify they are stripped
        let dangerous = [
            "LD_PRELOAD",
            "PYTHONPATH",
            "IFS",
            "BASH_ENV",
            "NODE_OPTIONS",
            "GEM_HOME",
        ];

        // SAFETY: test isolation
        for var in &dangerous {
            unsafe { std::env::set_var(var, "evil") };
        }

        let policy = parse_policy("").unwrap();
        let env = sanitize_environment(&policy, "alice", "root", "/root", "/bin/bash");
        let keys: HashSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();

        for var in &dangerous {
            assert!(
                !keys.contains(var),
                "Unsafe var {} was present in sanitized env after being set",
                var
            );
        }

        // SAFETY: test cleanup
        for var in &dangerous {
            unsafe { std::env::remove_var(var) };
        }
    }

    #[test]
    fn test_sanitize_env_keep_does_not_override_unsafe() {
        // Even if an unsafe var is in env_keep, it must still be blocked
        let policy = parse_policy(
            r#"
[defaults]
env_keep = ["PYTHONPATH", "IFS", "BASH_ENV"]
"#,
        )
        .unwrap();

        // SAFETY: test isolation
        unsafe {
            std::env::set_var("PYTHONPATH", "evil");
            std::env::set_var("IFS", "evil");
            std::env::set_var("BASH_ENV", "evil");
        }

        let env = sanitize_environment(&policy, "alice", "root", "/root", "/bin/bash");
        let keys: HashSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();

        assert!(
            !keys.contains("PYTHONPATH"),
            "PYTHONPATH leaked through env_keep"
        );
        assert!(!keys.contains("IFS"), "IFS leaked through env_keep");
        assert!(
            !keys.contains("BASH_ENV"),
            "BASH_ENV leaked through env_keep"
        );

        // SAFETY: test cleanup
        unsafe {
            std::env::remove_var("PYTHONPATH");
            std::env::remove_var("IFS");
            std::env::remove_var("BASH_ENV");
        }
    }

    #[test]
    fn test_sanitize_bash_func_via_env_keep_still_blocked() {
        let policy = parse_policy(
            r#"
[defaults]
env_keep = ["BASH_FUNC_exploit%%"]
"#,
        )
        .unwrap();

        unsafe { std::env::set_var("BASH_FUNC_exploit%%", "() { evil; }") };
        let env = sanitize_environment(&policy, "alice", "root", "/root", "/bin/bash");
        let keys: HashSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains("BASH_FUNC_exploit%%"));
        unsafe { std::env::remove_var("BASH_FUNC_exploit%%") };
    }
}
