# ADR-004: Environment Sanitization Strategy

## Status

Accepted (2026-04-04)

## Context

A setuid-root binary inherits the caller's environment, which can contain variables that hijack dynamic linking, shell behavior, or interpreter module loading. The sanitization strategy must be both comprehensive and maintainable.

## Decision

Use a three-layer approach:

1. **Prefix blocking**: Block entire namespaces by prefix — `LD_*` (dynamic linker) and `BASH_FUNC_*` (ShellShock-style function exports). This catches future additions to these namespaces without requiring list updates.

2. **Explicit blocklist**: Named variables across categories:
   - Shell injection: `IFS`, `BASH_ENV`, `CDPATH`, `SHELLOPTS`, `PS4`, `PROMPT_COMMAND`, `INPUTRC`
   - DNS/locale hijacking: `LOCALDOMAIN`, `RES_OPTIONS`, `HOSTALIASES`, `NLSPATH`, `GCONV_PATH`
   - Interpreter injection: Python (`PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`), Perl (`PERL5LIB`, `PERL5OPT`, `PERLLIB`, `PERL_MM_OPT`), Ruby (`RUBYLIB`, `RUBYOPT`, `GEM_HOME`, `GEM_PATH`, `BUNDLE_GEMFILE`), Node (`NODE_PATH`, `NODE_OPTIONS`), Java (`CLASSPATH`, `JAVA_TOOL_OPTIONS`), Lua (`LUA_PATH`, `LUA_CPATH`), PHP (`PHPRC`)

3. **Allow-list**: Only variables in `SAFE_ENV_VARS` (plus policy `env_keep`) pass through. Even if a variable is in `env_keep`, it is blocked if it appears in the explicit blocklist or matches a blocked prefix.

## Consequences

- **Positive**: Prefix blocking is future-proof for `LD_*` and `BASH_FUNC_*` namespaces.
- **Positive**: `env_keep` cannot override safety — the blocklist always wins.
- **Positive**: The allow-list default means unknown variables are dropped, not passed.
- **Negative**: New dangerous variables in other namespaces (e.g., a future `RUBY_*` prefix) require manual addition to the blocklist. This is mitigated by the allow-list default.
