# ADR-003: Argument-Level Command Matching in Policy Patterns

## Status

Accepted (2026-04-04)

## Context

The policy format supports command patterns with arguments, e.g.:
- `commands = ["/usr/bin/systemctl restart *"]`
- `deny_commands = ["/usr/bin/systemctl stop firewall"]`

However, the original implementation passed only the resolved binary path (not arguments) to the authorization engine, making argument-level patterns completely ineffective. This was a critical authorization bypass — deny rules with arguments were silently ignored.

## Decision

1. Pass the full command string (binary path + arguments) to `check_authorization`.
2. Extend `command_matches` with a trailing ` *` wildcard pattern: if a pattern ends with ` *`, the command must start with the prefix before ` *`.
3. For path-level matching (directory globs and basename), extract only the binary portion (before the first space).

## Consequences

- **Positive**: `deny_commands` patterns with arguments now work correctly.
- **Positive**: Fine-grained allow patterns like `/usr/bin/systemctl restart *` now restrict which subcommands are permitted.
- **Negative**: ~10ns regression in `command_matches` for glob and basename patterns due to the additional `strip_suffix(" *")` check and `find(' ')` call. This is negligible in the context of a privilege escalation tool where authentication takes milliseconds.
- **Negative**: The ` *` wildcard is a simple prefix match, not a full glob. Patterns like `/usr/bin/cmd foo * bar` are not supported. This is consistent with sudo's approach and sufficient for real-world use cases.
