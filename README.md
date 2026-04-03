# Shakti

**Shakti** (Sanskrit: power/energy) — AGNOS privilege escalation tool.

Authenticates the calling user (via PAM or password verification), checks a
TOML-based policy file (`/etc/agnos/sudoers.toml`), then executes the
requested command with the target user's credentials.

## Security Properties

- All attempts (success and failure) are audit-logged
- Environment is sanitized before exec
- Command arguments are validated against shell injection
- Policy supports per-user, per-group, and per-command rules
- Rate-limited authentication (max 3 attempts)
- Timestamp-based credential caching (configurable TTL)

## Part of AGNOS

Shakti is a component of [AGNOS](https://agnosticos.org), the AI-Native General Operating System.

## License

GPL-3.0-only
