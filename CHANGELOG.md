# Changelog

All notable changes to this project will be documented in this file.

The format follows the spirit of Keep a Changelog, and this project uses semantic versioning.

## [1.0.0] - 2026-06-22

### Added

- Initial public release of VaultUI Python.
- Single-file Python 3.8 implementation with minimal runtime dependencies.
- Curses-based TUI for browsing HashiCorp Vault.
- Dashboard with seal status, Vault version, HA details, storage backend, resource counts, and quick navigation.
- Secret engine browser with support for KV, PKI, Transit, Identity, Database, AWS, and generic mounts.
- KV v2 path browser, secret detail view, clipboard copy, version history, and version diff.
- Policy, auth method, PKI certificate/role, Transit key, Identity entity/group, Database, AWS, and token inspection views.
- Context switching through `~/.vaultui.yaml`.
- Token, userpass, and AppRole authentication.
- Command palette and configurable keybindings.
- Clipboard auto-clear for copied secrets.
- Headless `get` subcommand with JSON output.
- Local dev Vault seed script: `seed-vault-dev.sh`.
- PlantUML architecture diagrams in `diagramms/`.
- English and Russian README files.
