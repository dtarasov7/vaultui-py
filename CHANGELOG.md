# Changelog

All notable changes to this project will be documented in this file.

The format follows the spirit of Keep a Changelog, and this project uses semantic versioning.

## [1.2.0] - 2026-11-13

### Added

- LDAP authentication with `--auth-method ldap` and custom auth mount support.
- Hidden password prompts for LDAP and userpass when omitted from CLI/configuration. Supported at TUI startup, in headless mode, and during context switching; entered passwords are not saved to configuration.

### Fixed

- Connection options passed before `get` are no longer overwritten by subcommand defaults.

## [1.1.0] - 2026-11-11

### Added

- Persistent numbered tabs with active highlighting: `0` for overview and `1–8` for Vault sections. Each tab retains its screen, filter and selection; the tab bar wraps on narrow terminals.
- Complete auth backend configuration, including LDAP, mount properties and tuning.
- Section API resource browsing with `b`, custom PKI/Transit/Database/AWS mount selection with `m`, and full KV v2 metadata with `m` in secret details.
- `:read <path> [key=value ...]` and `:list <path>` commands for arbitrary Vault API paths. JSON/YAML views preserve the full response, including warnings, lease metadata and list `key_info`.
- Full property values opened with `Enter`, with wrapping and scrolling; value and JSON copying in detail views.
- Split Policies view: policy list above an automatically updated preview of the selected policy. `PgUp/PgDn` scroll the preview; `Enter` opens full screen.
- Visible row ranges, totals and above/below markers in all tables, text and JSON/YAML viewers, with independent indicators for both Policies panes.
- Russian keyboard layout and Caps Lock support for letter shortcuts, including custom bindings; Unicode input through curses `get_wch`.
- Automated checks for navigation, data preservation, policy panes, scroll indicators and shortcuts; an opt-in comparison of tab data against the Vault CLI on a running server.

### Changed

- Mount, Transit, Identity, Database, AWS, PKI and token details retain every returned field instead of a fixed projection. Empty strings, `false`, `0`, `[]`, `{}` and `null` remain distinct.
- **Shortcut changes:** JSON view moved from `J` to `F2`, copy JSON from `C` to `F4`, and jump to bottom from `G` to `End`. Letters now perform the same action in either case; `y` still opens YAML.
- Command and filter input preserves its original layout and case without shortcut normalization.
- A failed collection no longer hides available neighboring collections. Individual resource errors are visible; `!` opens the current screen's full error text.

### Fixed

- Fields lost during display preparation and long values clipped in JSON/YAML views.
- Digits and letter shortcuts intercepted while entering a table filter.
- Scrolling to the last table row, viewport calculations, and Policies preview synchronization with selection and filtering.
- Refresh with `r`: cache invalidation, reloading in raw mode, and refreshing policy text screens.
- Stale tab state and connection status after context switching.
- Missing Policies divider after scroll indicators were introduced.

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
