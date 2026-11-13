# VaultUI Python

[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](CHANGELOG.md)

VaultUI Python is a single-file Python 3.8 terminal UI for HashiCorp Vault. It mirrors the main workflows of the original Go `vaultui` project while keeping runtime dependencies minimal: the application uses the Python standard library for CLI parsing, HTTP requests, curses rendering, clipboard integration, and JSON output.

## Features

- Dashboard with seal status, Vault version, HA status, storage backend, resource counts, and quick navigation.
- Secret engine browser for KV, PKI, Transit, Identity, Database, AWS, and other mounts.
- KV v2 browser with directory navigation, secret detail views, clipboard copy, version history, and version diffs.
- Policy, auth method, PKI, Transit, Identity, Database, AWS, and token inspection screens.
- Context switching through `~/.vaultui.yaml`.
- Token, userpass, LDAP, and AppRole authentication, with hidden password prompts for userpass and LDAP when omitted.
- Command palette with `:secrets`, `:auth`, `:policies`, `:identity`, `:pki`, `:transit`, `:db`, `:aws`, `:token`, `:ctx`, and `:go`.
- Configurable keybindings.
- Clipboard auto-clear for copied secrets.
- Headless `get` mode for JSON output in scripts.
- PlantUML architecture diagrams in `diagramms/`.

## Requirements

- Python 3.8 or newer.
- A terminal with curses support.
- HashiCorp Vault reachable over HTTP(S).
- Optional clipboard command for copy support: `xclip`, `xsel`, `wl-copy`, `pbcopy`, or `clip`.
- Optional `PyYAML`; if unavailable, the built-in config parser handles the documented `~/.vaultui.yaml` format.

## Quick Start

Start a local development Vault:

```bash
vault server -dev -dev-root-token-id=root
```

In another terminal, seed it with test data:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./seed-vault-dev.sh
```

Run the TUI:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./vaultui-py.py
```

Run a headless query:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./vaultui-py.py get secret secret/apps/myapp/config
```

## Dev Seed Data

`seed-vault-dev.sh` prepares an empty dev Vault without requiring PostgreSQL or LocalStack. It creates:

- KV v2 application and infrastructure secrets, including multiple versions for diff testing.
- ACL policies: `base-read`, `app-secrets`, `infra-secrets`, and `admin`.
- Auth methods: userpass, AppRole, and an unconfigured LDAP mount.
- Identity entities and groups.
- PKI root, role, and issued certificate.
- Transit keys.
- Database and AWS mounts with fake offline configuration and browsable roles.

The generated userpass credentials are:

```text
username: testuser
password: testpass
```

The script prints a fresh AppRole `role_id` and `secret_id` after each run.

## Configuration

Configuration is resolved in this order:

1. CLI flags.
2. Environment variables: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`.
3. `~/.vaultui.yaml`.
4. `~/.vault-token`.

Example `~/.vaultui.yaml`:

```yaml
current_context: dev

contexts:
  - name: dev
    address: http://127.0.0.1:8200
    token: root

  - name: staging
    address: https://vault.staging.example.com
    auth:
      method: userpass
      username: admin
      password: secret

  - name: prod
    address: https://vault.example.com
    namespace: admin
    auth:
      method: approle
      role_id: "xxx"
      secret_id: "yyy"

  - name: corporate
    address: https://vault.example.com
    auth:
      method: ldap
      mount_path: ldap
      username: alice
      # Password is requested when connecting.

settings:
  clipboard_timeout: 30
  keybindings:
    quit: "q"
    back: "esc,left"
```

## CLI Usage

```bash
./vaultui-py.py --vault-addr https://vault.example.com --token s.xxxxx
./vaultui-py.py --namespace admin
./vaultui-py.py --auth-method userpass --username admin --password secret
./vaultui-py.py --auth-method userpass --username admin
./vaultui-py.py --auth-method ldap --username alice
./vaultui-py.py --auth-method ldap --auth-mount corporate-ldap --username alice
./vaultui-py.py --auth-method approle --role-id xxx --secret-id yyy
```

For `userpass` and `ldap`, omitting both `--password` and the context's
`auth.password` triggers a hidden password prompt. This works at TUI startup,
in headless mode, and when switching contexts with `:ctx`. Entered passwords
are not saved to configuration. Default mounts are `userpass` and `ldap`;
use `--auth-mount` or `auth.mount_path` for custom paths. A username is required.
If no terminal is available for hidden input, supply the password explicitly.

Headless JSON mode:

```bash
./vaultui-py.py get health
./vaultui-py.py get engines
./vaultui-py.py get auth
./vaultui-py.py get policies
./vaultui-py.py get policy default
./vaultui-py.py get secret secret/apps/myapp/config
./vaultui-py.py get token
```

## TUI Navigation

Letter shortcuts work with English and Russian layouts regardless of Caps Lock:
`j/J/о/О` moves down, `k/K/л/Л` moves up, `r/R/к/К` refreshes, and `q/Q/й/Й`
quits. Filter and command palette input stays literal. Russian-layout `.` opens
the filter and `,` opens help. To keep actions independent of letter case, the
former `J`, `C` and `G` actions now use `F2` (JSON), `F4` (copy JSON) and `End`.

| Key | Action |
| --- | --- |
| `j` / `Down` | Move down |
| `k` / `Up` | Move up |
| `Enter` | Open selected item |
| `Esc` / `Left` | Go back |
| `g` / `Home` | Jump to top |
| `End` | Jump to bottom |
| `Ctrl+D` | Page down |
| `Ctrl+U` | Page up |
| `/` | Filter table rows |
| `r` | Refresh current view |
| `c` | Copy selected value or text |
| `F4` | Copy secret as JSON |
| `F2` / `y` | Toggle raw JSON/YAML view |
| `v` | Open KV v2 version history |
| `d` | Describe engine or diff versions |
| `Tab` | Switch tabs where available |
| `:` | Open command palette |
| `?` | Show help |
| `q` | Quit |

Tabs stay visible below the header, with the active tab highlighted. Switching
by number preserves each section's screen, filter, and selection. Pressing the
active number keeps the current screen; `r` refreshes views that support it.
The tab bar wraps on narrow terminals. `Esc` goes back within the section, then
returns to the overview from its root. `Tab` still switches internal view tabs.

Tab numbers:

| Key | Screen |
| --- | --- |
| `0` | Overview (Dashboard) |
| `1` | Secret Engines |
| `2` | Auth Methods |
| `3` | Policies |
| `4` | Identity |
| `5` | PKI |
| `6` | Transit |
| `7` | Database |
| `8` | AWS |

## Complete Vault data in the TUI

List tables are summaries. Detail screens retain every backend response field,
including fields added by newer Vault versions. Press `Enter` on a property to
read its complete value with wrapping and scrolling, including SQL, PEM, JSON,
arrays and nested objects. `c` copies a value, `F4` copies JSON, and `F2` / `y`
show JSON / YAML. Empty strings, `false`, `0`, `[]`, `{}` and `null` stay distinct.

Each scrollable area shows its position, for example `[^ 11-20/50 v]`:
rows 11–20 of 50 are visible, `^` means more content above, `v` means more
below, and `-` marks that boundary as reached. Tables count filtered rows;
text counts lines after wrapping to terminal width. The two Policies panes
have independent indicators.

| Tab | Information available |
| --- | --- |
| `0` Overview | `Enter` / `d`: full health, seal-status, HA-status, resource counts and read errors |
| `1` Secrets | `d`: complete mount properties; KV values, `m` for full KV v2 metadata, `v` for versions and diff |
| `2` Auth | `Enter`: backend configuration (including all LDAP fields), `[mount]` and `[tuning]`; `b`: method users, groups, roles and other resources |
| `3` Policies | List above the selected policy body; arrows select, `PgUp/PgDn` scroll the preview, `Enter` opens full screen; `d` / `F2` / `y`: API response; `b`: ACL, RGP and EGP collections when supported |
| `4` Identity | Complete entities/groups, metadata, aliases and membership; `b`: alias collections and OIDC resources |
| `5` PKI | Complete roles and certificate responses; `b`: issuers, keys, URL/CRL/cluster/auto-tidy configuration |
| `6` Transit | All key properties, versions and settings; `b`: keys and cache configuration |
| `7` Database | All connection and dynamic/static role fields, including connection_details, SQL, TTL and rotation settings |
| `8` AWS | Complete roles, root/lease configuration and lease lookup; `Enter` on Config opens its API response |
| `:token`, `:ctx` | Every token lookup field; `d` on a context shows its complete saved configuration |

Press `b` to browse common API endpoints for the current section. Selecting an
endpoint reads it. Use the command palette for any exact Vault API path:

```text
:read auth/ldap/config
:read sys/auth/ldap/tune
:list auth/ldap/groups
:read pki/roles/example
:read secret/metadata/apps/myapp/config
:read secret/data/apps/myapp/config version=2
```

Paths follow `vault read` / `vault list` semantics without KV path conversion.
In API lists, `Enter` opens an item, `l` lists its children, and `d` reads it.
`F2` / `y` show the complete list response, including `key_info`. For `:read`,
JSON / YAML also retains the response envelope, warnings and lease metadata.

Use `m` in PKI/Transit/Database/AWS to select any mounted instance, including
custom mount paths. `Tab` switches internal collections. A failed collection
does not hide available neighboring collections. Press `!` for the full screen
error. `r` clears the cache and reads tables/details again.

Results depend on the same token permissions, namespace and Vault configuration
as the CLI. Unsupported endpoints and permission errors are visible; values
withheld by Vault cannot be recovered. The endpoint catalogue does not generate
credentials or modify configuration.

API references: [LDAP configuration](https://developer.hashicorp.com/vault/api-docs/auth/ldap),
[auth mount tuning](https://developer.hashicorp.com/vault/api-docs/system/auth).

## Project Files

- `vaultui-py.py` — the complete single-file TUI and CLI implementation.
- `seed-vault-dev.sh` — local dev Vault seed script.
- `diagramms/` — PlantUML architecture diagrams in English and Russian.
- `vaultui/` — original Go implementation used as the functional reference.

## Diagrams

The `diagramms/` directory contains one PlantUML diagram per file:

- `component-architecture.puml`
- `runtime-flow.puml`
- `tui-navigation.puml`
- `vault-api-data-flow.puml`

Russian copies use the `-ru` suffix.

## Verification

Useful local checks:

```bash
python3 -m py_compile vaultui-py.py
python3 -m unittest discover -s tests -v
sh -n seed-vault-dev.sh
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./vaultui-py.py get health
```

Compare tab data with a running local Vault and the installed Vault CLI:

```bash
VAULTUI_LIVE_TESTS=1 VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root python3 -m unittest discover -s tests -p test_live_information.py -v
```

## Author

**Tarasov Dmitry**
- Email: dtarasov7@gmail.com

## Attribution

Parts of this code were generated with assistance
