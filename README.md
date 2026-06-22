# VaultUI Python

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](CHANGELOG.md)

VaultUI Python is a single-file Python 3.8 terminal UI for HashiCorp Vault. It mirrors the main workflows of the original Go `vaultui` project while keeping runtime dependencies minimal: the application uses the Python standard library for CLI parsing, HTTP requests, curses rendering, clipboard integration, and JSON output.

## Features

- Dashboard with seal status, Vault version, HA status, storage backend, resource counts, and quick navigation.
- Secret engine browser for KV, PKI, Transit, Identity, Database, AWS, and other mounts.
- KV v2 browser with directory navigation, secret detail views, clipboard copy, version history, and version diffs.
- Policy, auth method, PKI, Transit, Identity, Database, AWS, and token inspection screens.
- Context switching through `~/.vaultui.yaml`.
- Token, userpass, and AppRole authentication.
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
./vaultui-py.py --auth-method approle --role-id xxx --secret-id yyy
```

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

| Key | Action |
| --- | --- |
| `j` / `Down` | Move down |
| `k` / `Up` | Move up |
| `Enter` | Open selected item |
| `Esc` / `Left` | Go back |
| `g` / `Home` | Jump to top |
| `G` / `End` | Jump to bottom |
| `Ctrl+D` | Page down |
| `Ctrl+U` | Page up |
| `/` | Filter table rows |
| `r` | Refresh current view |
| `c` | Copy selected value or text |
| `C` | Copy secret as JSON |
| `J` / `y` | Toggle raw JSON/YAML view |
| `v` | Open KV v2 version history |
| `d` | Describe engine or diff versions |
| `Tab` | Switch tabs where available |
| `:` | Open command palette |
| `?` | Show help |
| `q` | Quit |

Quick jumps:

| Key | Screen |
| --- | --- |
| `1` | Secret Engines |
| `2` | Auth Methods |
| `3` | Policies |
| `4` | Identity |
| `5` | PKI |
| `6` | Transit |
| `7` | Database |
| `8` | AWS |

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
sh -n seed-vault-dev.sh
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./vaultui-py.py get health
```

## Author

**Tarasov Dmitry**
- Email: dtarasov7@gmail.com

## Attribution

Parts of this code were generated with assistance
