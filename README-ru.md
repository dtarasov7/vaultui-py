# VaultUI Python

[![Версия](https://img.shields.io/badge/version-1.0.0-blue.svg)](CHANGELOG-ru.md)

VaultUI Python — это однофайловый TUI для HashiCorp Vault на Python 3.8. Он повторяет основные рабочие сценарии оригинального Go-проекта `vaultui`, но использует минимум зависимостей: CLI, HTTP-запросы, curses-интерфейс, буфер обмена и JSON-вывод реализованы средствами стандартной библиотеки Python.

## Возможности

- Dashboard со статусом seal, версией Vault, HA-режимом, storage backend, счётчиками ресурсов и быстрой навигацией.
- Браузер secret engines для KV, PKI, Transit, Identity, Database, AWS и других mount-ов.
- Браузер KV v2 с переходом по каталогам, просмотром secrets, копированием значений, историей версий и diff между версиями.
- Экраны policies, auth methods, PKI, Transit, Identity, Database, AWS и token inspector.
- Переключение контекстов через `~/.vaultui.yaml`.
- Аутентификация через token, userpass и AppRole.
- Command palette с командами `:secrets`, `:auth`, `:policies`, `:identity`, `:pki`, `:transit`, `:db`, `:aws`, `:token`, `:ctx` и `:go`.
- Настраиваемые keybindings.
- Clipboard с автоочисткой скопированных secrets.
- Headless-режим `get` для JSON-вывода в скриптах.
- Архитектурные диаграммы PlantUML в каталоге `diagramms/`.

## Требования

- Python 3.8 или новее.
- Терминал с поддержкой curses.
- Доступный HashiCorp Vault по HTTP(S).
- Необязательная команда для clipboard: `xclip`, `xsel`, `wl-copy`, `pbcopy` или `clip`.
- Необязательный `PyYAML`; если он не установлен, встроенный парсер поддерживает документированный формат `~/.vaultui.yaml`.

## Быстрый старт

Запустите локальный dev Vault:

```bash
vault server -dev -dev-root-token-id=root
```

В другом терминале заполните Vault тестовыми данными:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./seed-vault-dev.sh
```

Запустите TUI:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./vaultui-py.py
```

Выполните headless-запрос:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./vaultui-py.py get secret secret/apps/myapp/config
```

## Тестовые данные для dev Vault

`seed-vault-dev.sh` подготавливает пустой dev Vault без необходимости запускать PostgreSQL или LocalStack. Скрипт создаёт:

- KV v2 application и infrastructure secrets, включая несколько версий для проверки diff.
- ACL policies: `base-read`, `app-secrets`, `infra-secrets` и `admin`.
- Auth methods: userpass, AppRole и не настроенный LDAP mount.
- Identity entities и groups.
- PKI root, role и выпущенный certificate.
- Transit keys.
- Database и AWS mounts с фейковой offline-конфигурацией и просматриваемыми roles.

Сгенерированные userpass-credentials:

```text
username: testuser
password: testpass
```

После каждого запуска скрипт печатает новый AppRole `role_id` и `secret_id`.

## Конфигурация

Параметры применяются в таком порядке:

1. CLI-флаги.
2. Переменные окружения: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`.
3. `~/.vaultui.yaml`.
4. `~/.vault-token`.

Пример `~/.vaultui.yaml`:

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

## Использование CLI

```bash
./vaultui-py.py --vault-addr https://vault.example.com --token s.xxxxx
./vaultui-py.py --namespace admin
./vaultui-py.py --auth-method userpass --username admin --password secret
./vaultui-py.py --auth-method approle --role-id xxx --secret-id yyy
```

Headless JSON-режим:

```bash
./vaultui-py.py get health
./vaultui-py.py get engines
./vaultui-py.py get auth
./vaultui-py.py get policies
./vaultui-py.py get policy default
./vaultui-py.py get secret secret/apps/myapp/config
./vaultui-py.py get token
```

## Навигация в TUI

| Клавиша | Действие |
| --- | --- |
| `j` / `Down` | Вниз |
| `k` / `Up` | Вверх |
| `Enter` | Открыть выбранный элемент |
| `Esc` / `Left` | Назад |
| `g` / `Home` | В начало |
| `G` / `End` | В конец |
| `Ctrl+D` | На страницу вниз |
| `Ctrl+U` | На страницу вверх |
| `/` | Фильтр строк таблицы |
| `r` | Обновить текущий экран |
| `c` | Скопировать выбранное значение или текст |
| `C` | Скопировать secret как JSON |
| `J` / `y` | Переключить raw JSON/YAML |
| `v` | Открыть историю версий KV v2 |
| `d` | Описать engine или diff версий |
| `Tab` | Переключить вкладку, если она есть |
| `:` | Открыть command palette |
| `?` | Показать help |
| `q` | Выйти |

Быстрые переходы:

| Клавиша | Экран |
| --- | --- |
| `1` | Secret Engines |
| `2` | Auth Methods |
| `3` | Policies |
| `4` | Identity |
| `5` | PKI |
| `6` | Transit |
| `7` | Database |
| `8` | AWS |

## Файлы проекта

- `vaultui-py.py` — полная реализация TUI и CLI в одном файле.
- `seed-vault-dev.sh` — скрипт заполнения локального dev Vault.
- `diagramms/` — архитектурные диаграммы PlantUML на английском и русском.
- `vaultui/` — оригинальная Go-реализация, использованная как функциональный ориентир.

## Диаграммы

Каталог `diagramms/` содержит по одной PlantUML-диаграмме на файл:

- `component-architecture.puml`
- `runtime-flow.puml`
- `tui-navigation.puml`
- `vault-api-data-flow.puml`

Русские копии имеют суффикс `-ru`.

## Проверка

Полезные локальные проверки:

```bash
python3 -m py_compile vaultui-py.py
sh -n seed-vault-dev.sh
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./vaultui-py.py get health
```

## Автор

**Tarasov Dmitry**
- Email: dtarasov7@gmail.com

## Атрибуция

Части этого кода были сгенерированы с помощью ассистента
