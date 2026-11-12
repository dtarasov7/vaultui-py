# VaultUI Python

[![Версия](https://img.shields.io/badge/version-1.1.0-blue.svg)](CHANGELOG-ru.md)

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

Буквенные hotkey работают в английской и русской раскладках независимо от
Caps Lock: `j/J/о/О` — вниз, `k/K/л/Л` — вверх, `r/R/к/К` — обновление,
`q/Q/й/Й` — выход. Ввод в фильтрах и command palette сохраняется буквально.
В русской раскладке `.` открывает фильтр, `,` — help.
Чтобы регистр не менял действие, прежние `J`, `C`, `G` заменены на `F2`
(JSON), `F4` (копирование JSON) и `End` (в конец).

| Клавиша | Действие |
| --- | --- |
| `j` / `Down` | Вниз |
| `k` / `Up` | Вверх |
| `Enter` | Открыть выбранный элемент |
| `Esc` / `Left` | Назад |
| `g` / `Home` | В начало |
| `End` | В конец |
| `Ctrl+D` | На страницу вниз |
| `Ctrl+U` | На страницу вверх |
| `/` | Фильтр строк таблицы |
| `r` | Обновить текущий экран |
| `c` | Скопировать выбранное значение или текст |
| `F4` | Скопировать secret как JSON |
| `F2` / `y` | Переключить raw JSON/YAML |
| `v` | Открыть историю версий KV v2 |
| `d` | Описать engine или diff версий |
| `Tab` | Переключить вкладку, если она есть |
| `:` | Открыть command palette |
| `?` | Показать help |
| `q` | Выйти |

Вкладки постоянно отображаются под заголовком; активная выделена цветом.
Переключение по цифрам сохраняет открытый экран, фильтр и позицию в каждом
разделе. Повторное нажатие номера оставляет текущий экран; `r` обновляет данные
в поддерживающих обновление экранах. На узком терминале панель переносится на
несколько строк. `Esc` возвращает назад внутри раздела, а из его корня — в обзор.
`Tab` по-прежнему переключает внутренние вкладки текущего экрана.

Номера вкладок:

| Клавиша | Экран |
| --- | --- |
| `0` | Обзор (Dashboard) |
| `1` | Secret Engines |
| `2` | Auth Methods |
| `3` | Policies |
| `4` | Identity |
| `5` | PKI |
| `6` | Transit |
| `7` | Database |
| `8` | AWS |

## Полные данные Vault в TUI

Таблицы списков показывают краткую сводку. В деталях сохраняются все поля
ответа Vault, включая неизвестные программе поля новых версий. `Enter` на
свойстве открывает полное значение с переносом строк и прокруткой: JSON,
SQL, PEM, списки и вложенные объекты не теряются из-за ширины терминала.
`c` копирует значение, `F4` — JSON, `F2` / `y` открывают JSON / YAML.
Пустая строка, `false`, `0`, `[]`, `{}` и `null` отображаются раздельно.

У каждой прокручиваемой области есть индикатор, например `[^ 11-20/50 v]`:
видны строки 11–20 из 50, `^` означает наличие строк выше, `v` — ниже,
`-` — соответствующая граница достигнута. В таблицах учитываются строки после
фильтрации, в тексте — строки после переноса по ширине терминала. Обе панели
Policies показывают свои позиции независимо.

| Вкладка | Доступная информация |
| --- | --- |
| `0` Обзор | `Enter` / `d`: полные health, seal-status, HA-status, счётчики и ошибки чтения |
| `1` Secrets | `d`: все свойства mount; KV: значения, `m` — полные KV v2 metadata, `v` — версии и diff |
| `2` Auth | `Enter`: конфигурация backend (например, все поля LDAP), `[mount]` и `[tuning]`; `b`: пользователи, группы, роли и другие ресурсы метода |
| `3` Policies | Сверху список, снизу текст выбранной политики; стрелки меняют выбор, `PgUp/PgDn` прокручивают текст, `Enter` открывает полный экран; `d` / `F2` / `y`: ответ API; `b`: списки ACL, RGP и EGP при их наличии |
| `4` Identity | Полные entities/groups, включая metadata, aliases и membership; `b`: отдельные aliases и OIDC-ресурсы |
| `5` PKI | Полные роли и сертификаты; `b`: issuers, keys, URL/CRL/cluster/auto-tidy config |
| `6` Transit | Все свойства ключей, версии и настройки; `b`: ключи и cache-config |
| `7` Database | Все поля connections, dynamic/static roles: connection_details, SQL, TTL и rotation settings |
| `8` AWS | Полные roles, root/lease config и lease lookup; `Enter` на Config открывает соответствующий ответ API |
| `:token`, `:ctx` | Все поля token lookup; `d` на контексте — все его сохранённые параметры |

`b` открывает каталог API-путей текущего раздела. Запрос выполняется при выборе
пути. Каталог содержит распространённые endpoints; произвольные пути доступны
через command palette без выхода из TUI:

```text
:read auth/ldap/config
:read sys/auth/ldap/tune
:list auth/ldap/groups
:read pki/roles/example
:read secret/metadata/apps/myapp/config
:read secret/data/apps/myapp/config version=2
```

Пути передаются как в `vault read` / `vault list`, без преобразования KV-путей.
В API-списке `Enter` открывает элемент, `l` выполняет LIST дочернего пути,
`d` выполняет READ. `F2` / `y` показывают полный ответ списка, включая `key_info`.
Для `:read` JSON / YAML содержит также envelope: warnings, lease metadata и
другие возвращённые сервером поля.

В PKI/Transit/Database/AWS клавиша `m` открывает выбор mount, в том числе с
нестандартным путём. `Tab` переключает внутренние списки. Ошибка одного списка
не скрывает успешно прочитанные соседние списки; `!` открывает полный текст
ошибки текущего экрана. `r` повторяет чтение с очисткой кеша в таблицах и деталях.

Доступность данных определяется теми же правами токена, namespace и настройками
Vault, что и в CLI. Неподдерживаемые endpoints и ошибки доступа показываются
явно; скрытые самим Vault значения восстановить нельзя. Каталог не запускает
выдачу credentials и операции изменения конфигурации.

API-ориентиры: [LDAP configuration](https://developer.hashicorp.com/vault/api-docs/auth/ldap),
[auth mount tuning](https://developer.hashicorp.com/vault/api-docs/system/auth).

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
python3 -m unittest discover -s tests -v
sh -n seed-vault-dev.sh
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./vaultui-py.py get health
```

Сравнение вкладок с настоящим локальным Vault и установленным Vault CLI:

```bash
VAULTUI_LIVE_TESTS=1 VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root python3 -m unittest discover -s tests -p test_live_information.py -v
```

## Автор

**Tarasov Dmitry**
- Email: dtarasov7@gmail.com

## Атрибуция

Части этого кода были сгенерированы с помощью ассистента
