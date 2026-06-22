# Журнал изменений

Все значимые изменения проекта будут документироваться в этом файле.

Формат следует духу Keep a Changelog, а проект использует семантическое версионирование.

## [1.0.0] - 2026-06-22

### Добавлено

- Первый публичный релиз VaultUI Python.
- Однофайловая реализация на Python 3.8 с минимальными runtime-зависимостями.
- TUI на curses для просмотра HashiCorp Vault.
- Dashboard со статусом seal, версией Vault, HA-деталями, storage backend, счётчиками ресурсов и быстрой навигацией.
- Браузер secret engines с поддержкой KV, PKI, Transit, Identity, Database, AWS и generic mounts.
- Браузер KV v2 path, просмотр secret, копирование в clipboard, история версий и diff между версиями.
- Экраны policies, auth methods, PKI certificates/roles, Transit keys, Identity entities/groups, Database, AWS и token inspector.
- Переключение контекстов через `~/.vaultui.yaml`.
- Аутентификация через token, userpass и AppRole.
- Command palette и настраиваемые keybindings.
- Clipboard с автоочисткой скопированных secrets.
- Headless-подкоманда `get` с JSON-выводом.
- Скрипт заполнения локального dev Vault: `seed-vault-dev.sh`.
- Архитектурные диаграммы PlantUML в `diagramms/`.
- README-файлы на английском и русском языках.
