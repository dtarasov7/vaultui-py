#!/usr/bin/env python3
"""Single-file Python 3.8 VaultUI clone.

Purpose:
    Provide an interactive curses TUI and a headless JSON CLI for HashiCorp
    Vault using only the Python standard library.
Назначение:
    Реализовать интерактивный curses TUI и headless JSON CLI для HashiCorp
    Vault только средствами стандартной библиотеки Python.

Inputs:
    CLI flags, environment variables, ~/.vaultui.yaml, ~/.vault-token, and
    Vault HTTP API responses.
Входные данные:
    CLI-флаги, переменные окружения, ~/.vaultui.yaml, ~/.vault-token и ответы
    Vault HTTP API.

Returns:
    TUI frames in the terminal or JSON on stdout; exits with a non-zero code on
    connection, authentication, or API errors.
Результат:
    Кадры TUI в терминале или JSON в stdout; при ошибках подключения,
    аутентификации или API возвращает ненулевой код выхода.

PyYAML is optional.  When it is unavailable, a small parser handles the
documented ~/.vaultui.yaml shape.
PyYAML необязателен. Если он недоступен, используется небольшой парсер
документированной структуры ~/.vaultui.yaml.
"""

import argparse
import curses
import difflib
import getpass
import json
import os
import shlex
import ssl
import subprocess
import sys
import textwrap
import threading
import time
import traceback
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


APP_NAME = "VaultUI Python"
__VERSION__ = "1.2.0"
__AUTHOR__ = "Dmitry Tarasov"

DEFAULT_CONFIG_NAME = ".vaultui.yaml"
DEFAULT_TOKEN_NAME = ".vault-token"
DEFAULT_VAULT_ADDR = "https://127.0.0.1:8200"
DEFAULT_CLIPBOARD_TIMEOUT = 30
CACHE_TTL = 30.0


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def home_path(name: str) -> str:
    """Return a file path in the user's home directory."""
    return os.path.join(os.path.expanduser("~"), name)


def default_config_path() -> str:
    """Return the default VaultUI config path."""
    return home_path(DEFAULT_CONFIG_NAME)


def read_token_file() -> str:
    """Read ~/.vault-token when it exists, returning an empty string on errors."""
    try:
        with open(home_path(DEFAULT_TOKEN_NAME), "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def vault_join(*parts: str) -> str:
    """Join Vault API path fragments without losing mount semantics."""
    cleaned = [str(p).strip("/") for p in parts if p is not None and str(p).strip("/") != ""]
    return "/".join(cleaned)


def ensure_slash(path: str) -> str:
    """Ensure a Vault mount path ends with a slash."""
    if not path:
        return path
    return path if path.endswith("/") else path + "/"


def safe_int(value: Any, default: int = 0) -> int:
    """Convert a loose JSON value to int."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_bool(value: Any) -> bool:
    """Convert common JSON/YAML boolean representations to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "on", "1")
    return bool(value)


def stringify(value: Any) -> str:
    """Render a value compactly for table cells and clipboard operations."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value)


def value_or_dash(value: Any, dash: str = "-") -> str:
    """Render empty values as a dash."""
    text = stringify(value)
    return text if text else dash


def extract_string_list(data: Dict[str, Any], key: str) -> List[str]:
    """Extract a list of strings from Vault data."""
    raw = data.get(key)
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw if item is not None]
    if isinstance(raw, tuple):
        return [str(item) for item in raw if item is not None]
    if isinstance(raw, str):
        if "," in raw:
            return [part.strip() for part in raw.split(",") if part.strip()]
        return [raw] if raw else []
    return [str(raw)]


def format_duration_seconds(seconds: Any, no_expiry: str = "infinity") -> str:
    """Format seconds as a short human-readable duration."""
    sec = safe_int(seconds, 0)
    if sec <= 0:
        return no_expiry
    days, rem = divmod(sec, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return "%dd %dh" % (days, hours)
    if hours:
        return "%dh %dm" % (hours, minutes)
    if minutes:
        return "%dm %ds" % (minutes, secs)
    return "%ds" % secs


def extract_duration_field(data: Dict[str, Any], key: str) -> str:
    """Read a Vault TTL field that may be numeric seconds or a string."""
    raw = data.get(key)
    if raw is None or raw == "":
        return ""
    if isinstance(raw, (int, float)):
        return "system default" if int(raw) <= 0 else format_duration_seconds(raw)
    return str(raw)


def parse_time(value: Any) -> str:
    """Normalize an RFC3339-like timestamp for display."""
    if not value:
        return ""
    text = str(value)
    return text[:19].replace("T", " ")


def json_default(value: Any) -> str:
    """Fallback JSON serializer for datetime and unknown values."""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def sort_mounts_by_path(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort Vault mounts by path for stable UI output."""
    return sorted(entries, key=lambda item: item.get("path", ""))


def longest_mount_match(full_path: str, engines: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Find the longest secret engine mount matching a full Vault path."""
    matches = [engine for engine in engines if full_path.startswith(engine.get("path", ""))]
    if not matches:
        return None
    return sorted(matches, key=lambda item: len(item.get("path", "")), reverse=True)[0]


# ---------------------------------------------------------------------------
# YAML config support
# ---------------------------------------------------------------------------


def parse_scalar(text: str) -> Any:
    """Parse the small scalar subset used by ~/.vaultui.yaml."""
    text = text.strip()
    if text == "":
        return ""
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        return text[1:-1]
    lower = text.lower()
    if lower in ("true", "false"):
        return lower == "true"
    if lower in ("null", "none", "~"):
        return None
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(part.strip()) for part in inner.split(",")]
    try:
        return int(text)
    except ValueError:
        return text


def split_key_value(line: str) -> Tuple[str, Any]:
    """Split a simple YAML key/value line."""
    if ":" not in line:
        return line.strip(), ""
    key, value = line.split(":", 1)
    return key.strip(), parse_scalar(value.strip())


def parse_config_subset(text: str) -> Dict[str, Any]:
    """Parse the documented VaultUI YAML subset without external packages.

    Args:
        text (str): Raw YAML-like configuration text.
        text (str): Исходный YAML-подобный текст конфигурации.

    Returns:
        Dict[str, Any]: Config dictionary containing contexts and settings.
        Dict[str, Any]: Словарь конфигурации с contexts и settings.

    Raises:
        None: Malformed unsupported lines are ignored by design.
        None: Неподдержанные строки намеренно игнорируются.
    """
    cfg: Dict[str, Any] = {"contexts": [], "settings": {"keybindings": {}}}
    section = ""
    current_ctx: Optional[Dict[str, Any]] = None
    current_auth: Optional[Dict[str, Any]] = None
    in_keybindings = False

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if indent == 0:
            current_ctx = None
            current_auth = None
            in_keybindings = False
            if stripped == "contexts:":
                section = "contexts"
                continue
            if stripped == "settings:":
                section = "settings"
                continue
            key, value = split_key_value(stripped)
            cfg[key] = value
            section = ""
            continue

        # EN: This is a narrow YAML subset parser, not a general YAML engine.
        # RU: Это парсер узкого подмножества YAML, а не полноценный YAML-движок.
        if section == "contexts":
            if indent == 2 and stripped.startswith("- "):
                current_ctx = {}
                current_auth = None
                cfg.setdefault("contexts", []).append(current_ctx)
                rest = stripped[2:].strip()
                if rest:
                    key, value = split_key_value(rest)
                    current_ctx[key] = value
                continue
            if current_ctx is None:
                continue
            if indent == 4:
                key, value = split_key_value(stripped)
                if key == "auth" and value == "":
                    current_auth = {}
                    current_ctx["auth"] = current_auth
                else:
                    current_ctx[key] = value
                continue
            if indent >= 6 and current_auth is not None:
                key, value = split_key_value(stripped)
                current_auth[key] = value
                continue

        if section == "settings":
            settings = cfg.setdefault("settings", {})
            if indent == 2:
                key, value = split_key_value(stripped)
                if key == "keybindings" and value == "":
                    settings.setdefault("keybindings", {})
                    in_keybindings = True
                else:
                    settings[key] = value
                    in_keybindings = False
                continue
            if indent >= 4 and in_keybindings:
                key, value = split_key_value(stripped)
                settings.setdefault("keybindings", {})[key] = value
                continue

    return cfg


def load_config(path: str) -> Dict[str, Any]:
    """Load VaultUI config from YAML, returning an empty config if missing."""
    if not path:
        path = default_config_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        return {"current_context": "", "contexts": [], "settings": {"keybindings": {}}}
    except OSError as exc:
        raise RuntimeError("reading config %s: %s" % (path, exc))

    try:
        import yaml  # type: ignore

        parsed = yaml.safe_load(text) or {}
        if not isinstance(parsed, dict):
            return {"current_context": "", "contexts": [], "settings": {"keybindings": {}}}
        return parsed
    except Exception:
        return parse_config_subset(text)


def yaml_quote(value: Any) -> str:
    """Render a scalar safely for the fallback YAML writer."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if text == "" or any(ch in text for ch in ":#[]{}\"'") or text.strip() != text:
        return json.dumps(text)
    return text


def dump_config_subset(cfg: Dict[str, Any]) -> str:
    """Dump the documented config subset as YAML."""
    lines: List[str] = []
    lines.append("current_context: %s" % yaml_quote(cfg.get("current_context", "")))
    lines.append("")
    lines.append("contexts:")
    for ctx in cfg.get("contexts", []) or []:
        lines.append("  - name: %s" % yaml_quote(ctx.get("name", "")))
        for key in ("address", "token", "namespace"):
            if ctx.get(key) not in (None, ""):
                lines.append("    %s: %s" % (key, yaml_quote(ctx.get(key))))
        auth = ctx.get("auth") or {}
        if auth:
            lines.append("    auth:")
            for key in ("method", "mount_path", "username", "password", "role_id", "secret_id"):
                if auth.get(key) not in (None, ""):
                    lines.append("      %s: %s" % (key, yaml_quote(auth.get(key))))
    settings = cfg.get("settings") or {}
    if settings:
        lines.append("")
        lines.append("settings:")
        if settings.get("clipboard_timeout") not in (None, ""):
            lines.append("  clipboard_timeout: %s" % yaml_quote(settings.get("clipboard_timeout")))
        keybindings = settings.get("keybindings") or {}
        if keybindings:
            lines.append("  keybindings:")
            for key in sorted(keybindings):
                lines.append("    %s: %s" % (key, yaml_quote(keybindings[key])))
    return "\n".join(lines) + "\n"


def save_config(path: str, cfg: Dict[str, Any]) -> None:
    """Save VaultUI config, preferring PyYAML when present."""
    if not path:
        path = default_config_path()
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    try:
        import yaml  # type: ignore

        text = yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False)
    except Exception:
        text = dump_config_subset(cfg)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def get_context(cfg: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    """Find a named config context."""
    for ctx in cfg.get("contexts", []) or []:
        if ctx.get("name") == name:
            return ctx
    return None


def current_context(cfg: Dict[str, Any], explicit: str = "") -> Optional[Dict[str, Any]]:
    """Return the selected config context, if any."""
    name = explicit or cfg.get("current_context", "")
    return get_context(cfg, name) if name else None


@dataclass
class RuntimeConfig:
    """Resolved settings for one Vault connection.

    Args:
        address (str): Vault base URL.
        token (str): Vault token resolved from flags/env/config/token file.
        namespace (str): Optional Vault Enterprise namespace.
        auth_method (str): token, userpass, ldap, or approle.
        clipboard_timeout (int): Secret auto-clear timeout in seconds.
        address (str): Базовый URL Vault.
        token (str): Токен Vault из флагов/env/config/token file.
        namespace (str): Необязательный namespace Vault Enterprise.
        auth_method (str): token, userpass, ldap или approle.
        clipboard_timeout (int): Таймаут автоочистки секретов в секундах.

    Returns:
        RuntimeConfig: Dataclass instance used by client, TUI, and CLI.
        RuntimeConfig: Экземпляр dataclass для клиента, TUI и CLI.
    """

    address: str
    token: str
    namespace: str
    auth_method: str
    auth_mount: str
    username: str
    password: str
    role_id: str
    secret_id: str
    clipboard_timeout: int
    keybindings: Dict[str, str]
    config_path: str
    raw_config: Dict[str, Any]
    current_context_name: str = ""
    insecure: bool = False
    timeout: float = 20.0


def first_non_empty(*values: Any) -> str:
    """Return the first value that is not None or an empty string."""
    for value in values:
        if value is not None and str(value) != "":
            return str(value)
    return ""


def resolve_runtime_config(args: argparse.Namespace) -> RuntimeConfig:
    """Resolve CLI flags, environment variables, config file, and token file.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.
        args (argparse.Namespace): Разобранные аргументы командной строки.

    Returns:
        RuntimeConfig: Final connection and UI settings.
        RuntimeConfig: Итоговые параметры подключения и UI.

    Raises:
        RuntimeError: If the config file exists but cannot be read or parsed.
        RuntimeError: Если существующий config-файл нельзя прочитать или разобрать.
    """
    cfg_path = args.config or default_config_path()
    cfg = load_config(cfg_path)
    ctx = current_context(cfg, getattr(args, "context", "") or "")
    ctx = ctx or {}
    auth = ctx.get("auth") or {}
    settings = cfg.get("settings") or {}

    address = first_non_empty(
        getattr(args, "vault_addr", None),
        os.environ.get("VAULT_ADDR"),
        ctx.get("address"),
        DEFAULT_VAULT_ADDR,
    )
    namespace = first_non_empty(
        getattr(args, "namespace", None),
        os.environ.get("VAULT_NAMESPACE"),
        ctx.get("namespace"),
    )
    token = first_non_empty(
        getattr(args, "token", None),
        os.environ.get("VAULT_TOKEN"),
        ctx.get("token"),
        read_token_file(),
    )
    auth_method = first_non_empty(getattr(args, "auth_method", None), auth.get("method"), "token")
    auth_mount = first_non_empty(getattr(args, "auth_mount", None), auth.get("mount_path"))
    username = first_non_empty(getattr(args, "username", None), auth.get("username"))
    password = first_non_empty(getattr(args, "password", None), auth.get("password"))
    role_id = first_non_empty(getattr(args, "role_id", None), auth.get("role_id"))
    secret_id = first_non_empty(getattr(args, "secret_id", None), auth.get("secret_id"))
    clipboard_timeout = safe_int(settings.get("clipboard_timeout"), DEFAULT_CLIPBOARD_TIMEOUT)

    return RuntimeConfig(
        address=address,
        token=token,
        namespace=namespace,
        auth_method=auth_method,
        auth_mount=auth_mount,
        username=username,
        password=password,
        role_id=role_id,
        secret_id=secret_id,
        clipboard_timeout=clipboard_timeout,
        keybindings=dict(settings.get("keybindings") or {}),
        config_path=cfg_path,
        raw_config=cfg,
        current_context_name=(ctx.get("name") or cfg.get("current_context", "") or ""),
        insecure=bool(getattr(args, "insecure", False)),
        timeout=float(getattr(args, "timeout", 20.0) or 20.0),
    )


# ---------------------------------------------------------------------------
# Vault HTTP client
# ---------------------------------------------------------------------------


class VaultError(Exception):
    """Application-level Vault error with a readable message.

    Args:
        message (str): Human-readable API, auth, or connection failure.
        message (str): Читаемое описание ошибки API, auth или подключения.

    Returns:
        VaultError: Exception raised to CLI/TUI boundaries.
        VaultError: Исключение, передаваемое на границы CLI/TUI.
    """


def prompt_auth_password(method: str, username: str) -> str:
    """Request a password without echo; refuse getpass's visible-input fallback."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("%s password for %s: " % (method, username))
    except (EOFError, getpass.GetPassWarning) as exc:
        raise VaultError("cannot read a hidden %s password; use an interactive terminal or --password" % method) from exc
    if not password:
        raise VaultError("%s password cannot be empty" % method)
    return password


class TTLCache:
    """Tiny TTL cache for read-heavy Vault endpoints.

    Args:
        ttl (float): Number of seconds before a cached value expires.
        ttl (float): Количество секунд до истечения кешированного значения.

    Returns:
        TTLCache: Mutable in-memory cache with prefix invalidation.
        TTLCache: Изменяемый in-memory кеш с инвалидированием по префиксу.
    """

    def __init__(self, ttl: float) -> None:
        self.ttl = ttl
        self.items: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Any:
        """Return a cached value or None when missing/expired."""
        item = self.items.get(key)
        if not item:
            return None
        ts, value = item
        if time.time() - ts > self.ttl:
            self.items.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        """Store a value with the cache timestamp."""
        self.items[key] = (time.time(), value)

    def clear(self) -> None:
        """Remove all cached values."""
        self.items.clear()

    def invalidate_prefix(self, prefix: str) -> None:
        """Remove cached values whose keys start with prefix."""
        for key in list(self.items):
            if key.startswith(prefix):
                self.items.pop(key, None)


class VaultClient:
    """Small HashiCorp Vault API client built on urllib.

    Args:
        address (str): Vault server base URL without /v1.
        token (str): Optional Vault token.
        namespace (str): Optional Vault namespace header.
        insecure (bool): Disable TLS verification for local/dev Vault.
        timeout (float): HTTP timeout in seconds.
        address (str): Базовый URL Vault без /v1.
        token (str): Необязательный Vault token.
        namespace (str): Необязательный заголовок Vault namespace.
        insecure (bool): Отключить TLS-проверку для local/dev Vault.
        timeout (float): HTTP timeout в секундах.

    Returns:
        VaultClient: Authenticated-capable HTTP client with small read cache.
        VaultClient: HTTP-клиент с поддержкой auth и небольшим read-cache.

    Raises:
        VaultError: Raised by request helpers on API and connection failures.
        VaultError: Выбрасывается helper-ами при ошибках API и подключения.
    """

    def __init__(
        self,
        address: str,
        token: str = "",
        namespace: str = "",
        insecure: bool = False,
        timeout: float = 20.0,
    ) -> None:
        self.address = (address or DEFAULT_VAULT_ADDR).rstrip("/")
        self.token = token or ""
        self.namespace = namespace or ""
        self.timeout = timeout
        self.cache = TTLCache(CACHE_TTL)
        context = ssl._create_unverified_context() if insecure else None
        self.ssl_context = context

    def _url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        encoded = quote(path.strip("/"), safe="/")
        url = "%s/v1/%s" % (self.address, encoded)
        if params:
            url += "?" + urlencode(params, doseq=True)
        return url

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Vault-Token"] = self.token
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        return headers

    def request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        allow_status: Optional[Iterable[int]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Send one Vault API request and decode the JSON response.

        Args:
            method (str): HTTP method, usually GET, LIST, or POST.
            path (str): Logical Vault path below /v1.
            data (Optional[Dict[str, Any]]): JSON payload for writes.
            params (Optional[Dict[str, Any]]): Query parameters.
            allow_status (Optional[Iterable[int]]): Non-2xx statuses accepted as data.
            method (str): HTTP-метод, обычно GET, LIST или POST.
            path (str): Логический путь Vault ниже /v1.
            data (Optional[Dict[str, Any]]): JSON-payload для записи.
            params (Optional[Dict[str, Any]]): Query-параметры.
            allow_status (Optional[Iterable[int]]): Non-2xx статусы, принимаемые как данные.

        Returns:
            Optional[Dict[str, Any]]: Decoded JSON object, empty response, or None on 404.
            Optional[Dict[str, Any]]: JSON-объект, пустой ответ или None при 404.

        Raises:
            VaultError: On HTTP, network, or JSON decode errors.
            VaultError: При HTTP, network или JSON decode ошибках.
        """
        # EN: Vault health intentionally uses non-200 statuses for sealed/standby.
        # RU: Vault health намеренно использует non-200 статусы для sealed/standby.
        body = None if data is None else json.dumps(data).encode("utf-8")
        req = Request(self._url(path, params), data=body, headers=self._headers(), method=method)
        allowed = set(allow_status or [])
        try:
            if self.ssl_context is not None:
                response = urlopen(req, timeout=self.timeout, context=self.ssl_context)
            else:
                response = urlopen(req, timeout=self.timeout)
            raw = response.read().decode("utf-8", "replace")
            if not raw:
                return None
            return json.loads(raw)
        except HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            parsed = None
            if raw:
                try:
                    parsed = json.loads(raw)
                except ValueError:
                    parsed = {"errors": [raw]}
            if exc.code in allowed:
                return parsed or {}
            if exc.code == 404:
                return None
            errors = []
            if isinstance(parsed, dict):
                errors = parsed.get("errors") or []
            msg = "; ".join(str(err) for err in errors) if errors else raw
            raise VaultError("Vault HTTP %s on %s %s: %s" % (exc.code, method, path, msg or exc.reason))
        except URLError as exc:
            raise VaultError("Vault connection failed: %s" % exc.reason)
        except ValueError as exc:
            raise VaultError("Invalid JSON response from Vault: %s" % exc)

    def read(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Read a logical Vault path."""
        return self.request("GET", path, params=params)

    def list(self, path: str) -> Optional[Dict[str, Any]]:
        """List keys under a logical Vault path."""
        return self.request("LIST", path)

    def write(self, path: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Write data to a logical Vault path."""
        return self.request("POST", path, data=data)

    def authenticate(
        self,
        method: str,
        mount_path: str = "",
        username: str = "",
        password: str = "",
        role_id: str = "",
        secret_id: str = "",
        password_prompt: Optional[Callable[[str, str], str]] = None,
    ) -> None:
        """Authenticate with token, userpass, LDAP, or AppRole.

        Args:
            method (str): token, userpass, ldap, or approle.
            mount_path (str): Optional auth mount override.
            username (str): Userpass or LDAP username.
            password (str): Password; missing values are requested without echo.
            role_id (str): AppRole role_id.
            secret_id (str): Optional AppRole secret_id.
            password_prompt: Optional TUI-aware password input callback.
            method (str): token, userpass, ldap или approle.
            mount_path (str): Необязательный override auth mount.
            username (str): Username для userpass или LDAP.
            password (str): Пароль; при отсутствии запрашивается без отображения.
            role_id (str): role_id для AppRole.
            secret_id (str): Необязательный secret_id для AppRole.

        Returns:
            None: Sets self.token on successful non-token auth.
            None: Устанавливает self.token при успешной non-token auth.

        Raises:
            VaultError: On missing credentials, unsupported method, or login failure.
            VaultError: При нехватке credentials, неизвестном методе или login failure.
        """
        method = method or "token"
        if method == "token":
            return
        if method in ("userpass", "ldap"):
            if not username:
                raise VaultError("%s auth requires --username" % method)
            if not password:
                password = (password_prompt or prompt_auth_password)(method, username)
            if not password:
                raise VaultError("%s password cannot be empty" % method)
            mount = mount_path or method
            response = self.write(vault_join("auth", mount, "login", username), {"password": password})
        elif method == "approle":
            if not role_id:
                raise VaultError("approle auth requires --role-id")
            mount = mount_path or "approle"
            payload = {"role_id": role_id}
            if secret_id:
                payload["secret_id"] = secret_id
            response = self.write(vault_join("auth", mount, "login"), payload)
        else:
            raise VaultError("unsupported auth method: %s" % method)

        auth = (response or {}).get("auth") or {}
        token = auth.get("client_token")
        if not token:
            raise VaultError("%s login returned no client token" % method)
        self.token = token
        self.cache.clear()

    def health(self) -> Dict[str, Any]:
        """Read /sys/health, accepting Vault's documented non-200 states."""
        cached = self.cache.get("sys/health")
        if cached is not None:
            return cached
        response = self.request("GET", "sys/health", allow_status={200, 429, 472, 473, 501, 503}) or {}
        self.cache.set("sys/health", response)
        return response

    def seal_status(self) -> Dict[str, Any]:
        """Read /sys/seal-status."""
        return self.read("sys/seal-status") or {}

    def ha_status(self) -> Dict[str, Any]:
        """Read /sys/ha-status."""
        return self.read("sys/ha-status") or {}

    def list_secret_engines(self) -> List[Dict[str, Any]]:
        """List mounted secret engines."""
        cached = self.cache.get("sys/mounts")
        if cached is not None:
            return cached
        response = self.read("sys/mounts") or {}
        data = response.get("data") or {}
        entries: List[Dict[str, Any]] = []
        for path, mount in data.items():
            options = mount.get("options") or {}
            version = ""
            if options.get("version"):
                version = "v%s" % options.get("version")
            entries.append(
                {
                    **mount,
                    "path": path,
                    "type": mount.get("type", ""),
                    "description": mount.get("description", ""),
                    "version": version,
                    "running_version": mount.get("running_version", ""),
                    "accessor": mount.get("accessor", ""),
                    "local": bool(mount.get("local", False)),
                    "seal_wrap": bool(mount.get("seal_wrap", False)),
                    "options": options,
                }
            )
        entries = sort_mounts_by_path(entries)
        self.cache.set("sys/mounts", entries)
        return entries

    def list_auth_methods(self) -> List[Dict[str, Any]]:
        """List enabled auth methods."""
        cached = self.cache.get("sys/auth")
        if cached is not None:
            return cached
        response = self.read("sys/auth") or {}
        data = response.get("data") or {}
        entries: List[Dict[str, Any]] = []
        for path, auth in data.items():
            entries.append(
                {
                    **auth,
                    "path": path,
                    "type": auth.get("type", ""),
                    "description": auth.get("description", ""),
                    "accessor": auth.get("accessor", ""),
                    "local": bool(auth.get("local", False)),
                    "seal_wrap": bool(auth.get("seal_wrap", False)),
                }
            )
        entries = sort_mounts_by_path(entries)
        self.cache.set("sys/auth", entries)
        return entries

    def list_policies(self) -> List[str]:
        """List ACL policy names.

        Args:
            None.
            Нет.

        Returns:
            List[str]: Sorted ACL policy names.
            List[str]: Отсортированные имена ACL policies.

        Raises:
            VaultError: If both modern and legacy policy list endpoints fail.
            VaultError: Если modern и legacy endpoints списка policies не сработали.
        """
        # Vault exposes policy collection endpoints through LIST, not GET.
        # Some older installations also support the legacy sys/policy path.
        # Vault отдаёт collection endpoints через LIST, не GET.
        # Старые установки могут поддерживать legacy sys/policy.
        try:
            response = self.list("sys/policies/acl")
            if response is None:
                response = self.list("sys/policy") or {}
        except VaultError as first_error:
            response = self.list("sys/policy")
            if response is None:
                raise first_error
        data = response.get("data") or {}
        names = data.get("policies") or data.get("keys") or []
        return sorted(str(name).rstrip("/") for name in names)

    def get_policy(self, name: str) -> str:
        """Read one ACL policy body."""
        response = self.read(vault_join("sys/policies/acl", name)) or {}
        data = response.get("data") or {}
        return str(data.get("policy") or data.get("rules") or "")

    def read_engine_config(self, path: str) -> Dict[str, Any]:
        """Read detailed mount configuration for a secret engine."""
        cache_key = "sys/mounts/" + path
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        response = self.read(vault_join("sys/mounts", path.rstrip("/"))) or {}
        data = response.get("data") or response
        result = dict(data, path=ensure_slash(path))
        self.cache.set(cache_key, result)
        return result

    def list_secrets(self, mount: str, sub_path: str, kv_v2: bool) -> List[Dict[str, Any]]:
        """List keys below a secret engine path."""
        list_path = vault_join(mount, "metadata", sub_path) if kv_v2 else vault_join(mount, sub_path)
        cache_key = "list:" + list_path
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        response = self.list(list_path) or {}
        data = response.get("data") or {}
        keys = data.get("keys") or []
        entries = [{"name": str(key), "is_dir": str(key).endswith("/")} for key in keys]
        entries.sort(key=lambda item: (not item["is_dir"], item["name"]))
        self.cache.set(cache_key, entries)
        return entries

    def read_secret(self, mount: str, sub_path: str, kv_v2: bool) -> Dict[str, Any]:
        """Read a KV secret, unwrapping KV v2 data."""
        read_path = vault_join(mount, "data", sub_path) if kv_v2 else vault_join(mount, sub_path)
        response = self.read(read_path) or {}
        data = response.get("data")
        if data is None:
            raise VaultError("no secret found at %s" % read_path)
        if kv_v2 and isinstance(data, dict) and isinstance(data.get("data"), dict):
            data = data.get("data")
        return dict(data or {})

    def read_secret_metadata(self, mount: str, sub_path: str) -> List[Dict[str, Any]]:
        """Read KV v2 metadata and version history."""
        response = self.read(vault_join(mount, "metadata", sub_path)) or {}
        data = response.get("data") or {}
        versions = data.get("versions") or {}
        entries: List[Dict[str, Any]] = []
        for version, info in versions.items():
            item = dict(info or {})
            item["version"] = safe_int(version)
            entries.append(item)
        entries.sort(key=lambda item: item.get("version", 0), reverse=True)
        return entries

    def read_secret_version(self, mount: str, sub_path: str, version: int) -> Dict[str, Any]:
        """Read a specific KV v2 secret version."""
        response = self.read(vault_join(mount, "data", sub_path), params={"version": str(version)}) or {}
        data = response.get("data")
        if not data:
            raise VaultError("no secret found at %s version %s" % (sub_path, version))
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            data = data.get("data")
        return dict(data or {})

    def list_pki_certs(self, mount: str) -> List[Dict[str, str]]:
        """List PKI certificate serial numbers."""
        response = self.list(vault_join(mount, "certs")) or {}
        keys = (response.get("data") or {}).get("keys") or []
        return [{"serial": str(key)} for key in sorted(keys)]

    def list_pki_roles(self, mount: str) -> List[Dict[str, str]]:
        """List PKI role names."""
        response = self.list(vault_join(mount, "roles")) or {}
        keys = (response.get("data") or {}).get("keys") or []
        return [{"name": str(key)} for key in sorted(keys)]

    def read_pki_cert(self, mount: str, serial: str) -> Dict[str, Any]:
        """Read one PKI certificate."""
        response = self.read(vault_join(mount, "cert", serial)) or {}
        data = response.get("data")
        if not data:
            raise VaultError("no certificate found: %s" % serial)
        return dict(data)

    def read_logical_data(self, path: str) -> Dict[str, Any]:
        """Read a logical path and return its data object."""
        response = self.read(path) or {}
        data = response.get("data")
        if data is None:
            raise VaultError("no data found at %s" % path)
        return dict(data)

    def list_transit_keys(self, mount: str) -> List[Dict[str, str]]:
        """List transit key names."""
        response = self.list(vault_join(mount, "keys")) or {}
        keys = (response.get("data") or {}).get("keys") or []
        return [{"name": str(key)} for key in sorted(keys)]

    def read_transit_key(self, mount: str, name: str) -> Dict[str, Any]:
        """Read transit key properties."""
        return self.read_logical_data(vault_join(mount, "keys", name))

    def list_identity_entities(self) -> List[Dict[str, Any]]:
        """List identity entities and read summaries."""
        response = self.list("identity/entity/id") or {}
        keys = (response.get("data") or {}).get("keys") or []
        entities: List[Dict[str, Any]] = []
        for entity_id in keys:
            try:
                entities.append(self.read_identity_entity(str(entity_id)))
            except VaultError as exc:
                entities.append({"id": str(entity_id), "name": str(entity_id), "error": str(exc)})
        entities.sort(key=lambda item: item.get("name", ""))
        return entities

    def list_identity_groups(self) -> List[Dict[str, Any]]:
        """List identity groups and read summaries."""
        response = self.list("identity/group/id") or {}
        keys = (response.get("data") or {}).get("keys") or []
        groups: List[Dict[str, Any]] = []
        for group_id in keys:
            try:
                groups.append(self.read_identity_group(str(group_id)))
            except VaultError as exc:
                groups.append({"id": str(group_id), "name": str(group_id), "error": str(exc)})
        groups.sort(key=lambda item: item.get("name", ""))
        return groups

    def read_identity_entity(self, entity_id: str) -> Dict[str, Any]:
        """Read identity entity details."""
        data = self.read_logical_data(vault_join("identity/entity/id", entity_id))
        return {
            "id": entity_id,
            "name": data.get("name", ""),
            "policies": extract_string_list(data, "policies"),
            "raw": data,
        }

    def read_identity_group(self, group_id: str) -> Dict[str, Any]:
        """Read identity group details."""
        data = self.read_logical_data(vault_join("identity/group/id", group_id))
        return {
            "id": group_id,
            "name": data.get("name", ""),
            "type": data.get("type", ""),
            "policies": extract_string_list(data, "policies"),
            "member_entity_ids": extract_string_list(data, "member_entity_ids"),
            "raw": data,
        }

    def list_db_connections(self, mount: str) -> List[Dict[str, Any]]:
        """List database connection configs."""
        response = self.list(vault_join(mount, "config")) or {}
        keys = (response.get("data") or {}).get("keys") or []
        conns: List[Dict[str, Any]] = []
        for name in keys:
            conn = {"name": str(name), "plugin_name": "", "allowed_roles": []}
            try:
                detail = self.read_db_connection(mount, str(name))
                conn["plugin_name"] = detail.get("plugin_name", "")
                conn["allowed_roles"] = detail.get("allowed_roles", [])
            except VaultError as exc:
                conn["error"] = str(exc)
            conns.append(conn)
        conns.sort(key=lambda item: item.get("name", ""))
        return conns

    def read_db_connection(self, mount: str, name: str) -> Dict[str, Any]:
        """Read database connection details."""
        return self.read_logical_data(vault_join(mount, "config", name))

    def list_db_roles(self, mount: str) -> List[Dict[str, Any]]:
        """List dynamic database roles."""
        response = self.list(vault_join(mount, "roles")) or {}
        keys = (response.get("data") or {}).get("keys") or []
        roles: List[Dict[str, Any]] = []
        for name in keys:
            role = {"name": str(name), "db_name": "", "default_ttl": "", "max_ttl": ""}
            try:
                detail = self.read_db_role(mount, str(name))
                role.update(
                    {
                        "db_name": detail.get("db_name", ""),
                        "default_ttl": extract_duration_field(detail, "default_ttl"),
                        "max_ttl": extract_duration_field(detail, "max_ttl"),
                    }
                )
            except VaultError as exc:
                role["error"] = str(exc)
            roles.append(role)
        roles.sort(key=lambda item: item.get("name", ""))
        return roles

    def read_db_role(self, mount: str, name: str) -> Dict[str, Any]:
        """Read dynamic database role details."""
        return self.read_logical_data(vault_join(mount, "roles", name))

    def list_db_static_roles(self, mount: str) -> List[Dict[str, Any]]:
        """List static database roles."""
        response = self.list(vault_join(mount, "static-roles")) or {}
        keys = (response.get("data") or {}).get("keys") or []
        roles: List[Dict[str, Any]] = []
        for name in keys:
            role = {"name": str(name), "db_name": "", "username": "", "rotation_period": ""}
            try:
                detail = self.read_db_static_role(mount, str(name))
                role.update(
                    {
                        "db_name": detail.get("db_name", ""),
                        "username": detail.get("username", ""),
                        "rotation_period": extract_duration_field(detail, "rotation_period"),
                    }
                )
            except VaultError as exc:
                role["error"] = str(exc)
            roles.append(role)
        roles.sort(key=lambda item: item.get("name", ""))
        return roles

    def read_db_static_role(self, mount: str, name: str) -> Dict[str, Any]:
        """Read static database role details."""
        return self.read_logical_data(vault_join(mount, "static-roles", name))

    def list_aws_roles(self, mount: str) -> List[Dict[str, Any]]:
        """List AWS roles."""
        response = self.list(vault_join(mount, "roles")) or {}
        keys = (response.get("data") or {}).get("keys") or []
        roles: List[Dict[str, Any]] = []
        for name in keys:
            role = {"name": str(name), "credential_type": "", "policy_arns": []}
            try:
                detail = self.read_aws_role(mount, str(name))
                role["credential_type"] = ", ".join(extract_string_list(detail, "credential_type"))
                role["policy_arns"] = extract_string_list(detail, "policy_arns")
            except VaultError as exc:
                role["error"] = str(exc)
            roles.append(role)
        roles.sort(key=lambda item: item.get("name", ""))
        return roles

    def read_aws_role(self, mount: str, name: str) -> Dict[str, Any]:
        """Read AWS role details."""
        return self.read_logical_data(vault_join(mount, "roles", name))

    def read_aws_config(self, mount: str) -> Dict[str, Any]:
        """Read AWS root and lease config."""
        return self.read_sections({name: vault_join(mount, "config", name) for name in ("root", "lease")})

    def read_sections(self, paths: Dict[str, str]) -> Dict[str, Any]:
        """Read independent configuration sections, retaining endpoint errors."""
        result: Dict[str, Any] = {}
        for name, path in paths.items():
            try:
                result[name] = self.read_logical_data(path)
            except VaultError as exc:
                result[name] = {"error": str(exc), "path": path}
        return result

    def read_auth_config(self, mount: str) -> Dict[str, Any]:
        """Read the auth backend configuration and mount tuning independently."""
        sections = self.read_sections({
            "configuration": vault_join("auth", mount, "config"),
            "tuning": vault_join("sys/auth", mount, "tune"),
        })
        try:
            methods = self.list_auth_methods()
            sections["mount"] = next((item for item in methods if item["path"] == ensure_slash(mount)), {})
        except VaultError as exc:
            sections["mount"] = {"error": str(exc)}
        return sections

    def list_aws_leases(self, mount: str) -> List[Dict[str, Any]]:
        """List active leases under an AWS secrets engine."""
        prefix = "aws/creds" if mount == "aws/" else vault_join(mount, "creds")
        response = self.list(vault_join("sys/leases/lookup", prefix)) or {}
        keys = (response.get("data") or {}).get("keys") or []
        leases: List[Dict[str, Any]] = []
        for role_name in keys:
            role = str(role_name).rstrip("/")
            try:
                leases.extend(self._list_aws_role_leases(vault_join(prefix, role)))
            except VaultError as exc:
                leases.append({"role": role, "lease_id": vault_join(prefix, role), "error": str(exc)})
        leases.sort(key=lambda item: item.get("lease_id", ""))
        return leases

    def _list_aws_role_leases(self, prefix: str) -> List[Dict[str, Any]]:
        response = self.list(vault_join("sys/leases/lookup", prefix)) or {}
        keys = (response.get("data") or {}).get("keys") or []
        leases: List[Dict[str, Any]] = []
        for lease_id in keys:
            full_id = vault_join(prefix, str(lease_id).rstrip("/"))
            info = self.write("sys/leases/lookup", {"lease_id": full_id}) or {}
            data = info.get("data") or {}
            role, short = split_lease_id(full_id)
            leases.append(
                {
                    **data,
                    "lease_id": full_id,
                    "role": role,
                    "short_id": short,
                    "ttl": safe_int(data.get("ttl")),
                    "issue_time": data.get("issue_time", ""),
                    "expire_time": data.get("expire_time", ""),
                    "renewable": bool(data.get("renewable", False)),
                }
            )
        return leases

    def inspect_token(self) -> Dict[str, Any]:
        """Lookup the current token."""
        response = self.read("auth/token/lookup-self") or {}
        data = response.get("data")
        if data is None:
            raise VaultError("token lookup returned no data")
        return dict(data)

    def renew_self_token(self) -> int:
        """Renew the current token and return the new TTL in seconds."""
        response = self.write("auth/token/renew-self", {}) or {}
        auth = response.get("auth") or {}
        return safe_int(auth.get("lease_duration"))


class TokenRenewer:
    """Background token renewer matching the Go implementation's behavior.

    Args:
        client (VaultClient): Client whose current token should be renewed.
        client (VaultClient): Клиент, текущий token которого нужно продлевать.

    Returns:
        TokenRenewer: Daemon-thread controller stopped by the TUI on exit.
        TokenRenewer: Контроллер daemon-thread, останавливаемый TUI при выходе.

    Raises:
        None: Renewal failures stop the background loop silently.
        None: Ошибки renewal тихо останавливают фоновый цикл.
    """

    def __init__(self, client: VaultClient) -> None:
        self.client = client
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start renewal in a daemon thread."""
        self.thread = threading.Thread(target=self._loop, name="vault-token-renewer", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        """Stop background renewal."""
        self.stop_event.set()

    def _loop(self) -> None:
        try:
            data = self.client.inspect_token()
            ttl = safe_int(data.get("ttl"))
            renewable = bool(data.get("renewable", False))
        except VaultError:
            return
        if not renewable or ttl <= 0:
            return
        interval = max(10, int(ttl * 2 / 3))
        while not self.stop_event.wait(interval):
            try:
                ttl = self.client.renew_self_token()
            except VaultError:
                return
            interval = max(10, int(ttl * 2 / 3)) if ttl > 0 else interval


# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------


class Clipboard:
    """Cross-platform clipboard helper with delayed clearing.

    Args:
        None.
        Нет.

    Returns:
        Clipboard: Helper that writes through available OS clipboard tools.
        Clipboard: Helper, пишущий через доступные системные clipboard tools.

    Raises:
        RuntimeError: If no clipboard command is available or writing fails.
        RuntimeError: Если нет clipboard command или запись не удалась.
    """

    def __init__(self) -> None:
        self.clear_timer: Optional[threading.Timer] = None

    def write(self, text: str, clear_after: int = 0) -> None:
        """Write text to the OS clipboard and optionally clear it later.

        Args:
            text (str): Clipboard content.
            clear_after (int): Seconds before overwriting the clipboard with an empty string.
            text (str): Содержимое буфера обмена.
            clear_after (int): Секунды до перезаписи буфера пустой строкой.

        Returns:
            None.
            Нет.

        Raises:
            RuntimeError: If no supported clipboard command exists or command fails.
            RuntimeError: Если нет поддерживаемой clipboard command или команда завершилась ошибкой.
        """
        self._write_now(text)
        if clear_after > 0:
            if self.clear_timer:
                self.clear_timer.cancel()
            self.clear_timer = threading.Timer(clear_after, lambda: self._write_now(""))
            self.clear_timer.daemon = True
            self.clear_timer.start()

    def _write_now(self, text: str) -> None:
        cmd = self._command()
        if not cmd:
            raise RuntimeError("no clipboard tool found (install xclip, xsel, wl-copy, pbcopy, or clip)")
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, err = proc.communicate(text.encode("utf-8"))
        if proc.returncode != 0:
            raise RuntimeError(err.decode("utf-8", "replace").strip() or "clipboard command failed")

    def _command(self) -> Optional[List[str]]:
        if sys.platform == "darwin":
            return ["pbcopy"]
        if sys.platform.startswith("win"):
            return ["clip"]
        for cmd in (["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"], ["wl-copy"]):
            if shutil_which(cmd[0]):
                return cmd
        return None


def shutil_which(name: str) -> Optional[str]:
    """Small shutil.which equivalent kept explicit for readability."""
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        full = os.path.join(directory, name)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return None


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def simple_yaml_dump(value: Any, indent: int = 0) -> str:
    """Render data as simple YAML for raw views without PyYAML.

    Args:
        value (Any): JSON-like value to render.
        indent (int): Current indentation level.
        value (Any): JSON-подобное значение для вывода.
        indent (int): Текущий уровень отступа.

    Returns:
        str: YAML-like text good enough for UI/raw copy output.
        str: YAML-подобный текст для UI/raw copy output.

    Raises:
        None.
        Нет.
    """
    prefix = " " * indent
    if isinstance(value, dict):
        lines: List[str] = []
        for key in sorted(value.keys(), key=str):
            item = value[key]
            if isinstance(item, (dict, list)):
                lines.append("%s%s:" % (prefix, key))
                lines.append(simple_yaml_dump(item, indent + 2))
            else:
                lines.append("%s%s: %s" % (prefix, key, yaml_quote(item)))
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append("%s-" % prefix)
                lines.append(simple_yaml_dump(item, indent + 2))
            else:
                lines.append("%s- %s" % (prefix, yaml_quote(item)))
        return "\n".join(lines)
    return "%s%s" % (prefix, yaml_quote(value))


def render_raw(data: Any, fmt: str) -> str:
    """Render raw data as JSON or YAML."""
    if fmt == "yaml":
        try:
            import yaml  # type: ignore

            return yaml.safe_dump(data, sort_keys=False, default_flow_style=False).rstrip()
        except Exception:
            return simple_yaml_dump(data).rstrip()
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False, default=json_default)


def split_lease_id(lease_id: str) -> Tuple[str, str]:
    """Split a Vault AWS lease ID into role and short ID."""
    parts = lease_id.split("/")
    if len(parts) >= 3:
        return parts[-2], parts[-1]
    return "-", lease_id


def fit(text: Any, width: int) -> str:
    """Fit text into a fixed terminal width."""
    text = stringify(text).replace("\n", "\\n").replace("\t", "    ")
    if width <= 0:
        return ""
    if len(text) <= width:
        return text.ljust(width)
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def wrap_lines(text: str, width: int) -> List[str]:
    """Wrap text preserving blank lines."""
    if width <= 1:
        return [""]
    lines: List[str] = []
    for line in str(text).splitlines() or [""]:
        if not line:
            lines.append("")
        else:
            lines.extend(textwrap.wrap(line, width=width, replace_whitespace=False, drop_whitespace=False) or [""])
    return lines


class Theme:
    """Curses color pair registry.

    Args:
        None.
        Нет.

    Returns:
        Theme: Terminal color-pair registry with monochrome fallback.
        Theme: Реестр terminal color-pair с fallback для monochrome.
    """

    HEADER = 1
    TITLE = 2
    DIM = 3
    OK = 4
    ERROR = 5
    ACCENT = 6
    SELECTED = 7
    STATUS = 8

    def __init__(self) -> None:
        self.has_color = False

    def setup(self) -> None:
        """Initialize color pairs when the terminal supports them."""
        self.has_color = curses.has_colors()
        if not self.has_color:
            return
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(self.HEADER, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(self.TITLE, curses.COLOR_CYAN, -1)
        curses.init_pair(self.DIM, curses.COLOR_WHITE, -1)
        curses.init_pair(self.OK, curses.COLOR_GREEN, -1)
        curses.init_pair(self.ERROR, curses.COLOR_RED, -1)
        curses.init_pair(self.ACCENT, curses.COLOR_YELLOW, -1)
        curses.init_pair(self.SELECTED, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(self.STATUS, curses.COLOR_BLACK, curses.COLOR_WHITE)

    def pair(self, pair_id: int, extra: int = 0) -> int:
        """Return curses attributes for a color pair."""
        if not self.has_color:
            if pair_id in (self.HEADER, self.SELECTED, self.STATUS):
                return curses.A_REVERSE | extra
            if pair_id == self.TITLE:
                return curses.A_BOLD | extra
            return extra
        return curses.color_pair(pair_id) | extra


def addstr_safe(win: Any, y: int, x: int, text: Any, width: int, attr: int = 0) -> None:
    """Write a clipped string to curses, ignoring edge errors."""
    if y < 0 or x < 0 or width <= 0:
        return
    try:
        win.addstr(y, x, stringify(text)[:width], attr)
    except curses.error:
        pass


def clear_area(win: Any, y: int, x: int, height: int, width: int) -> None:
    """Clear a rectangular-ish area with spaces."""
    for row in range(max(0, height)):
        addstr_safe(win, y + row, x, " " * max(0, width), width)


def scroll_indicator(offset: int, visible: int, total: int) -> str:
    """Describe the visible range and whether more content exists above/below."""
    total = max(0, total)
    offset = min(max(0, offset), total)
    end = min(total, offset + max(0, visible))
    first = offset + 1 if end > offset else 0
    above = "^" if offset > 0 else "-"
    below = "v" if end < total else "-"
    return "[%s %d-%d/%d %s]" % (above, first, end if first else 0, total, below)


def draw_scroll_indicator(win: Any, y: int, x: int, width: int, offset: int,
                          visible: int, total: int, theme: Theme) -> None:
    """Place the indicator at the right edge of a header or separator."""
    text = scroll_indicator(offset, visible, total)
    addstr_safe(win, y, x + max(0, width - len(text)), text, width,
                theme.pair(Theme.TITLE, curses.A_BOLD))


# ---------------------------------------------------------------------------
# Keybindings
# ---------------------------------------------------------------------------


DEFAULT_KEYS: Dict[str, str] = {
    "up": "k,up",
    "down": "j,down",
    "top": "g,home",
    "bottom": "end",
    "page_down": "ctrl+d",
    "page_up": "ctrl+u",
    "enter": "enter",
    "back": "esc,left",
    "quit": "q",
    "command": ":",
    "copy": "c",
    "copy_json": "f4",
}


class KeyMap:
    """Maps curses key codes to semantic actions.

    Args:
        overrides (Dict[str, str]): Optional config keybinding overrides.
        overrides (Dict[str, str]): Необязательные keybinding overrides из config.

    Returns:
        KeyMap: Translator from curses integer codes to action tokens.
        KeyMap: Переводчик curses integer codes в action tokens.
    """

    def __init__(self, overrides: Dict[str, str]) -> None:
        merged = dict(DEFAULT_KEYS)
        for key, value in (overrides or {}).items():
            if value:
                merged[key] = str(value)
        self.bindings = {action: self._split(value) for action, value in merged.items()}

    def _split(self, value: str) -> set:
        return {self.shortcut(part.strip()) for part in value.split(",") if part.strip()}

    @staticmethod
    def shortcut(token: str) -> str:
        """Normalize shortcut case and Russian ЙЦУКЕН physical key positions."""
        layout = str.maketrans("йцукенгшщзхъфывапролджэячсмитьбюё", "qwertyuiop[]asdfghjkl;'zxcvbnm,.`")
        token = token.lower().translate(layout)
        return {".": "/", ",": "?"}.get(token, token)

    def token(self, code: Union[int, str]) -> str:
        """Convert a Unicode character or curses special key into a token."""
        if isinstance(code, str):
            if len(code) != 1:
                return code
            if ord(code) >= 32 and ord(code) != 127:
                return code
            code = ord(code)
        if code in (10, 13, curses.KEY_ENTER):
            return "enter"
        if code in (27,):
            return "esc"
        if code in (9,):
            return "tab"
        if code in (curses.KEY_BTAB,):
            return "shift+tab"
        if code in (curses.KEY_BACKSPACE, 127, 8):
            return "backspace"
        if code == 4:
            return "ctrl+d"
        if code == 21:
            return "ctrl+u"
        if code == 3:
            return "ctrl+c"
        if code == curses.KEY_UP:
            return "up"
        if code == curses.KEY_DOWN:
            return "down"
        if code == curses.KEY_LEFT:
            return "left"
        if code == curses.KEY_RIGHT:
            return "right"
        if code == curses.KEY_HOME:
            return "home"
        if code == curses.KEY_END:
            return "end"
        if code == curses.KEY_NPAGE:
            return "pagedown"
        if code == curses.KEY_PPAGE:
            return "pageup"
        if code == curses.KEY_F2:
            return "f2"
        if code == curses.KEY_F4:
            return "f4"
        if 0 <= code < 256:
            try:
                return chr(code)
            except ValueError:
                return ""
        return str(code)

    def matches(self, action: str, token: str) -> bool:
        """Return true when a token matches an action."""
        return self.shortcut(token) in self.bindings.get(action, set())


# ---------------------------------------------------------------------------
# Table component
# ---------------------------------------------------------------------------


@dataclass
class Column:
    """Terminal table column.

    Args:
        title (str): Header label.
        min_width (int): Minimum column width in characters.
        flex (bool): Whether the column absorbs remaining width.
        title (str): Заголовок колонки.
        min_width (int): Минимальная ширина в символах.
        flex (bool): Должна ли колонка занимать остаток ширины.
    """

    title: str
    min_width: int
    flex: bool = False


class Table:
    """Vim-navigable table with filtering and scrolling.

    Args:
        columns (Sequence[Column]): Column definitions.
        columns (Sequence[Column]): Описания колонок.

    Returns:
        Table: Stateful table component with cursor, offset, and filter query.
        Table: Stateful table-компонент с cursor, offset и filter query.
    """

    def __init__(self, columns: Sequence[Column]) -> None:
        self.columns = list(columns)
        self.all_rows: List[List[str]] = []
        self.all_items: List[Any] = []
        self.rows: List[List[str]] = []
        self.items: List[Any] = []
        self.cursor = 0
        self.offset = 0
        self.query = ""

    def set_rows(self, rows: Sequence[Sequence[Any]], items: Optional[Sequence[Any]] = None) -> None:
        """Replace table rows and optional backing items."""
        self.all_rows = [[stringify(cell) for cell in row] for row in rows]
        self.all_items = list(items) if items is not None else list(range(len(rows)))
        self.apply_filter(self.query)

    def apply_filter(self, query: str) -> None:
        """Apply a case-insensitive row filter."""
        self.query = query
        if not query:
            self.rows = list(self.all_rows)
            self.items = list(self.all_items)
        else:
            lower = query.lower()
            rows: List[List[str]] = []
            items: List[Any] = []
            for row, item in zip(self.all_rows, self.all_items):
                if lower in " ".join(row).lower():
                    rows.append(row)
                    items.append(item)
            self.rows = rows
            self.items = items
        self.cursor = min(self.cursor, max(0, len(self.rows) - 1))
        self.offset = min(self.offset, max(0, len(self.rows) - 1))

    def selected(self) -> Any:
        """Return the selected backing item."""
        if not self.items or self.cursor >= len(self.items):
            return None
        return self.items[self.cursor]

    def move(self, delta: int, height: int) -> None:
        """Move the cursor by delta rows."""
        if not self.rows:
            return
        self.cursor = max(0, min(len(self.rows) - 1, self.cursor + delta))
        self._ensure_visible(height)

    def top(self) -> None:
        """Move to the first row."""
        self.cursor = 0
        self.offset = 0

    def bottom(self, height: int) -> None:
        """Move to the last row."""
        self.cursor = max(0, len(self.rows) - 1)
        self._ensure_visible(height)

    def page(self, direction: int, height: int) -> None:
        """Move by one visible page."""
        page = max(1, height - 2)
        self.move(direction * page, height)

    def _ensure_visible(self, height: int) -> None:
        visible = max(1, height - 2)
        if self.cursor < self.offset:
            self.offset = self.cursor
        if self.cursor >= self.offset + visible:
            self.offset = self.cursor - visible + 1

    def _widths(self, total_width: int) -> List[int]:
        # EN: Flex columns get spare space first, then all columns shrink to fit.
        # RU: Flex-колонки сначала получают свободное место, затем всё ужимается.
        available = max(1, total_width - max(0, len(self.columns) - 1))
        widths = [col.min_width for col in self.columns]
        flex_indexes = [i for i, col in enumerate(self.columns) if col.flex]
        min_total = sum(widths)
        if flex_indexes and available > min_total:
            extra = available - min_total
            per = extra // len(flex_indexes)
            for idx in flex_indexes:
                widths[idx] += per
            widths[flex_indexes[-1]] += extra - per * len(flex_indexes)
        while sum(widths) > available and max(widths) > 4:
            idx = max(range(len(widths)), key=lambda i: widths[i])
            widths[idx] -= 1
        return widths

    def render(self, win: Any, y: int, x: int, height: int, width: int, theme: Theme) -> None:
        """Render the table into a curses window."""
        clear_area(win, y, x, height, width)
        if height <= 0:
            return
        widths = self._widths(width)
        xpos = x
        for col, col_width in zip(self.columns, widths):
            addstr_safe(win, y, xpos, fit(col.title.upper(), col_width), col_width, theme.pair(Theme.DIM, curses.A_BOLD))
            xpos += col_width + 1
        if height > 1:
            addstr_safe(win, y + 1, x, "-" * min(width, sum(widths) + len(widths) - 1), width, theme.pair(Theme.DIM))
        visible = max(0, height - 2)
        end = min(len(self.rows), self.offset + visible)
        for screen_row, idx in enumerate(range(self.offset, end)):
            row_y = y + 2 + screen_row
            attr = theme.pair(Theme.SELECTED) if idx == self.cursor else 0
            xpos = x
            row = self.rows[idx]
            for cell_idx, col_width in enumerate(widths):
                cell = row[cell_idx] if cell_idx < len(row) else ""
                addstr_safe(win, row_y, xpos, fit(cell, col_width), col_width, attr)
                xpos += col_width + 1
        if not self.rows and height > 3:
            msg = "No rows"
            if self.query:
                msg = "No rows match /%s" % self.query
            addstr_safe(win, y + 3, x, msg, width, theme.pair(Theme.DIM))
        if height > 1:
            draw_scroll_indicator(win, y + 1, x, width, self.offset, visible, len(self.rows), theme)


# ---------------------------------------------------------------------------
# View base classes
# ---------------------------------------------------------------------------


class View:
    """Base class for TUI screens.

    Args:
        title (str): Human-readable screen title.
        title (str): Читаемый заголовок экрана.

    Returns:
        View: Stateful screen object used by the router stack.
        View: Stateful объект экрана, используемый стеком маршрутизации.
    """

    def __init__(self, title: str) -> None:
        self.title = title
        self.error = ""

    def load(self, app: "VaultTUI") -> None:
        """Load or refresh data for this view."""

    def handle_key(self, app: "VaultTUI", token: str) -> bool:
        """Handle one key token, returning true when consumed."""
        return False

    def render(self, app: "VaultTUI", win: Any, y: int, height: int, width: int) -> None:
        """Render this view."""
        clear_area(win, y, 0, height, width)
        addstr_safe(win, y, 0, self.title, width, app.theme.pair(Theme.TITLE, curses.A_BOLD))

    def hints(self) -> List[Tuple[str, str]]:
        """Return status bar key hints."""
        return [("esc", "back")]


class TableView(View):
    """Base class for screens backed by a Table.

    Args:
        title (str): Screen title shown above the table.
        title (str): Заголовок экрана над таблицей.

    Returns:
        TableView: View with shared navigation, filtering, refresh, and enter handling.
        TableView: View с общей навигацией, фильтрацией, refresh и enter handling.
    """

    columns: Sequence[Column] = ()

    def __init__(self, title: str) -> None:
        super().__init__(title)
        self.table = Table(self.columns)
        self.filter_active = False
        self.filter_input = ""
        self.section_errors: Dict[str, str] = {}

    def read_collection(self, name: str, loader: Callable[[], List[Any]]) -> List[Any]:
        """Keep available collections when another collection cannot be read."""
        try:
            return loader()
        except VaultError as exc:
            self.section_errors[name] = str(exc)
            return []

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        """Return table rows and backing items."""
        return [], []

    def load(self, app: "VaultTUI") -> None:
        """Fetch table rows.

        Args:
            app (VaultTUI): Running application with client and UI state.
            app (VaultTUI): Запущенное приложение с client и UI state.

        Returns:
            None: Updates table rows or stores an error message.
            None: Обновляет строки таблицы или сохраняет текст ошибки.

        Raises:
            None: Exceptions are captured for on-screen display.
            None: Исключения перехватываются для отображения на экране.
        """
        try:
            self.section_errors = {}
            rows, items = self.rows_and_items(app)
            self.table.set_rows(rows, items)
            for item in items:
                if isinstance(item, dict) and item.get("error"):
                    name = str(item.get("name") or item.get("id") or item.get("lease_id") or "item")
                    self.section_errors[name] = str(item["error"])
            self.error = "; ".join("%s: %s" % pair for pair in self.section_errors.items())
        except Exception as exc:
            self.error = str(exc)

    def open_selected(self, app: "VaultTUI", item: Any) -> None:
        """Open the selected item."""

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        """Handle view-specific keys."""
        return False

    def navigation_height(self, app: "VaultTUI") -> int:
        """Return the table's height, including its column headers."""
        return max(0, app.body_height - 2)

    def handle_key(self, app: "VaultTUI", token: str) -> bool:
        """Handle navigation, filtering, refresh, and enter."""
        if self.filter_active:
            if token == "enter":
                self.table.apply_filter(self.filter_input)
                self.filter_active = False
                return True
            if token == "esc":
                self.filter_active = False
                self.filter_input = self.table.query
                return True
            if token == "backspace":
                self.filter_input = self.filter_input[:-1]
                return True
            if len(token) == 1 and token.isprintable():
                self.filter_input += token
                return True
            return True

        if app.keys.matches("up", token):
            self.table.move(-1, self.navigation_height(app))
            return True
        if app.keys.matches("down", token):
            self.table.move(1, self.navigation_height(app))
            return True
        if app.keys.matches("top", token):
            self.table.top()
            return True
        if app.keys.matches("bottom", token):
            self.table.bottom(self.navigation_height(app))
            return True
        if app.keys.matches("page_down", token) or token == "pagedown":
            self.table.page(1, self.navigation_height(app))
            return True
        if app.keys.matches("page_up", token) or token == "pageup":
            self.table.page(-1, self.navigation_height(app))
            return True
        if token == "/":
            self.filter_active = True
            self.filter_input = self.table.query
            return True
        if token == "r":
            app.client.cache.clear()
            self.load(app)
            app.status("refreshed")
            return True
        if app.keys.matches("enter", token):
            item = self.table.selected()
            if item is not None:
                self.open_selected(app, item)
            return True
        return self.extra_key(app, token)

    def render(self, app: "VaultTUI", win: Any, y: int, height: int, width: int) -> None:
        """Render title, errors, filter prompt, and table."""
        clear_area(win, y, 0, height, width)
        title = self.title
        if self.table.query:
            title += "  /%s" % self.table.query
        addstr_safe(win, y, 0, title, width, app.theme.pair(Theme.TITLE, curses.A_BOLD))
        table_y = y + 2
        if self.filter_active:
            addstr_safe(win, y + 1, 0, "/ " + self.filter_input + "_", width, app.theme.pair(Theme.ACCENT))
        elif self.error:
            addstr_safe(win, y + 1, 0, "Error: " + self.error, width, app.theme.pair(Theme.ERROR))
        else:
            addstr_safe(win, y + 1, 0, "", width)
        self.table.render(win, table_y, 0, max(0, height - 2), width, app.theme)

    def hints(self) -> List[Tuple[str, str]]:
        """Return standard table key hints."""
        return [("up/down", "navigate"), ("enter", "open"), ("/", "filter"), ("r", "refresh"), ("esc", "back")]


class DetailView(View):
    """Key/value table with JSON/YAML raw mode.

    Args:
        title (str): Screen title for the detail record.
        title (str): Заголовок экрана detail-записи.

    Returns:
        DetailView: Detail screen that can toggle table/raw JSON/YAML modes.
        DetailView: Detail-экран с переключением table/raw JSON/YAML modes.
    """

    def __init__(self, title: str) -> None:
        super().__init__(title)
        self.table = Table([Column("Property", 24), Column("Value", 30, True)])
        self.data: Dict[str, Any] = {}
        self.raw_mode = False
        self.raw_format = "json"
        self.raw_scroll = 0

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        """Fetch detail data."""
        return {}

    def rows_from_data(self, data: Dict[str, Any]) -> List[List[Any]]:
        """Convert detail data to table rows."""
        rows: List[List[Any]] = []
        for key, value in data.items():
            text = json.dumps(value, ensure_ascii=False, default=json_default) if not isinstance(value, str) else value
            rows.append([key, text if text else '""'])
        return rows

    def load(self, app: "VaultTUI") -> None:
        """Fetch details and rebuild rows.

        Args:
            app (VaultTUI): Running application with VaultClient.
            app (VaultTUI): Запущенное приложение с VaultClient.

        Returns:
            None: Updates self.data and table rows or stores an error.
            None: Обновляет self.data и rows таблицы или сохраняет ошибку.

        Raises:
            None: Exceptions are captured for on-screen display.
            None: Исключения перехватываются для отображения на экране.
        """
        try:
            self.data = self.fetch_data(app)
            rows = self.rows_from_data(self.data)
            self.table.set_rows(rows, rows)
            self.error = ""
        except Exception as exc:
            self.error = str(exc)

    def toggle_raw(self, fmt: str) -> None:
        """Toggle raw mode or switch raw format."""
        if self.raw_mode and self.raw_format == fmt:
            self.raw_mode = False
        else:
            self.raw_mode = True
            self.raw_format = fmt
            self.raw_scroll = 0

    def raw_payload(self) -> Dict[str, Any]:
        """Return complete data for JSON/YAML viewing and copying."""
        return self.data

    def raw_lines(self, width: Optional[int] = None) -> List[str]:
        """Return raw rendered lines."""
        text = render_raw(self.raw_payload(), self.raw_format)
        return wrap_lines(text, width) if width else text.splitlines()

    def handle_key(self, app: "VaultTUI", token: str) -> bool:
        """Handle table/raw navigation and copy."""
        if token == "r":
            app.client.cache.clear()
            self.load(app)
            app.status("refreshed")
            return True
        if app.keys.matches("copy_json", token):
            app.copy_text(render_raw(self.raw_payload(), "json"), "copied JSON")
            return True
        if self.raw_mode:
            lines = self.raw_lines(app.body_width)
            body = max(1, app.body_height - 2)
            if app.keys.matches("up", token):
                self.raw_scroll = max(0, self.raw_scroll - 1)
                return True
            if app.keys.matches("down", token):
                self.raw_scroll = min(max(0, len(lines) - body), self.raw_scroll + 1)
                return True
            if app.keys.matches("top", token):
                self.raw_scroll = 0
                return True
            if app.keys.matches("bottom", token):
                self.raw_scroll = max(0, len(lines) - body)
                return True
            if app.keys.matches("page_down", token) or token == "pagedown":
                self.raw_scroll = min(max(0, len(lines) - body), self.raw_scroll + body)
                return True
            if app.keys.matches("page_up", token) or token == "pageup":
                self.raw_scroll = max(0, self.raw_scroll - body)
                return True
            if token == "c":
                app.copy_text(render_raw(self.raw_payload(), self.raw_format), "%s copied" % self.raw_format.upper())
                return True
            if token == "f2":
                self.toggle_raw("json")
                return True
            if token == "y":
                self.toggle_raw("yaml")
                return True
            if token == "esc":
                self.raw_mode = False
                return True
            return False

        if app.keys.matches("up", token):
            self.table.move(-1, max(0, app.body_height - 2))
            return True
        if app.keys.matches("down", token):
            self.table.move(1, max(0, app.body_height - 2))
            return True
        if app.keys.matches("top", token):
            self.table.top()
            return True
        if app.keys.matches("bottom", token):
            self.table.bottom(max(0, app.body_height - 2))
            return True
        if app.keys.matches("page_down", token) or token == "pagedown":
            self.table.page(1, max(0, app.body_height - 2))
            return True
        if app.keys.matches("page_up", token) or token == "pageup":
            self.table.page(-1, max(0, app.body_height - 2))
            return True
        if app.keys.matches("enter", token) or app.keys.matches("copy", token):
            selected = self.table.selected()
            if selected:
                key = selected[0]
                value = self.data[key]
                text = value if isinstance(value, str) else render_raw(value, "json")
                if app.keys.matches("copy", token):
                    app.copy_text(text, "copied %s" % key)
                else:
                    app.push(TextView(self.title + " / " + key, text))
            return True
        if token == "f2":
            self.toggle_raw("json")
            return True
        if token == "y":
            self.toggle_raw("yaml")
            return True
        return False

    def render(self, app: "VaultTUI", win: Any, y: int, height: int, width: int) -> None:
        """Render details or raw data."""
        clear_area(win, y, 0, height, width)
        title = self.title
        if self.raw_mode:
            title += "  [%s]" % self.raw_format.upper()
        addstr_safe(win, y, 0, title, width, app.theme.pair(Theme.TITLE, curses.A_BOLD))
        if self.error:
            addstr_safe(win, y + 2, 0, "Error: " + self.error, width, app.theme.pair(Theme.ERROR))
            return
        if self.raw_mode:
            lines = self.raw_lines(width)
            body_y = y + 2
            body_h = max(0, height - 2)
            self.raw_scroll = min(self.raw_scroll, max(0, len(lines) - body_h))
            end = min(len(lines), self.raw_scroll + body_h)
            for row, line in enumerate(lines[self.raw_scroll : end]):
                addstr_safe(win, body_y + row, 0, line, width)
            if height > 1:
                draw_scroll_indicator(win, y + 1, 0, width, self.raw_scroll, body_h, len(lines), app.theme)
            return
        self.table.render(win, y + 2, 0, max(0, height - 2), width, app.theme)

    def hints(self) -> List[Tuple[str, str]]:
        """Return detail view key hints."""
        if self.raw_mode:
            return [("up/down", "scroll"), ("c", "copy raw"), ("F2/y", "json/yaml"), ("esc", "table")]
        return [("enter", "full value"), ("c/F4", "copy value/JSON"), ("F2/y", "raw"), ("r", "refresh"), ("esc", "back")]


class TextView(View):
    """Scrollable text view with copy support.

    Args:
        title (str): Screen title.
        text (str): Initial text content.
        loader (Optional[Callable[[VaultTUI], str]]): Optional refresh loader.
        title (str): Заголовок экрана.
        text (str): Начальный текст.
        loader (Optional[Callable[[VaultTUI], str]]): Необязательный loader для refresh.

    Returns:
        TextView: Scrollable text screen for policies, PEM data, and diffs.
        TextView: Прокручиваемый текстовый экран для policies, PEM и diffs.
    """

    def __init__(self, title: str, text: str = "", loader: Optional[Callable[["VaultTUI"], str]] = None) -> None:
        super().__init__(title)
        self.text = text
        self.loader = loader
        self.scroll = 0

    def load(self, app: "VaultTUI") -> None:
        """Load text content when a loader was provided."""
        if not self.loader:
            return
        try:
            self.text = self.loader(app)
            self.error = ""
        except Exception as exc:
            self.error = str(exc)

    def handle_key(self, app: "VaultTUI", token: str) -> bool:
        """Handle text scrolling and copy."""
        body = max(1, app.body_height - 2)
        lines = self.display_lines(app.body_width)
        max_scroll = max(0, len(lines) - body)
        if app.keys.matches("up", token):
            self.scroll = max(0, self.scroll - 1)
            return True
        if app.keys.matches("down", token):
            self.scroll = min(max_scroll, self.scroll + 1)
            return True
        if app.keys.matches("top", token):
            self.scroll = 0
            return True
        if app.keys.matches("bottom", token):
            self.scroll = max_scroll
            return True
        if app.keys.matches("page_down", token) or token == "pagedown":
            self.scroll = min(max_scroll, self.scroll + body)
            return True
        if app.keys.matches("page_up", token) or token == "pageup":
            self.scroll = max(0, self.scroll - body)
            return True
        if token == "c":
            app.copy_text(self.text, "copied")
            return True
        if token == "r":
            app.client.cache.clear()
            self.load(app)
            app.status("refreshed")
            return True
        return False

    def display_lines(self, width: int) -> List[str]:
        """Return wrapped display lines."""
        return wrap_lines(self.text, max(1, width))

    def render(self, app: "VaultTUI", win: Any, y: int, height: int, width: int) -> None:
        """Render text content."""
        clear_area(win, y, 0, height, width)
        addstr_safe(win, y, 0, self.title, width, app.theme.pair(Theme.TITLE, curses.A_BOLD))
        if self.error:
            addstr_safe(win, y + 2, 0, "Error: " + self.error, width, app.theme.pair(Theme.ERROR))
            return
        lines = self.display_lines(width)
        body_h = max(0, height - 2)
        max_scroll = max(0, len(lines) - body_h)
        self.scroll = min(self.scroll, max_scroll)
        for row, line in enumerate(lines[self.scroll : self.scroll + body_h]):
            addstr_safe(win, y + 2 + row, 0, line, width)
        if height > 1:
            draw_scroll_indicator(win, y + 1, 0, width, self.scroll, body_h, len(lines), app.theme)

    def hints(self) -> List[Tuple[str, str]]:
        """Return text view hints."""
        return [("up/down", "scroll"), ("c", "copy"), ("r", "refresh"), ("esc", "back")]


# ---------------------------------------------------------------------------
# Concrete views
# ---------------------------------------------------------------------------


class DashboardView(View):
    """Vault overview screen.

    Args:
        None.
        Нет.

    Returns:
        DashboardView: Root screen with health, seal, HA, resource counts, and quick nav.
        DashboardView: Root-экран с health, seal, HA, счётчиками ресурсов и quick nav.
    """

    def __init__(self) -> None:
        super().__init__("Dashboard")
        self.health: Dict[str, Any] = {}
        self.seal: Dict[str, Any] = {}
        self.ha: Dict[str, Any] = {}
        self.counts: Dict[str, int] = {}
        self.count_errors: List[str] = []

    def load(self, app: "VaultTUI") -> None:
        """Fetch dashboard status and resource counts."""
        self.count_errors = []
        try:
            self.health = app.client.health()
            self.error = ""
        except Exception as exc:
            self.error = str(exc)
            return

        try:
            self.seal = app.client.seal_status()
        except Exception as exc:
            self.seal = {}
            self.count_errors.append("Seal status: %s" % exc)
        try:
            self.ha = app.client.ha_status()
        except Exception as exc:
            self.ha = {}
            self.count_errors.append("HA status: %s" % exc)

        self.counts = {}
        for label, loader in (
            ("Secret Engines", app.client.list_secret_engines),
            ("Auth Methods", app.client.list_auth_methods),
            ("Policies", app.client.list_policies),
        ):
            try:
                self.counts[label] = len(loader())
            except Exception as exc:
                self.counts[label] = -1
                self.count_errors.append("%s: %s" % (label, exc))

    def handle_key(self, app: "VaultTUI", token: str) -> bool:
        if token == "r":
            app.client.cache.clear()
            self.load(app)
            return True
        if token in ("enter", "d", "f2", "y"):
            def load_details(current_app: "VaultTUI") -> Dict[str, Any]:
                self.load(current_app)
                return {"health": self.health, "seal_status": self.seal, "ha_status": self.ha,
                        "resources": self.counts, "errors": ([self.error] if self.error else []) + self.count_errors}
            view = MappingLoaderDetailView("Overview / Full status", load_details)
            app.push(view)
            if token in ("f2", "y"):
                view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False

    def render(self, app: "VaultTUI", win: Any, y: int, height: int, width: int) -> None:
        """Render dashboard panels."""
        clear_area(win, y, 0, height, width)
        addstr_safe(win, y, 0, "Dashboard", width, app.theme.pair(Theme.TITLE, curses.A_BOLD))
        if self.error:
            addstr_safe(win, y + 2, 0, "Could not connect to Vault", width, app.theme.pair(Theme.ERROR, curses.A_BOLD))
            for idx, line in enumerate(wrap_lines(self.error, width)):
                addstr_safe(win, y + 4 + idx, 0, line, width, app.theme.pair(Theme.DIM))
            return
        h = self.health
        sealed = bool(h.get("sealed", False))
        nodes = self.ha.get("nodes") or []
        active = sum(1 for node in nodes if node.get("active_node"))
        standby = sum(1 for node in nodes if not node.get("active_node"))
        lines = [
            ("Status", "sealed" if sealed else "unsealed", Theme.ERROR if sealed else Theme.OK),
            ("Version", h.get("version", "n/a"), 0),
            ("Seal Type", self.seal.get("type") or self.seal.get("seal_type") or "n/a", 0),
            ("Storage", self.seal.get("storage_type") or "n/a", 0),
            ("HA Nodes", "%d active, %d standby" % (active, standby) if nodes else "n/a", 0),
            ("Cluster", h.get("cluster_name") or "n/a", 0),
        ]
        row = y + 2
        for label, value, color in lines:
            addstr_safe(win, row, 2, (label + ":").ljust(18), 20, app.theme.pair(Theme.DIM))
            addstr_safe(win, row, 22, value, width - 22, app.theme.pair(color) if color else 0)
            row += 1
        row += 1
        addstr_safe(win, row, 2, "Resources", width - 2, app.theme.pair(Theme.ACCENT, curses.A_BOLD))
        row += 1
        for label, value in self.counts.items():
            addstr_safe(win, row, 2, (label + ":").ljust(18), 20, app.theme.pair(Theme.DIM))
            if value < 0:
                addstr_safe(win, row, 22, "error", width - 22, app.theme.pair(Theme.ERROR))
            else:
                addstr_safe(win, row, 22, str(value), width - 22)
            row += 1
        for err in self.count_errors[:2]:
            addstr_safe(win, row, 2, fit(err, width - 2), width - 2, app.theme.pair(Theme.DIM))
            row += 1

    def hints(self) -> List[Tuple[str, str]]:
        """Return dashboard hints."""
        return [("enter", "full status"), ("b", "resources"), ("r", "refresh"), (":", "command"), ("?", "help")]


class EnginesView(TableView):
    """Secret engines browser.

    Args:
        None.
        Нет.

    Returns:
        EnginesView: Table screen for mounted secret engines.
        EnginesView: Табличный экран mounted secret engines.
    """

    columns = [Column("Path", 20), Column("Type", 14), Column("Version", 10), Column("Description", 20, True)]

    def __init__(self) -> None:
        super().__init__("Secret Engines")

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        engines = app.client.list_secret_engines()
        rows = [[e.get("path"), e.get("type"), e.get("version"), e.get("description")] for e in engines]
        return rows, engines

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        mount = item.get("path", "")
        typ = item.get("type", "")
        if typ == "pki":
            app.push(PKIView(mount))
        elif typ == "transit":
            app.push(TransitView(mount))
        elif typ == "database":
            app.push(DatabaseView(mount))
        elif typ == "aws":
            app.push(AWSView(mount))
        elif typ == "identity":
            app.push(IdentityView())
        elif typ == "system":
            app.open_resources(DashboardView())
        else:
            app.push(PathBrowserView(mount, "", item.get("version") == "v2"))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token in ("d", "f2", "y"):
            item = self.table.selected()
            if not item:
                return True
            view = EngineDetailView(item.get("path", ""))
            app.push(view)
            if token in ("f2", "y"):
                view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False

    def hints(self) -> List[Tuple[str, str]]:
        return [("up/down", "navigate"), ("enter", "browse"), ("d", "describe"), ("F2/y", "raw"), ("esc", "back")]


class EngineDetailView(DetailView):
    """Secret engine mount detail view.

    EN: Shows mount configuration and raw JSON/YAML for one engine.
    RU: Показывает конфигурацию mount и raw JSON/YAML для одного engine.
    """

    def __init__(self, mount: str) -> None:
        super().__init__("Engine: " + mount)
        self.mount = mount

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        return app.client.read_engine_config(self.mount)


class PathBrowserView(TableView):
    """KV and logical path browser.

    Args:
        mount (str): Secret engine mount path.
        sub_path (str): Current path inside the mount.
        kv_v2 (bool): Whether KV v2 data/metadata endpoints are required.
        mount (str): Mount path secret engine.
        sub_path (str): Текущий путь внутри mount.
        kv_v2 (bool): Нужны ли KV v2 endpoints data/metadata.

    Returns:
        PathBrowserView: Directory/secret listing screen.
        PathBrowserView: Экран списка каталогов и secrets.
    """

    columns = [Column("Name", 32, True), Column("Type", 12)]

    def __init__(self, mount: str, sub_path: str, kv_v2: bool) -> None:
        super().__init__(ensure_slash(mount) + sub_path)
        self.mount = ensure_slash(mount)
        self.sub_path = sub_path
        self.kv_v2 = kv_v2

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        entries = app.client.list_secrets(self.mount, self.sub_path, self.kv_v2)
        rows = [[entry["name"], "dir" if entry["is_dir"] else "secret"] for entry in entries]
        return rows, entries

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        name = item.get("name", "")
        new_path = self.sub_path + name
        if item.get("is_dir"):
            app.push(PathBrowserView(self.mount, new_path, self.kv_v2))
        else:
            app.push(SecretDetailView(self.mount, new_path, self.kv_v2))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token in ("f2", "y"):
            item = self.table.selected()
            if item and not item.get("is_dir"):
                view = SecretDetailView(self.mount, self.sub_path + item.get("name", ""), self.kv_v2)
                app.push(view)
                view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False

    def hints(self) -> List[Tuple[str, str]]:
        return [("up/down", "navigate"), ("enter", "open"), ("F2/y", "raw"), ("esc", "back")]


class SecretDetailView(DetailView):
    """KV secret detail view.

    Args:
        mount (str): KV mount path.
        sub_path (str): Secret path inside the mount.
        kv_v2 (bool): Whether the mount uses KV v2.
        version (int): Optional KV v2 version to read.
        mount (str): KV mount path.
        sub_path (str): Путь secret внутри mount.
        kv_v2 (bool): Использует ли mount KV v2.
        version (int): Необязательная версия KV v2.

    Returns:
        SecretDetailView: Key/value detail screen with copy and version navigation.
        SecretDetailView: Detail-экран key/value с copy и переходом к версиям.
    """

    def __init__(self, mount: str, sub_path: str, kv_v2: bool, version: int = 0) -> None:
        title = ensure_slash(mount) + sub_path
        if version:
            title += " (v%d)" % version
        super().__init__(title)
        self.mount = ensure_slash(mount)
        self.sub_path = sub_path
        self.kv_v2 = kv_v2
        self.version = version
        self.keys: List[str] = []

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        data = (
            app.client.read_secret_version(self.mount, self.sub_path, self.version)
            if self.version and self.kv_v2
            else app.client.read_secret(self.mount, self.sub_path, self.kv_v2)
        )
        self.keys = sorted(data.keys())
        return {key: data[key] for key in self.keys}

    def handle_key(self, app: "VaultTUI", token: str) -> bool:
        if not self.raw_mode:
            if token == "m" and self.kv_v2:
                app.push(APIReadView(vault_join(self.mount, "metadata", self.sub_path)))
                return True
            if app.keys.matches("copy", token):
                selected = self.table.selected()
                if selected:
                    key = selected[0]
                    app.copy_text(stringify(self.data.get(key, "")), "copied %s" % key)
                return True
            if app.keys.matches("copy_json", token):
                app.copy_text(render_raw(self.data, "json"), "copied JSON")
                return True
            if token == "v" and self.kv_v2:
                app.push(VersionsView(self.mount, self.sub_path))
                return True
        return super().handle_key(app, token)

    def hints(self) -> List[Tuple[str, str]]:
        if self.raw_mode:
            return super().hints()
        hints = [("up/down", "navigate"), ("c", "copy value"), ("F4", "copy JSON"), ("F2/y", "raw")]
        if self.kv_v2:
            hints.append(("v", "versions"))
            hints.append(("m", "metadata"))
        hints.append(("esc", "back"))
        return hints


class VersionsView(TableView):
    """KV v2 version history view.

    EN: Lists metadata versions and opens version detail or diff screens.
    RU: Показывает версии metadata и открывает detail версии или diff.
    """

    columns = [Column("Version", 10), Column("Created", 24), Column("Status", 14, True)]

    def __init__(self, mount: str, sub_path: str) -> None:
        super().__init__(ensure_slash(mount) + sub_path + " versions")
        self.mount = ensure_slash(mount)
        self.sub_path = sub_path

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        versions = app.client.read_secret_metadata(self.mount, self.sub_path)
        rows = []
        for idx, ver in enumerate(versions):
            status = "current" if idx == 0 else "old"
            if ver.get("destroyed"):
                status = "destroyed"
            elif ver.get("deletion_time"):
                status = "deleted"
            rows.append(["v%d" % ver.get("version", 0), parse_time(ver.get("created_time")), status])
        return rows, versions

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        app.push(SecretDetailView(self.mount, self.sub_path, True, safe_int(item.get("version"))))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token == "d":
            idx = self.table.cursor
            if idx + 1 < len(self.table.items):
                new_ver = safe_int(self.table.items[idx].get("version"))
                old_ver = safe_int(self.table.items[idx + 1].get("version"))
                app.push(DiffView(self.mount, self.sub_path, old_ver, new_ver))
            return True
        return False

    def hints(self) -> List[Tuple[str, str]]:
        return [("up/down", "navigate"), ("enter", "view"), ("d", "diff prev"), ("esc", "back")]


class DiffView(TextView):
    """Diff two KV v2 secret versions.

    EN: Compares key/value maps from two KV v2 versions.
    RU: Сравнивает key/value карты двух версий KV v2.
    """

    def __init__(self, mount: str, sub_path: str, old_version: int, new_version: int) -> None:
        self.mount = ensure_slash(mount)
        self.sub_path = sub_path
        self.old_version = old_version
        self.new_version = new_version
        super().__init__("Diff v%d -> v%d %s%s" % (old_version, new_version, self.mount, sub_path))

    def load(self, app: "VaultTUI") -> None:
        try:
            old = app.client.read_secret_version(self.mount, self.sub_path, self.old_version)
            new = app.client.read_secret_version(self.mount, self.sub_path, self.new_version)
            self.text = self._compute(old, new)
            self.error = ""
        except Exception as exc:
            self.error = str(exc)

    def _compute(self, old: Dict[str, Any], new: Dict[str, Any]) -> str:
        lines: List[str] = []
        for key in sorted(set(old) | set(new)):
            old_val = stringify(old.get(key))
            new_val = stringify(new.get(key))
            if key not in old:
                lines.append("+ %-24s %s" % (key, new_val))
            elif key not in new:
                lines.append("- %-24s %s" % (key, old_val))
            elif old_val != new_val:
                lines.append("- %-24s %s" % (key, old_val))
                lines.append("+ %-24s %s" % (key, new_val))
            else:
                lines.append("  %-24s %s" % (key, old_val))
        return "\n".join(lines) if lines else "No differences"


class PoliciesView(TableView):
    """ACL policies browser.

    EN: Lists ACL policies above a preview of the selected policy body.
    RU: Показывает список ACL policies и содержимое выбранной policy под ним.
    """

    columns = [Column("Name", 30, True), Column("Type", 10)]

    def __init__(self) -> None:
        super().__init__("Policies")
        self.preview: Optional[PolicyDetailView] = None

    def load(self, app: "VaultTUI") -> None:
        super().load(app)
        self.update_preview(app, force=True)

    def update_preview(self, app: "VaultTUI", force: bool = False) -> None:
        """Read only when selection changes or the user requests a refresh."""
        name = self.table.selected()
        if name is None:
            self.preview = None
        elif force or self.preview is None or self.preview.name != name:
            self.preview = PolicyDetailView(name)
            self.preview.load(app)

    def navigation_height(self, app: "VaultTUI") -> int:
        upper = max(1, app.body_height // 2)
        # Compact terminals omit table headers, leaving one title and actual rows.
        return upper - 2 if upper >= 5 else upper + 1

    def preview_lines(self, width: int) -> List[str]:
        if self.preview is None:
            return []
        return wrap_lines(self.preview.error or self.preview.text or "Policy has no body.", width)

    def handle_key(self, app: "VaultTUI", token: str) -> bool:
        if not self.filter_active and token in ("pageup", "pagedown"):
            if self.preview:
                visible = max(1, app.body_height - max(1, app.body_height // 2) - 1)
                lines = self.preview_lines(app.body_width)
                delta = visible if token == "pagedown" else -visible
                self.preview.scroll = max(0, min(max(0, len(lines) - visible), self.preview.scroll + delta))
            return True
        if not self.filter_active and app.keys.matches("copy", token):
            if self.preview and not self.preview.error:
                app.copy_text(self.preview.text, "copied policy %s" % self.preview.name)
            return True
        handled = super().handle_key(app, token)
        self.update_preview(app)
        return handled

    def render(self, app: "VaultTUI", win: Any, y: int, height: int, width: int) -> None:
        """Keep the policy list and selected policy body visible together."""
        if height <= 0:
            return
        upper = max(1, height // 2)
        table_height = upper - 2 if upper >= 5 else upper + 1
        self.table._ensure_visible(table_height)
        if upper >= 5:
            super().render(app, win, y, upper, width)
        else:
            clear_area(win, y, 0, upper, width)
            title = "/ " + self.filter_input + "_" if self.filter_active else self.title
            indicator = scroll_indicator(self.table.offset, upper - 1, len(self.table.rows))
            addstr_safe(win, y, 0, title, max(0, width - len(indicator) - 1), app.theme.pair(Theme.TITLE, curses.A_BOLD))
            for row, index in enumerate(range(self.table.offset, min(len(self.table.rows), self.table.offset + upper - 1))):
                attr = app.theme.pair(Theme.SELECTED) if index == self.table.cursor else 0
                addstr_safe(win, y + 1 + row, 0, self.table.rows[index][0], width, attr)
            draw_scroll_indicator(win, y, 0, width, self.table.offset, upper - 1, len(self.table.rows), app.theme)
        lower = height - upper
        clear_area(win, y + upper, 0, lower, width)
        if lower <= 0:
            return
        title = " Policy: %s " % self.preview.name if self.preview else " No policy selected "
        lines = self.preview_lines(width)
        visible = max(0, lower - 1)
        if self.preview:
            self.preview.scroll = min(self.preview.scroll, max(0, len(lines) - visible))
        offset = self.preview.scroll if self.preview else 0
        indicator = scroll_indicator(offset, visible, len(lines))
        title_width = max(0, width - len(indicator))
        addstr_safe(win, y + upper, 0, fit(title, title_width).rstrip().center(title_width, "-"), title_width, app.theme.pair(Theme.TITLE, curses.A_BOLD))
        draw_scroll_indicator(win, y + upper, 0, width, offset, visible, len(lines), app.theme)
        if not self.preview:
            return
        attr = app.theme.pair(Theme.ERROR) if self.preview.error else 0
        for row, line in enumerate(lines[self.preview.scroll:self.preview.scroll + visible]):
            addstr_safe(win, y + upper + 1 + row, 0, line, width, attr)

    def hints(self) -> List[Tuple[str, str]]:
        return [("up/down", "select"), ("PgUp/PgDn", "preview"), ("enter", "full screen"),
                ("/", "filter"), ("c", "copy"), ("r", "refresh"), ("esc", "back")]

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        policies = app.client.list_policies()
        return [[name, "root" if name == "root" else "acl"] for name in policies], policies

    def open_selected(self, app: "VaultTUI", item: str) -> None:
        app.push(PolicyDetailView(item))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token in ("d", "f2", "y"):
            item = self.table.selected()
            if item:
                view = APIReadView(vault_join("sys/policies/acl", item))
                app.push(view)
                if token in ("f2", "y"):
                    view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False


class PolicyDetailView(TextView):
    """Policy body viewer.

    EN: Displays one ACL policy body with scrolling and copy support.
    RU: Отображает тело одной ACL policy с прокруткой и копированием.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__("Policy: " + name)

    def load(self, app: "VaultTUI") -> None:
        try:
            self.text = app.client.get_policy(self.name)
            self.error = ""
        except Exception as exc:
            self.error = str(exc)


class AuthMethodsView(TableView):
    """Auth methods browser.

    EN: Lists enabled auth mounts with type, accessor, and description.
    RU: Показывает включённые auth mounts с type, accessor и description.
    """

    columns = [Column("Path", 20), Column("Type", 14), Column("Accessor", 24), Column("Description", 20, True)]

    def __init__(self) -> None:
        super().__init__("Auth Methods")

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        methods = app.client.list_auth_methods()
        rows = [[m.get("path"), m.get("type"), m.get("accessor"), m.get("description")] for m in methods]
        return rows, methods

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        app.push(AuthDetailView(item.get("path", ""), item.get("type", "")))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token in ("d", "f2", "y", "b"):
            item = self.table.selected()
            if item:
                view = AuthDetailView(item.get("path", ""), item.get("type", ""))
                if token == "b":
                    app.open_resources(view)
                else:
                    app.push(view)
                    if token in ("f2", "y"):
                        view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False

    def hints(self) -> List[Tuple[str, str]]:
        return [("enter", "configuration"), ("b", "resources"), ("F2/y", "raw"), ("r", "refresh"), ("esc", "back")]


class AuthDetailView(DetailView):
    """Complete backend configuration, mount metadata, and tuning."""

    def __init__(self, mount: str, auth_type: str) -> None:
        super().__init__("Auth: " + mount)
        self.mount = ensure_slash(mount)
        self.auth_type = auth_type
        self.sections: Dict[str, Any] = {}

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        self.sections = app.client.read_auth_config(self.mount)
        return {
            **self.sections["configuration"],
            "[mount]": self.sections["mount"],
            "[tuning]": self.sections["tuning"],
        }

    def raw_payload(self) -> Dict[str, Any]:
        return self.sections


class StaticDetailView(DetailView):
    """Detail view for already-loaded dictionaries.

    EN: Wraps already-normalized dictionaries in a standard detail screen.
    RU: Оборачивает уже нормализованные словари в стандартный detail-экран.
    """

    def __init__(self, title: str, data: Dict[str, Any]) -> None:
        super().__init__(title)
        self.static_data = data

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        return dict(self.static_data)


class APIReadView(DetailView):
    """Read any exact Vault API path without dropping the response envelope."""

    def __init__(self, path: str, params: Optional[Dict[str, Any]] = None) -> None:
        self.path = path.strip("/")
        self.params = params
        self.response: Dict[str, Any] = {}
        super().__init__("Read: " + self.path)

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        response = app.client.read(self.path, params=self.params)
        if response is None:
            raise VaultError("no data found at %s" % self.path)
        self.response = response
        data = response.get("data", response)
        return data if isinstance(data, dict) else {"data": data}

    def raw_payload(self) -> Dict[str, Any]:
        return self.response


class APIListView(TableView):
    """LIST collection with explicit read/list actions and complete list metadata."""

    columns = [Column("Key", 32, True), Column("Info", 40, True)]

    def __init__(self, path: str, read_prefix: str = "") -> None:
        self.path = path.strip("/")
        self.read_prefix = read_prefix.strip("/") or self.path
        self.response: Dict[str, Any] = {}
        super().__init__("List: " + self.path)

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        response = app.client.list(self.path)
        if response is None:
            raise VaultError("no list found at %s" % self.path)
        self.response = response
        data = response.get("data") or {}
        info = data.get("key_info") or {}
        keys = data.get("keys") or []
        return [[key, info.get(key, "")] for key in keys], keys

    def open_selected(self, app: "VaultTUI", item: str) -> None:
        if item.endswith("/"):
            app.push(APIListView(vault_join(self.path, item), vault_join(self.read_prefix, item)))
        else:
            app.push(APIReadView(vault_join(self.read_prefix, item)))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        item = self.table.selected()
        if token == "l":
            if item:
                app.push(APIListView(vault_join(self.path, item)))
            return True
        if token == "d":
            if item:
                app.push(APIReadView(vault_join(self.read_prefix, item)))
            return True
        if token in ("f2", "y"):
            view = StaticDetailView(self.title + " response", self.response)
            app.push(view)
            view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False

    def hints(self) -> List[Tuple[str, str]]:
        return [("enter", "open"), ("l", "list child"), ("d", "read child"), ("F2/y", "full response"), ("r", "refresh"), ("esc", "back")]


class EndpointBrowserView(TableView):
    """Discover common configuration and resource paths for the current section."""

    columns = [Column("Operation", 10), Column("API path", 48, True)]

    def __init__(self, title: str, endpoints: Sequence[Tuple[str, str, str]]) -> None:
        super().__init__(title + " / Resources")
        self.endpoints = endpoints

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        return [[method, path] for method, path, _ in self.endpoints], list(self.endpoints)

    def open_selected(self, app: "VaultTUI", item: Tuple[str, str, str]) -> None:
        method, path, read_prefix = item
        app.push(APIListView(path, read_prefix) if method == "LIST" else APIReadView(path))


class MountSelectorView(TableView):
    """Select any mounted instance of a backend, including custom mount paths."""

    columns = [Column("Mount", 30, True), Column("Description", 40, True)]

    def __init__(self, engine_type: str) -> None:
        super().__init__("Select mount: " + engine_type)
        self.engine_type = engine_type

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        mounts = [item for item in app.client.list_secret_engines() if item.get("type") == self.engine_type]
        return [[item["path"], item.get("description", "")] for item in mounts], mounts

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        cls = {"pki": PKIView, "transit": TransitView, "database": DatabaseView, "aws": AWSView}[self.engine_type]
        app.push(cls(item["path"]))


class PKIView(TableView):
    """PKI certificates and roles browser.

    EN: Switches between certificate and role tabs for a PKI mount.
    RU: Переключает вкладки сертификатов и ролей для PKI mount.
    """

    cert_columns = [Column("Serial Number", 50, True)]
    role_columns = [Column("Role Name", 30, True)]

    def __init__(self, mount: str) -> None:
        self.mount = ensure_slash(mount)
        self.tab = 0
        self.certs: List[Dict[str, Any]] = []
        self.roles: List[Dict[str, Any]] = []
        super().__init__("PKI: " + self.mount)
        self.table = Table(self.cert_columns)

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        self.certs = self.read_collection("Certificates", lambda: app.client.list_pki_certs(self.mount))
        self.roles = self.read_collection("Roles", lambda: app.client.list_pki_roles(self.mount))
        return self._current_rows()

    def _current_rows(self) -> Tuple[List[List[Any]], List[Any]]:
        if self.tab == 0:
            self.table.columns = list(self.cert_columns)
            return [[c.get("serial")] for c in self.certs], self.certs
        self.table.columns = list(self.role_columns)
        return [[r.get("name")] for r in self.roles], self.roles

    def _rebuild_tab(self) -> None:
        rows, items = self._current_rows()
        self.table.set_rows(rows, items)

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        if self.tab == 0:
            app.push(PKICertDetailView(self.mount, item.get("serial", "")))
        else:
            app.push(MappingLoaderDetailView("PKI Role: " + item.get("name", ""), lambda a: a.client.read_logical_data(vault_join(self.mount, "roles", item.get("name", "")))))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token == "tab":
            self.tab = (self.tab + 1) % 2
            self._rebuild_tab()
            return True
        if token in ("f2", "y"):
            item = self.table.selected()
            if item:
                self.open_selected(app, item)
                view = app.current()
                if isinstance(view, DetailView):
                    view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False

    def render(self, app: "VaultTUI", win: Any, y: int, height: int, width: int) -> None:
        self.title = "PKI: %s  [%s] %s" % (self.mount, "Certificates" if self.tab == 0 else "Roles", "Roles" if self.tab == 0 else "Certificates")
        super().render(app, win, y, height, width)

    def hints(self) -> List[Tuple[str, str]]:
        return [("up/down", "navigate"), ("tab", "switch tab"), ("enter", "view"), ("esc", "back")]


class PKICertDetailView(DetailView):
    """Complete certificate response, including PEM, chain and revocation fields."""

    def __init__(self, mount: str, serial: str) -> None:
        self.mount = ensure_slash(mount)
        self.serial = serial
        super().__init__("Certificate: " + serial)

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        return app.client.read_pki_cert(self.mount, self.serial)


class TransitView(TableView):
    """Transit key browser.

    EN: Lists Transit encryption keys for one mount.
    RU: Показывает Transit encryption keys для одного mount.
    """

    columns = [Column("Key Name", 24, True)]

    def __init__(self, mount: str) -> None:
        self.mount = ensure_slash(mount)
        super().__init__("Transit: " + self.mount)

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        keys = app.client.list_transit_keys(self.mount)
        return [[key.get("name")] for key in keys], keys

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        app.push(TransitKeyDetailView(self.mount, item.get("name", "")))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token in ("f2", "y"):
            item = self.table.selected()
            if item:
                view = TransitKeyDetailView(self.mount, item.get("name", ""))
                app.push(view)
                view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False


class TransitKeyDetailView(DetailView):
    """Transit key detail viewer.

    EN: Shows Transit key properties and raw JSON/YAML.
    RU: Показывает свойства Transit key и raw JSON/YAML.
    """

    def __init__(self, mount: str, key_name: str) -> None:
        self.mount = ensure_slash(mount)
        self.key_name = key_name
        super().__init__("Transit Key: " + key_name)

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        return app.client.read_transit_key(self.mount, self.key_name)


class IdentityView(TableView):
    """Identity entities and groups browser.

    EN: Switches between entity and group tabs in Vault Identity.
    RU: Переключает вкладки entities и groups в Vault Identity.
    """

    entity_columns = [Column("Name", 24), Column("ID", 40, True)]
    group_columns = [Column("Name", 24), Column("ID", 40), Column("Type", 12, True)]

    def __init__(self) -> None:
        self.tab = 0
        self.entities: List[Dict[str, Any]] = []
        self.groups: List[Dict[str, Any]] = []
        super().__init__("Identity")
        self.table = Table(self.entity_columns)

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        self.entities = self.read_collection("Entities", app.client.list_identity_entities)
        self.groups = self.read_collection("Groups", app.client.list_identity_groups)
        return self._current_rows()

    def _current_rows(self) -> Tuple[List[List[Any]], List[Any]]:
        if self.tab == 0:
            self.table.columns = list(self.entity_columns)
            return [[e.get("name"), e.get("id")] for e in self.entities], self.entities
        self.table.columns = list(self.group_columns)
        return [[g.get("name"), g.get("id"), g.get("type")] for g in self.groups], self.groups

    def _rebuild_tab(self) -> None:
        rows, items = self._current_rows()
        self.table.set_rows(rows, items)

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        app.push(IdentityDetailView(self.tab == 0, item.get("id", ""), item.get("name", "")))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token == "tab":
            self.tab = (self.tab + 1) % 2
            self._rebuild_tab()
            return True
        if token in ("f2", "y"):
            item = self.table.selected()
            if item:
                view = IdentityDetailView(self.tab == 0, item.get("id", ""), item.get("name", ""))
                app.push(view)
                view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False

    def render(self, app: "VaultTUI", win: Any, y: int, height: int, width: int) -> None:
        self.title = "Identity  [%s] %s" % ("Entities" if self.tab == 0 else "Groups", "Groups" if self.tab == 0 else "Entities")
        super().render(app, win, y, height, width)

    def hints(self) -> List[Tuple[str, str]]:
        return [("up/down", "navigate"), ("tab", "switch tab"), ("enter", "view"), ("F2/y", "raw"), ("esc", "back")]


class IdentityDetailView(DetailView):
    """Identity entity or group detail viewer.

    EN: Displays normalized entity/group fields plus raw Vault data.
    RU: Показывает нормализованные поля entity/group и raw Vault data.
    """

    def __init__(self, is_entity: bool, item_id: str, name: str) -> None:
        self.is_entity = is_entity
        self.item_id = item_id
        self.name = name
        super().__init__(("Entity: " if is_entity else "Group: ") + name)

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        if self.is_entity:
            return app.client.read_identity_entity(self.item_id)["raw"]
        return app.client.read_identity_group(self.item_id)["raw"]


class MappingLoaderDetailView(DetailView):
    """Detail view backed by a callable returning a mapping.

    EN: Adapts simple loader callables into standard detail screens.
    RU: Адаптирует простые loader-функции в стандартные detail-экраны.
    """

    def __init__(self, title: str, loader: Callable[["VaultTUI"], Dict[str, Any]]) -> None:
        super().__init__(title)
        self.loader = loader

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        return self.loader(app)


class DatabaseView(TableView):
    """Database engine browser.

    EN: Switches between database connections, dynamic roles, and static roles.
    RU: Переключает connections, dynamic roles и static roles database engine.
    """

    conn_columns = [Column("Name", 24), Column("Plugin", 30), Column("Allowed Roles", 20, True)]
    role_columns = [Column("Name", 24), Column("DB Name", 24), Column("Default TTL", 14), Column("Max TTL", 14, True)]
    static_columns = [Column("Name", 24), Column("DB Name", 24), Column("Username", 20), Column("Rotation Period", 18, True)]

    def __init__(self, mount: str) -> None:
        self.mount = ensure_slash(mount)
        self.tab = 0
        self.conns: List[Dict[str, Any]] = []
        self.roles: List[Dict[str, Any]] = []
        self.static_roles: List[Dict[str, Any]] = []
        super().__init__("Database: " + self.mount)
        self.table = Table(self.conn_columns)

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        self.conns = self.read_collection("Connections", lambda: app.client.list_db_connections(self.mount))
        self.roles = self.read_collection("Roles", lambda: app.client.list_db_roles(self.mount))
        self.static_roles = self.read_collection("Static Roles", lambda: app.client.list_db_static_roles(self.mount))
        return self._current_rows()

    def _current_rows(self) -> Tuple[List[List[Any]], List[Any]]:
        if self.tab == 0:
            self.table.columns = list(self.conn_columns)
            return [[c.get("name"), c.get("plugin_name"), ", ".join(c.get("allowed_roles") or [])] for c in self.conns], self.conns
        if self.tab == 1:
            self.table.columns = list(self.role_columns)
            return [[r.get("name"), r.get("db_name"), r.get("default_ttl"), r.get("max_ttl")] for r in self.roles], self.roles
        self.table.columns = list(self.static_columns)
        return [[r.get("name"), r.get("db_name"), r.get("username"), r.get("rotation_period")] for r in self.static_roles], self.static_roles

    def _rebuild_tab(self) -> None:
        rows, items = self._current_rows()
        self.table.set_rows(rows, items)

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        name = item.get("name", "")
        if self.tab == 0:
            app.push(DBConnectionDetailView(self.mount, name))
        elif self.tab == 1:
            app.push(DBRoleDetailView(self.mount, name))
        else:
            app.push(DBStaticRoleDetailView(self.mount, name))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token == "tab":
            self.tab = (self.tab + 1) % 3
            self._rebuild_tab()
            return True
        if token in ("f2", "y"):
            item = self.table.selected()
            if item:
                name = item.get("name", "")
                view: DetailView
                if self.tab == 0:
                    view = DBConnectionDetailView(self.mount, name)
                elif self.tab == 1:
                    view = DBRoleDetailView(self.mount, name)
                else:
                    view = DBStaticRoleDetailView(self.mount, name)
                app.push(view)
                view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False

    def render(self, app: "VaultTUI", win: Any, y: int, height: int, width: int) -> None:
        names = ["Connections", "Roles", "Static Roles"]
        self.title = "Database: %s  [%s]" % (self.mount, names[self.tab])
        super().render(app, win, y, height, width)

    def hints(self) -> List[Tuple[str, str]]:
        return [("up/down", "navigate"), ("tab", "switch tab"), ("enter", "view"), ("F2/y", "raw"), ("esc", "back")]


class DBConnectionDetailView(DetailView):
    """Database connection detail viewer.

    EN: Shows database connection plugin, URL, roles, and policy fields.
    RU: Показывает plugin, URL, роли и policy поля database connection.
    """

    def __init__(self, mount: str, name: str) -> None:
        self.mount = mount
        self.name = name
        super().__init__("Connection: " + name)

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        return app.client.read_db_connection(self.mount, self.name)


class DBRoleDetailView(DetailView):
    """Database dynamic role detail viewer.

    EN: Shows dynamic database role TTLs and SQL statement templates.
    RU: Показывает TTL и SQL-шаблоны dynamic database role.
    """

    def __init__(self, mount: str, name: str) -> None:
        self.mount = mount
        self.name = name
        super().__init__("Role: " + name)

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        return app.client.read_db_role(self.mount, self.name)


class DBStaticRoleDetailView(DetailView):
    """Database static role detail viewer.

    EN: Shows static database role rotation settings.
    RU: Показывает настройки rotation для static database role.
    """

    def __init__(self, mount: str, name: str) -> None:
        self.mount = mount
        self.name = name
        super().__init__("Static Role: " + name)

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        return app.client.read_db_static_role(self.mount, self.name)


class AWSView(TableView):
    """AWS secrets engine browser.

    EN: Switches between AWS roles, root config, and active leases.
    RU: Переключает AWS roles, root config и active leases.
    """

    role_columns = [Column("Name", 24), Column("Credential Type", 20), Column("Policy ARNs", 30, True)]
    config_columns = [Column("Property", 24), Column("Value", 30, True)]
    lease_columns = [Column("Role", 20), Column("Lease ID", 20, True), Column("TTL", 10), Column("Issue Time", 20)]

    def __init__(self, mount: str) -> None:
        self.mount = ensure_slash(mount)
        self.tab = 0
        self.roles: List[Dict[str, Any]] = []
        self.config: Dict[str, Any] = {}
        self.leases: List[Dict[str, Any]] = []
        super().__init__("AWS: " + self.mount)
        self.table = Table(self.role_columns)

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        self.roles = self.read_collection("Roles", lambda: app.client.list_aws_roles(self.mount))
        self.config = app.client.read_aws_config(self.mount)
        self.leases = self.read_collection("Leases", lambda: app.client.list_aws_leases(self.mount))
        return self._current_rows()

    def _current_rows(self) -> Tuple[List[List[Any]], List[Any]]:
        if self.tab == 0:
            self.table.columns = list(self.role_columns)
            return [[r.get("name"), r.get("credential_type"), ", ".join(r.get("policy_arns") or [])] for r in self.roles], self.roles
        if self.tab == 1:
            self.table.columns = list(self.config_columns)
            rows = [[key, value] for key, value in self.config.items()]
            return rows, [{"key": key, "value": value} for key, value in self.config.items()]
        self.table.columns = list(self.lease_columns)
        rows = [[l.get("role"), l.get("short_id"), format_duration_seconds(l.get("ttl"), "expired"), parse_time(l.get("issue_time"))] for l in self.leases]
        return rows, self.leases

    def _rebuild_tab(self) -> None:
        rows, items = self._current_rows()
        self.table.set_rows(rows, items)

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        if self.tab == 0:
            app.push(AWSRoleDetailView(self.mount, item.get("name", "")))
        elif self.tab == 1:
            name = item["key"]
            app.push(APIReadView(vault_join(self.mount, "config", name)))
        elif self.tab == 2:
            app.push(StaticDetailView("Lease: " + item.get("role", ""), item))

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token == "tab":
            self.tab = (self.tab + 1) % 3
            self._rebuild_tab()
            return True
        if token in ("f2", "y"):
            item = self.table.selected()
            if item:
                view: DetailView
                if self.tab == 0:
                    view = AWSRoleDetailView(self.mount, item.get("name", ""))
                elif self.tab == 1:
                    view = APIReadView(vault_join(self.mount, "config", item["key"]))
                else:
                    view = StaticDetailView("Lease: " + item.get("role", ""), item)
                app.push(view)
                view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False

    def render(self, app: "VaultTUI", win: Any, y: int, height: int, width: int) -> None:
        names = ["Roles", "Config", "Leases"]
        self.title = "AWS: %s  [%s]" % (self.mount, names[self.tab])
        super().render(app, win, y, height, width)

    def hints(self) -> List[Tuple[str, str]]:
        return [("up/down", "navigate"), ("tab", "switch tab"), ("enter", "view"), ("F2/y", "raw"), ("r", "refresh"), ("esc", "back")]


class AWSRoleDetailView(DetailView):
    """AWS role detail viewer.

    EN: Shows AWS credential type, role ARNs, policies, and TTLs.
    RU: Показывает AWS credential type, role ARNs, policies и TTL.
    """

    def __init__(self, mount: str, name: str) -> None:
        self.mount = mount
        self.name = name
        super().__init__("AWS Role: " + name)

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        return app.client.read_aws_role(self.mount, self.name)


class TokenInspectorView(DetailView):
    """Current token inspector.

    EN: Displays lookup-self metadata for the current token.
    RU: Показывает lookup-self metadata текущего token.
    """

    def __init__(self) -> None:
        super().__init__("Token Inspector")

    def fetch_data(self, app: "VaultTUI") -> Dict[str, Any]:
        return app.client.inspect_token()


class ContextsView(TableView):
    """Configured context switcher.

    EN: Lists ~/.vaultui.yaml contexts and switches the active Vault connection.
    RU: Показывает contexts из ~/.vaultui.yaml и переключает активное подключение.
    """

    columns = [Column("Name", 18), Column("Address", 32, True), Column("Namespace", 14), Column("Auth", 12)]

    def __init__(self) -> None:
        super().__init__("Contexts")

    def rows_and_items(self, app: "VaultTUI") -> Tuple[List[List[Any]], List[Any]]:
        contexts = app.config.raw_config.get("contexts") or []
        rows = []
        for ctx in contexts:
            name = ctx.get("name", "")
            if name == app.config.raw_config.get("current_context"):
                name = "* " + name
            auth = (ctx.get("auth") or {}).get("method") or "token"
            rows.append([name, ctx.get("address", ""), ctx.get("namespace") or "root", auth])
        return rows, contexts

    def open_selected(self, app: "VaultTUI", item: Dict[str, Any]) -> None:
        app.switch_context(item)

    def extra_key(self, app: "VaultTUI", token: str) -> bool:
        if token in ("d", "f2", "y"):
            item = self.table.selected()
            if item:
                view = StaticDetailView("Context: " + item.get("name", ""), item)
                app.push(view)
                if token in ("f2", "y"):
                    view.toggle_raw("json" if token == "f2" else "yaml")
            return True
        return False

    def hints(self) -> List[Tuple[str, str]]:
        return [("up/down", "navigate"), ("enter", "switch"), ("d", "details"), ("F2/y", "raw"), ("esc", "back")]


# ---------------------------------------------------------------------------
# Top-level TUI application
# ---------------------------------------------------------------------------


class VaultTUI:
    """Curses application controller with router, command palette, and status.

    Args:
        client (VaultClient): Vault API client used by all views.
        config (RuntimeConfig): Resolved runtime settings.
        client (VaultClient): Vault API client для всех экранов.
        config (RuntimeConfig): Разрешённые runtime-настройки.

    Returns:
        VaultTUI: Stateful terminal application controller.
        VaultTUI: Stateful controller terminal-приложения.

    Raises:
        curses.error: May propagate during terminal initialization failures.
        curses.error: Может возникнуть при ошибках инициализации terminal.
    """

    TABS = (
        ("0", "Overview", DashboardView, ()),
        ("1", "Secrets", EnginesView, ()),
        ("2", "Auth", AuthMethodsView, ()),
        ("3", "Policies", PoliciesView, ()),
        ("4", "Identity", IdentityView, ()),
        ("5", "PKI", PKIView, ("pki/",)),
        ("6", "Transit", TransitView, ("transit/",)),
        ("7", "Database", DatabaseView, ("database/",)),
        ("8", "AWS", AWSView, ("aws/",)),
    )

    def __init__(self, client: VaultClient, config: RuntimeConfig) -> None:
        self.client = client
        self.config = config
        self.keys = KeyMap(config.keybindings)
        self.theme = Theme()
        self.clipboard = Clipboard()
        self.stack: List[View] = []
        self.active_tab = "0"
        self.tab_stacks: Dict[str, List[View]] = {}
        self.command_active = False
        self.command_input = ""
        self.command_error = ""
        self.help_active = False
        self.status_text = ""
        self.status_until = 0.0
        self.body_height = 1
        self.body_width = 1
        self.health: Dict[str, Any] = {}
        self.health_error = ""
        self.health_checked_at = 0.0
        self.running = True
        self.screen: Optional[Any] = None
        self.renewer = TokenRenewer(client)

    def push(self, view: View) -> None:
        """Push and load a view."""
        self.stack.append(view)
        view.load(self)

    def pop(self) -> None:
        """Go back within the tab, or return to the overview."""
        if len(self.stack) > 1:
            self.stack.pop()
        elif self.active_tab != "0":
            self.quick_jump("0")

    def reset_to(self, view: View) -> None:
        """Open a command destination in its corresponding tab."""
        key = next((key for key, _, cls, _ in self.TABS if isinstance(view, cls)), None)
        if key is None:
            key = "1" if isinstance(view, (PathBrowserView, SecretDetailView)) else "0"
        self.tab_stacks[self.active_tab] = self.stack
        self.active_tab = key
        self.stack = []
        self.tab_stacks[key] = self.stack
        if not any(isinstance(view, cls) for _, _, cls, _ in self.TABS):
            _, _, cls, args = next(tab for tab in self.TABS if tab[0] == key)
            self.push(cls(*args))
        self.push(view)

    def current(self) -> View:
        """Return the current view."""
        if not self.stack:
            self.push(DashboardView())
        return self.stack[-1]

    def status(self, message: str, seconds: float = 3.0) -> None:
        """Show a transient status message."""
        self.status_text = message
        self.status_until = time.time() + seconds

    def copy_text(self, text: str, message: str) -> None:
        """Copy text to clipboard and report success or failure."""
        try:
            self.clipboard.write(text, self.config.clipboard_timeout)
            self.status("%s; clipboard clears in %ss" % (message, self.config.clipboard_timeout))
        except Exception as exc:
            self.status("copy failed: %s" % exc, 5.0)

    def open_resources(self, view: View) -> None:
        """Expose common read/list endpoints without automatically reading them."""
        endpoints: List[Tuple[str, str, str]] = []

        def add(method: str, path: str, read_prefix: str = "") -> None:
            endpoints.append((method, path.strip("/"), read_prefix))

        anchor = view
        if isinstance(view, AuthMethodsView):
            item = view.table.selected()
            if item:
                anchor = AuthDetailView(item["path"], item["type"])
        if isinstance(anchor, AuthDetailView):
            base = vault_join("auth", anchor.mount)
            add("READ", vault_join(base, "config"))
            add("READ", vault_join("sys/auth", anchor.mount, "tune"))
            collections = {
                "ldap": ("users", "groups"), "userpass": ("users",),
                "approle": ("role",), "jwt": ("role",), "oidc": ("role",),
                "kubernetes": ("role",), "cert": ("certs",), "aws": ("roles",),
                "azure": ("role",), "github": ("map/users", "map/teams"),
                "radius": ("users",), "token": ("roles",),
            }
            for path in collections.get(anchor.auth_type, ()):
                read_prefix = vault_join(base, "role") if anchor.auth_type == "aws" and path == "roles" else ""
                add("LIST", vault_join(base, path), read_prefix)
            if anchor.auth_type == "aws":
                for path in ("config/client", "config/identity"):
                    add("READ", vault_join(base, path))
        else:
            mount = getattr(view, "mount", "")
            typ = ""
            if isinstance(view, EnginesView):
                item = view.table.selected()
                if item:
                    mount, typ = item["path"], item["type"]
            candidates = [view] + list(reversed(self.stack))
            for candidate in candidates:
                for cls, engine_type in ((PKIView, "pki"), (TransitView, "transit"),
                                         (DatabaseView, "database"), (AWSView, "aws")):
                    if isinstance(candidate, cls):
                        typ = typ or engine_type
                        mount = mount or candidate.mount
            if mount:
                if not typ:
                    try:
                        typ = next((item["type"] for item in self.client.list_secret_engines() if item["path"] == mount), "")
                    except VaultError as exc:
                        self.status(str(exc), 5)
                add("READ", vault_join("sys/mounts", mount))
                add("READ", vault_join("sys/mounts", mount, "tune"))
                paths = {
                    "pki": (("LIST", "certs", "cert"), ("LIST", "roles", ""),
                            ("LIST", "issuers", "issuer"), ("LIST", "keys", "key"),
                            ("READ", "config/urls", ""), ("READ", "config/crl", ""),
                            ("READ", "config/cluster", ""), ("READ", "config/auto-tidy", "")),
                    "transit": (("LIST", "keys", ""), ("READ", "cache-config", "")),
                    "database": (("LIST", "config", ""), ("LIST", "roles", ""), ("LIST", "static-roles", "")),
                    "aws": (("LIST", "roles", ""), ("READ", "config/root", ""), ("READ", "config/lease", "")),
                    "kv": (("READ", "config", ""), ("LIST", "metadata", "data")),
                }
                for method, path, read_prefix in paths.get(typ, ()):
                    add(method, vault_join(mount, path), vault_join(mount, read_prefix) if read_prefix else "")
            elif self.active_tab == "3":
                for kind in ("acl", "rgp", "egp"):
                    add("LIST", "sys/policies/" + kind)
            elif self.active_tab == "4" or any(isinstance(candidate, IdentityView) for candidate in candidates):
                for path in ("entity/id", "group/id", "entity-alias/id", "group-alias/id", "oidc/key", "oidc/role", "oidc/assignment"):
                    add("LIST", "identity/" + path)
            elif self.active_tab == "2":
                add("READ", "sys/auth")
            else:
                for path in ("sys/health", "sys/seal-status", "sys/leader", "sys/ha-status",
                             "sys/mounts", "sys/auth", "sys/audit", "auth/token/lookup-self"):
                    add("READ", path)
        self.push(EndpointBrowserView(view.title, endpoints))

    def refresh_health(self) -> None:
        """Refresh header health status at most every 30 seconds."""
        if time.time() - self.health_checked_at < 30:
            return
        self.health_checked_at = time.time()
        try:
            self.health = self.client.health()
            self.health_error = ""
        except Exception as exc:
            self.health_error = str(exc)

    def run(self) -> None:
        """Run the curses UI."""
        self.renewer.start()
        try:
            curses.wrapper(self._run)
        finally:
            self.screen = None
            self.renewer.stop()

    def _run(self, stdscr: Any) -> None:
        self.screen = stdscr
        curses.curs_set(0)
        curses.noecho()
        curses.cbreak()
        stdscr.keypad(True)
        stdscr.timeout(500)
        self.theme.setup()
        self.push(DashboardView())
        while self.running:
            self.refresh_health()
            self.draw(stdscr)
            try:
                code = stdscr.get_wch()
            except curses.error:
                # get_wch reports the configured input timeout as curses.error.
                continue
            token = self.keys.token(code)
            self.handle_token(token)

    def draw(self, stdscr: Any) -> None:
        """Draw the full application frame."""
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        if width < 40 or height < 10:
            addstr_safe(stdscr, height // 2, 0, "Terminal too small; resize to at least 40x10", width, self.theme.pair(Theme.ERROR))
            stdscr.refresh()
            return

        tab_rows = self.tab_layout(width)
        header_h = 1 + len(tab_rows) + 1
        status_h = 1
        cmd_h = 1 if self.command_active else 0
        self.body_height = height - header_h - status_h - cmd_h
        self.body_width = width

        self.draw_header(stdscr, 0, width)
        self.draw_tabs(stdscr, 1, width, tab_rows)
        body_y = header_h
        if self.help_active:
            self.draw_help(stdscr, body_y, self.body_height, width)
        else:
            self.current().render(self, stdscr, body_y, self.body_height, width)
        if self.command_active:
            self.draw_command(stdscr, height - 2, width)
        self.draw_status(stdscr, height - 1, width)
        stdscr.refresh()

    def draw_header(self, win: Any, y: int, width: int) -> None:
        """Draw the top status header."""
        ns = self.client.namespace or "root"
        if self.health_error:
            status = "disconnected"
        elif self.health:
            status = "sealed" if self.health.get("sealed") else "unsealed"
        else:
            status = "connecting"
        version = self.health.get("version", "") if self.health else ""
        color = Theme.ERROR if self.health_error or status == "sealed" else Theme.OK if self.health else Theme.ACCENT
        addstr_safe(win, y, 0, "*", 1, self.theme.pair(color, curses.A_BOLD))
        text = " VaultUI | %s | ns: %s | %s" % (self.client.address, ns, status)
        if version:
            text += " | v" + str(version)
        addstr_safe(win, y, 1, text, width - 1, self.theme.pair(Theme.TITLE, curses.A_BOLD))

    def tab_layout(self, width: int) -> List[List[Tuple[str, str]]]:
        """Wrap whole tab labels to keep every shortcut visible."""
        rows: List[List[Tuple[str, str]]] = [[]]
        used = 0
        for key, label, _, _ in self.TABS:
            text = " [%s] %s " % (key, label)
            if rows[-1] and used + len(text) > width:
                rows.append([])
                used = 0
            rows[-1].append((key, text))
            used += len(text)
        return rows

    def draw_tabs(self, win: Any, y: int, width: int, rows: List[List[Tuple[str, str]]]) -> None:
        """Draw persistent numbered tabs above the current screen."""
        for row, tabs in enumerate(rows):
            x = 0
            for key, text in tabs:
                active = key == self.active_tab
                attr = self.theme.pair(Theme.TITLE, curses.A_BOLD | curses.A_REVERSE) if active else self.theme.pair(Theme.DIM)
                addstr_safe(win, y + row, x, text, min(len(text), width - x), attr)
                x += len(text)
        addstr_safe(win, y + len(rows), 0, "-" * width, width, self.theme.pair(Theme.DIM))

    def draw_command(self, win: Any, y: int, width: int) -> None:
        """Draw command palette input."""
        line = ":" + self.command_input + "_"
        if self.command_error:
            line += "  " + self.command_error
        else:
            matches = self.command_matches(self.command_input)
            if self.command_input and matches and matches[0] != self.command_input:
                line += "  tab: " + ", ".join(matches[:5])
        addstr_safe(win, y, 0, fit(line, width), width, self.theme.pair(Theme.ACCENT))

    def draw_status(self, win: Any, y: int, width: int) -> None:
        """Draw bottom key hints and transient status."""
        if self.status_text and time.time() <= self.status_until:
            text = self.status_text
        elif self.help_active:
            text = "esc/? close"
        else:
            hints = self.current().hints()
            common = "0-8 tabs  b resources  "
            if self.active_tab in ("5", "6", "7", "8"):
                common += "m mounts  "
            text = common + "  ".join("%s %s" % (key, desc) for key, desc in hints if key != "b")
        addstr_safe(win, y, 0, fit(text, width), width, self.theme.pair(Theme.STATUS))

    def draw_help(self, win: Any, y: int, height: int, width: int) -> None:
        """Draw the help overlay."""
        clear_area(win, y, 0, height, width)
        lines = [
            "Help",
            "",
            "General: q quit, ctrl+c force quit, ? help, : command, esc back",
            "Navigation: j/k or arrows, g/End, ctrl+d/ctrl+u, enter open",
            "Tabs: 0 overview, 1 secrets, 2 auth, 3 policies, 4 identity, 5 pki, 6 transit, 7 db, 8 aws",
            "Tabs remember their screen and selection; r refreshes the current view.",
            "Details: enter full value, c copy value, F4 copy JSON, F2/y complete JSON/YAML",
            "Resources: b API paths, m select PKI/Transit/Database/AWS mount, ! full error",
            "API: :read auth/ldap/config, :list auth/ldap/groups (exact Vault paths)",
            "Command palette: :secrets :auth :policies :identity :pki :transit :db :aws :token :ctx :dash :quit",
            "Path jump: :go mount/path",
            "",
            "Current view:",
        ]
        lines.extend("  %s - %s" % (key, desc) for key, desc in self.current().hints())
        for idx, line in enumerate(lines[:height]):
            attr = self.theme.pair(Theme.TITLE, curses.A_BOLD) if idx == 0 else 0
            addstr_safe(win, y + idx, 0, line, width, attr)

    def handle_token(self, token: str) -> None:
        """Dispatch a key token to command mode, global handlers, or current view.

        Args:
            token (str): Normalized key token from KeyMap.
            token (str): Нормализованный key token из KeyMap.

        Returns:
            None: Mutates application state or delegates to the current view.
            None: Меняет состояние приложения или делегирует текущему view.

        Raises:
            None: View-level errors are normally stored in view state.
            None: Ошибки view обычно сохраняются в состоянии view.
        """
        # EN: Global keys are handled before view keys to keep navigation consistent.
        # RU: Глобальные клавиши обрабатываются до view-клавиш для стабильной навигации.
        if token == "ctrl+c":
            self.running = False
            return
        if self.command_active:
            self.handle_command_key(token)
            return
        if not self.help_active:
            view = self.current()
            if isinstance(view, TableView) and view.filter_active:
                view.handle_key(self, token)
                return
        token = self.keys.shortcut(token)
        if self.help_active:
            if token in ("?", "esc") or self.keys.matches("back", token):
                self.help_active = False
            elif self.keys.matches("quit", token):
                self.running = False
            return
        if self.keys.matches("quit", token):
            self.running = False
            return
        if token == "?":
            self.help_active = True
            return
        if self.keys.matches("command", token):
            self.command_active = True
            self.command_input = ""
            self.command_error = ""
            return
        if token in tuple("012345678"):
            self.quick_jump(token)
            return
        if self.current().handle_key(self, token):
            return
        if token == "b":
            self.open_resources(self.current())
            return
        if token == "!" and self.current().error:
            self.push(TextView("Error / " + self.current().title, self.current().error))
            return
        if token == "m" and self.active_tab in ("5", "6", "7", "8"):
            self.push(MountSelectorView({"5": "pki", "6": "transit", "7": "database", "8": "aws"}[self.active_tab]))
            return
        if self.keys.matches("back", token):
            self.pop()

    def handle_command_key(self, token: str) -> None:
        """Edit or execute command palette input."""
        if token == "enter":
            self.execute_command(self.command_input.strip())
            return
        if token == "esc":
            self.command_active = False
            self.command_input = ""
            self.command_error = ""
            return
        if token == "backspace":
            self.command_input = self.command_input[:-1]
            self.command_error = ""
            return
        if token == "tab":
            matches = self.command_matches(self.command_input)
            if matches:
                self.command_input = matches[0]
            return
        if len(token) == 1 and token.isprintable():
            self.command_input += token
            self.command_error = ""

    def command_matches(self, prefix: str) -> List[str]:
        """Return command completion matches."""
        commands = [
            "auth",
            "aws",
            "ctx",
            "contexts",
            "dash",
            "dashboard",
            "db",
            "database",
            "identity",
            "pki",
            "policies",
            "quit",
            "secrets",
            "token",
            "transit",
            "go ",
            "read ",
            "list ",
        ]
        if not prefix:
            return commands
        lower = prefix.lower()
        starts = [cmd for cmd in commands if cmd.startswith(lower)]
        return starts or [cmd for cmd in commands if lower in cmd]

    def execute_command(self, command: str) -> None:
        """Execute a command palette command.

        Args:
            command (str): Command text without the leading colon.
            command (str): Текст команды без начального двоеточия.

        Returns:
            None: Navigates, quits, or reopens command mode with an error.
            None: Навигирует, завершает работу или снова открывает command mode с ошибкой.

        Raises:
            None: Errors are displayed inside the command palette.
            None: Ошибки отображаются внутри command palette.
        """
        # Commands open their destination; numeric tabs restore saved navigation.
        self.command_active = False
        self.command_input = ""
        self.command_error = ""
        try:
            if command in ("q", "quit"):
                self.running = False
            elif command in ("dash", "dashboard"):
                self.reset_to(DashboardView())
            elif command == "secrets":
                self.reset_to(EnginesView())
            elif command == "auth":
                self.reset_to(AuthMethodsView())
            elif command == "policies":
                self.reset_to(PoliciesView())
            elif command == "identity":
                self.reset_to(IdentityView())
            elif command == "pki":
                self.reset_to(PKIView("pki/"))
            elif command == "transit":
                self.reset_to(TransitView("transit/"))
            elif command in ("db", "database"):
                self.reset_to(DatabaseView("database/"))
            elif command == "aws":
                self.reset_to(AWSView("aws/"))
            elif command == "token":
                self.push(TokenInspectorView())
            elif command in ("ctx", "contexts"):
                self.reset_to(ContextsView())
            elif command.startswith("go "):
                self.go_to_path(command[3:].strip())
            elif command == "read" or command.startswith("read "):
                args = shlex.split(command[4:].strip())
                if not args:
                    raise VaultError("path required: read <Vault API path> [key=value ...]")
                params: Dict[str, Any] = {}
                for argument in args[1:]:
                    key, separator, value = argument.partition("=")
                    if not separator or not key:
                        raise VaultError("read parameters must use key=value")
                    params[key] = value
                self.push(APIReadView(args[0], params or None))
            elif command == "list" or command.startswith("list "):
                path = command[4:].strip()
                if not path:
                    raise VaultError("path required: list <Vault API path>")
                self.push(APIListView(path))
            else:
                self.command_active = True
                self.command_input = command
                self.command_error = "unknown command"
        except Exception as exc:
            self.command_active = True
            self.command_input = command
            self.command_error = str(exc)

    def quick_jump(self, token: str) -> None:
        """Switch tabs, loading on first use and preserving each view stack."""
        if token == self.active_tab and self.stack:
            return
        _, _, cls, args = next(tab for tab in self.TABS if tab[0] == token)
        self.tab_stacks[self.active_tab] = self.stack
        self.active_tab = token
        self.stack = self.tab_stacks.setdefault(token, [])
        if not self.stack:
            self.push(cls(*args))

    def go_to_path(self, full_path: str) -> None:
        """Jump to a Vault secret path."""
        if not full_path:
            raise VaultError("path required: go <mount/path>")
        engines = self.client.list_secret_engines()
        engine = longest_mount_match(full_path, engines)
        if not engine:
            raise VaultError("no engine found for path: %s" % full_path)
        mount = engine.get("path", "")
        sub_path = full_path[len(mount) :]
        kv_v2 = engine.get("version") == "v2"
        if not sub_path or sub_path.endswith("/"):
            self.reset_to(PathBrowserView(mount, sub_path, kv_v2))
        else:
            self.reset_to(SecretDetailView(mount, sub_path, kv_v2))

    def switch_context(self, ctx: Dict[str, Any]) -> None:
        """Switch to a configured Vault context.

        Args:
            ctx (Dict[str, Any]): Context entry from ~/.vaultui.yaml.
            ctx (Dict[str, Any]): Запись context из ~/.vaultui.yaml.

        Returns:
            None: Replaces client, saves current_context, and returns to dashboard.
            None: Меняет client, сохраняет current_context и возвращает dashboard.

        Raises:
            VaultError: If the new context cannot authenticate.
            VaultError: Если новый context не может пройти auth.
        """
        auth = ctx.get("auth") or {}
        client = VaultClient(
            address=ctx.get("address") or DEFAULT_VAULT_ADDR,
            token=ctx.get("token") or "",
            namespace=ctx.get("namespace") or "",
            insecure=self.config.insecure,
            timeout=self.config.timeout,
        )
        method = auth.get("method") or "token"
        if method != "token":
            client.authenticate(
                method,
                mount_path=auth.get("mount_path", ""),
                username=auth.get("username", ""),
                password=auth.get("password", ""),
                role_id=auth.get("role_id", ""),
                secret_id=auth.get("secret_id", ""),
                password_prompt=self.prompt_auth_password,
            )
        self.client = client
        self.config.raw_config["current_context"] = ctx.get("name", "")
        save_config(self.config.config_path, self.config.raw_config)
        self.health_checked_at = 0
        self.health = {}
        self.health_error = ""
        self.tab_stacks.clear()
        self.active_tab = "0"
        self.stack = []
        self.push(DashboardView())
        self.status("switched to context %s" % ctx.get("name", ""))

    def prompt_auth_password(self, method: str, username: str) -> str:
        """Temporarily suspend curses while getpass reads the new context password."""
        if self.screen is None:
            return prompt_auth_password(method, username)
        curses.def_prog_mode()
        curses.endwin()
        try:
            return prompt_auth_password(method, username)
        finally:
            curses.reset_prog_mode()
            curses.noecho()
            curses.curs_set(0)
            self.screen.clearok(True)


# ---------------------------------------------------------------------------
# Headless mode and CLI
# ---------------------------------------------------------------------------


def output_json(value: Any) -> None:
    """Print indented JSON to stdout.

    Args:
        value (Any): JSON-serializable value.
        value (Any): JSON-сериализуемое значение.

    Returns:
        None: Writes to stdout.
        None: Пишет в stdout.

    Raises:
        TypeError: If value cannot be serialized by json_default fallback.
        TypeError: Если value нельзя сериализовать даже через json_default fallback.
    """
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=json_default))


def headless_get(client: VaultClient, resource: str, path: str = "") -> None:
    """Implement the `get` subcommand for scripts.

    Args:
        client (VaultClient): Connected Vault client.
        resource (str): Resource name such as health, engines, secret, or policy.
        path (str): Optional secret path or policy name.
        client (VaultClient): Подключённый Vault client.
        resource (str): Имя ресурса, например health, engines, secret или policy.
        path (str): Необязательный secret path или policy name.

    Returns:
        None: Prints JSON to stdout.
        None: Печатает JSON в stdout.

    Raises:
        VaultError: On missing path, unknown resource, or Vault API failure.
        VaultError: При пустом path, неизвестном resource или ошибке Vault API.
    """
    if resource == "health":
        output_json(client.health())
    elif resource == "token":
        output_json(client.inspect_token())
    elif resource == "engines":
        output_json(client.list_secret_engines())
    elif resource == "auth":
        output_json(client.list_auth_methods())
    elif resource == "policies":
        output_json(client.list_policies())
    elif resource == "policy":
        if not path:
            raise VaultError("policy name required: vaultui-py.py get policy <name>")
        output_json({"name": path, "body": client.get_policy(path)})
    elif resource == "secret":
        if not path:
            raise VaultError("secret path required: vaultui-py.py get secret <mount/path>")
        engines = client.list_secret_engines()
        engine = longest_mount_match(path, engines)
        if not engine:
            raise VaultError("no secret engine found for path: %s" % path)
        mount = engine.get("path", "")
        sub_path = path[len(mount) :]
        output_json(client.read_secret(mount, sub_path, engine.get("version") == "v2"))
    else:
        raise VaultError("unknown resource: %s (try: health, engines, auth, policies, secret, policy, token)" % resource)


def add_global_args(parser: argparse.ArgumentParser, suppress_defaults: bool = False) -> None:
    """Add global CLI flags.

    Args:
        parser (argparse.ArgumentParser): Parser receiving shared flags.
        suppress_defaults (bool): Keep previously parsed global values in subcommands.
        parser (argparse.ArgumentParser): Parser, получающий общие флаги.

    Returns:
        None.
        Нет.
    """
    def add_argument(*flags: str, **kwargs: Any) -> None:
        if suppress_defaults:
            kwargs["default"] = argparse.SUPPRESS
        parser.add_argument(*flags, **kwargs)

    add_argument("--config", default="", help="config file (default $HOME/.vaultui.yaml)")
    add_argument("--context", default="", help="config context name")
    add_argument("--vault-addr", default=None, help="Vault server address")
    add_argument("--token", default=None, help="Vault authentication token")
    add_argument("--namespace", default=None, help="Vault namespace")
    add_argument("--auth-method", default=None, choices=["token", "userpass", "ldap", "approle"], help="Auth method")
    add_argument("--auth-mount", default=None, help="Custom auth mount path")
    add_argument("--username", default=None, help="Username for userpass or LDAP auth")
    add_argument("--password", default=None, help="Password for userpass or LDAP auth (prompted if omitted)")
    add_argument("--role-id", default=None, help="Role ID for AppRole auth")
    add_argument("--secret-id", default=None, help="Secret ID for AppRole auth")
    add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Args:
        None.
        Нет.

    Returns:
        argparse.ArgumentParser: Parser for TUI mode, version, and get subcommand.
        argparse.ArgumentParser: Parser для TUI mode, version и get subcommand.
    """
    parent = argparse.ArgumentParser(add_help=False)
    add_global_args(parent)
    parser = argparse.ArgumentParser(
        prog="vaultui-py.py",
        description="A k9s-inspired TUI for HashiCorp Vault, implemented as one Python file.",
        parents=[parent],
    )
    parser.add_argument("--version", action="store_true", help="show version and exit")
    sub = parser.add_subparsers(dest="subcommand")
    get = sub.add_parser("get", help="get Vault resources as JSON")
    add_global_args(get, suppress_defaults=True)
    get.add_argument("resource", help="health, engines, auth, policies, secret, policy, token")
    get.add_argument("path", nargs="?", default="", help="secret path or policy name")
    get.add_argument("-o", "--output", default="json", choices=["json"], help="output format")
    return parser


def make_client(config: RuntimeConfig) -> VaultClient:
    """Create and authenticate a Vault client from resolved config.

    Args:
        config (RuntimeConfig): Final runtime settings.
        config (RuntimeConfig): Итоговые runtime-настройки.

    Returns:
        VaultClient: Client ready for TUI or headless use.
        VaultClient: Client, готовый для TUI или headless режима.

    Raises:
        VaultError: If configured non-token authentication fails.
        VaultError: Если настроенная non-token authentication завершается ошибкой.
    """
    client = VaultClient(
        config.address,
        token=config.token,
        namespace=config.namespace,
        insecure=config.insecure,
        timeout=config.timeout,
    )
    if config.auth_method and config.auth_method != "token":
        client.authenticate(
            config.auth_method,
            mount_path=config.auth_mount,
            username=config.username,
            password=config.password,
            role_id=config.role_id,
            secret_id=config.secret_id,
        )
    return client


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Program entry point.

    Args:
        argv (Optional[Sequence[str]]): Optional argument vector for tests.
        argv (Optional[Sequence[str]]): Необязательный список аргументов для тестов.

    Returns:
        int: Process exit code; 0 on success, 1 on handled error, 130 on Ctrl+C.
        int: Код выхода процесса; 0 успех, 1 обработанная ошибка, 130 Ctrl+C.

    Raises:
        None: Errors are caught and reported to stderr.
        None: Ошибки перехватываются и выводятся в stderr.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print("%s %s" % (APP_NAME, __VERSION__))
        return 0
    try:
        config = resolve_runtime_config(args)
        client = make_client(config)
        if args.subcommand == "get":
            headless_get(client, args.resource, args.path)
            return 0
        VaultTUI(client, config).run()
        return 0
    except KeyboardInterrupt:
        return 130
    except VaultError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    except Exception as exc:
        print("Error: %s" % exc, file=sys.stderr)
        if os.environ.get("VAULTUI_DEBUG"):
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
