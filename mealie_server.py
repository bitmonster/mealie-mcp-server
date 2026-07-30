#!/usr/bin/env python3
"""Security-conscious MCP server for a self-hosted Mealie instance.

Configuration via environment variables:
- MEALIE_BASE_URL, default: http://127.0.0.1:9000
- MEALIE_API_TOKEN, preferred: Mealie long-live API token from /user/profile/api-tokens
- MEALIE_USERNAME + MEALIE_PASSWORD, optional fallback for local testing
- MEALIE_MCP_ALLOW_MUTATIONS=true, optional: enable create/update/delete tools
- MEALIE_MCP_MUTATION_SCOPE, comma-separated least-privilege write scopes

The server writes no secrets to stdout. stdout is reserved for MCP JSON-RPC.
"""

from __future__ import annotations

import json
import mimetypes
import ipaddress
import os
from pathlib import Path
import posixpath
import re
import socket
import stat
import sys
import time

import urllib.error
import urllib.parse
import urllib.request
import uuid
from io import BytesIO
from typing import Any

import pytesseract
from PIL import Image, ImageOps, ImageEnhance, ImageFilter
import get_chefkoch
import get_chefkoch.chefkoch as _chefkoch_impl

from mcp.server.fastmcp import FastMCP


def _validate_mealie_base_url(url: str) -> str:
    """Require a credential-free Mealie origin; remote plaintext HTTP is unsafe."""
    parsed = urllib.parse.urlsplit(str(url).strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("MEALIE_BASE_URL muss eine vollständige HTTP(S)-URL sein.")
    if parsed.username or parsed.password:
        raise RuntimeError("MEALIE_BASE_URL darf keine eingebetteten Zugangsdaten enthalten.")
    if parsed.query or parsed.fragment:
        raise RuntimeError("MEALIE_BASE_URL darf weder Query noch Fragment enthalten.")
    if parsed.scheme == "http":
        host = parsed.hostname.lower()
        is_loopback = host == "localhost"
        try:
            is_loopback = is_loopback or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if not is_loopback:
            raise RuntimeError("Entfernte Mealie-Instanzen müssen HTTPS verwenden.")
    return urllib.parse.urlunsplit(parsed).rstrip("/")


mcp = FastMCP("mealie")

BASE_URL = _validate_mealie_base_url(
    os.environ.get("MEALIE_BASE_URL", "http://127.0.0.1:9000")
)
PUBLIC_URL = os.environ.get("MEALIE_PUBLIC_URL", BASE_URL).rstrip("/")
API_TOKEN = os.environ.get("MEALIE_API_TOKEN", "").strip()
USERNAME = os.environ.get("MEALIE_USERNAME", "").strip()
PASSWORD = os.environ.get("MEALIE_PASSWORD", "")
ALLOW_MUTATIONS = os.environ.get("MEALIE_MCP_ALLOW_MUTATIONS", "").lower() in {"1", "true", "yes", "on"}
ALLOW_REMOTE_SOURCES = os.environ.get(
    "MEALIE_MCP_ALLOW_REMOTE_SOURCES", "false"
).strip().lower() in {"1", "true", "yes", "on"}
ALLOW_URL_IMPORTS = os.environ.get(
    "MEALIE_MCP_ALLOW_URL_IMPORTS", "false"
).strip().lower() in {"1", "true", "yes", "on"}
MUTATION_SCOPE = os.environ.get("MEALIE_MCP_MUTATION_SCOPE", "none").strip().lower() or "none"
TIMEOUT = float(os.environ.get("MEALIE_MCP_TIMEOUT", "30"))
DATA_DIR = Path(
    os.environ.get("MEALIE_MCP_DATA_DIR", "~/.cache/mealie-mcp")
).expanduser()
DOWNLOAD_DIR = Path(
    os.environ.get("MEALIE_MCP_DOWNLOAD_DIR", str(DATA_DIR / "downloads"))
).expanduser()
MAX_DOWNLOAD_BYTES = int(
    os.environ.get("MEALIE_MCP_MAX_DOWNLOAD_BYTES", str(100 * 1024 * 1024))
)
MAX_JSON_BYTES = int(
    os.environ.get("MEALIE_MCP_MAX_JSON_BYTES", str(10 * 1024 * 1024))
)
MAX_OPENAPI_BYTES = int(
    os.environ.get("MEALIE_MCP_MAX_OPENAPI_BYTES", str(20 * 1024 * 1024))
)
MAX_SOURCE_BYTES = 25 * 1024 * 1024
MAX_MULTIPART_BYTES = 50 * 1024 * 1024
MAX_IMAGE_PIXELS = int(os.environ.get("MEALIE_MCP_MAX_IMAGE_PIXELS", "40000000"))
OCR_TIMEOUT = float(os.environ.get("MEALIE_MCP_OCR_TIMEOUT", "60"))
MAX_OCR_TEXT_CHARS = int(
    os.environ.get("MEALIE_MCP_MAX_OCR_TEXT_CHARS", "100000")
)
MAX_CHEFKOCH_BYTES = int(
    os.environ.get("MEALIE_MCP_MAX_CHEFKOCH_BYTES", str(5 * 1024 * 1024))
)
_CHEFKOCH_ORIGINAL_GET = _chefkoch_impl.requests.get
_configured_local_roots = tuple(
    Path(part).expanduser()
    for part in os.environ.get("MEALIE_MCP_ALLOWED_LOCAL_ROOTS", "").split(os.pathsep)
    if part.strip()
)
ALLOWED_LOCAL_SOURCE_ROOTS = tuple(
    path.resolve(strict=False)
    for path in (
        DATA_DIR / "imports",
        DOWNLOAD_DIR,
        *_configured_local_roots,
    )
)

_access_token: str | None = None
_access_token_obtained_at = 0.0
_openapi_cache: dict[str, Any] | None = None
_openapi_cache_obtained_at = 0.0

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_SENSITIVE_PATH_PREFIXES = (
    "/api/admin",
    "/api/auth",
    "/api/users",
    "/api/groups",
    "/api/households/invitations",
    "/api/households/webhooks",
    "/api/households/events",
    "/api/households/members",
    "/api/households/permissions",
    "/api/households/preferences",
    "/api/households/self",
    "/api/households/statistics",
)
_SENSITIVE_TAG_PREFIXES = (
    "Admin:",
    "Users:",
    "Groups:",
    "Households: Invitations",
    "Households: Webhooks",
    "Households: Event Notifications",
    "Households: Self Service",
)


def _get_openapi_spec(force_refresh: bool = False) -> dict[str, Any]:
    """Load and briefly cache the live Mealie OpenAPI document."""
    global _openapi_cache, _openapi_cache_obtained_at
    if (
        not force_refresh
        and _openapi_cache is not None
        and time.time() - _openapi_cache_obtained_at < 300
    ):
        return _openapi_cache

    request = urllib.request.Request(
        BASE_URL + "/openapi.json",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with _open_mealie_request(request) as response:
            loaded = json.loads(
                _read_bounded_response(response, MAX_OPENAPI_BYTES, "OpenAPI").decode("utf-8")
            )
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Mealie OpenAPI konnte nicht geladen werden: {_redact(str(exc))}") from exc
    if not isinstance(loaded, dict) or not isinstance(loaded.get("paths"), dict):
        raise RuntimeError("Mealie lieferte kein gültiges OpenAPI-Dokument.")
    _openapi_cache = loaded
    _openapi_cache_obtained_at = time.time()
    return loaded


def _security_normalize_api_path(path: str) -> str:
    """Return a repeatedly decoded, normalized path for fail-closed policy checks."""
    raw = str(path).strip()
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise RuntimeError("API-Pfad muss ein reiner lokaler /api/…-Pfad sein.")
    decoded = parsed.path if parsed.path.startswith("/") else "/" + parsed.path
    for _ in range(3):
        next_value = urllib.parse.unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if "\x00" in decoded:
        raise RuntimeError("API-Pfad enthält ein unzulässiges Nullbyte.")
    decoded = decoded.replace("\\", "/")
    return posixpath.normpath(decoded)


def _is_sensitive_operation(path: str, tags: list[str] | tuple[str, ...] | None = None) -> bool:
    try:
        clean_path = _security_normalize_api_path(path)
    except RuntimeError:
        return True
    if clean_path != "/api" and not clean_path.startswith("/api/"):
        return True
    if any(
        clean_path == prefix or clean_path.startswith(prefix + "/")
        for prefix in _SENSITIVE_PATH_PREFIXES
    ):
        return True
    return any(
        str(tag).startswith(prefix)
        for tag in (tags or [])
        for prefix in _SENSITIVE_TAG_PREFIXES
    )


def _iter_openapi_operations(spec: dict[str, Any]):
    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        path_parameters = [
            item for item in (path_item.get("parameters") or []) if isinstance(item, dict)
        ]
        for method, operation in path_item.items():
            method_upper = str(method).upper()
            if method_upper not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            operation_id = str(operation.get("operationId") or "").strip()
            if operation_id:
                merged_operation = dict(operation)
                merged: dict[tuple[str, str], dict[str, Any]] = {}
                for parameter in [
                    *path_parameters,
                    *[
                        item
                        for item in (operation.get("parameters") or [])
                        if isinstance(item, dict)
                    ],
                ]:
                    key = (str(parameter.get("name")), str(parameter.get("in")))
                    merged[key] = parameter
                if merged:
                    merged_operation["parameters"] = list(merged.values())
                yield method_upper, str(path), operation_id, merged_operation


def _find_openapi_operation(operation_id: str) -> tuple[str, str, dict[str, Any]]:
    wanted = operation_id.strip()
    if not wanted:
        raise RuntimeError("operation_id darf nicht leer sein.")
    for method, path, candidate_id, operation in _iter_openapi_operations(
        _get_openapi_spec()
    ):
        if candidate_id == wanted:
            return method, path, operation
    raise RuntimeError(f"Unbekannte Mealie-OpenAPI-Operation: {wanted}")


def _openapi_path_matches(template: str, path: str) -> bool:
    """Match a normalized concrete API path against an OpenAPI path template."""
    pattern = re.escape(_security_normalize_api_path(template))
    pattern = re.sub(r"\\\{[^{}]+\\\}", r"[^/]+", pattern)
    return re.fullmatch(pattern, path) is not None


def _validate_raw_api_operation(method: str, path: str) -> str:
    """Resolve a raw request against live OpenAPI and apply tag-aware policy."""
    clean_path = _security_normalize_api_path(path)
    if _is_sensitive_operation(clean_path):
        raise RuntimeError("Sensible Admin/Auth/User-API-Pfade sind blockiert.")
    for candidate_method, template, _operation_id, operation in _iter_openapi_operations(
        _get_openapi_spec()
    ):
        if candidate_method == method and _openapi_path_matches(template, clean_path):
            if _is_sensitive_operation(clean_path, operation.get("tags") or []):
                raise RuntimeError("Sensible Mealie-OpenAPI-Operation ist blockiert.")
            return clean_path
    raise RuntimeError(
        f"Raw-API-Pfad ist für {method} nicht in der Live-OpenAPI bekannt und wird fail-closed blockiert: {clean_path}"
    )


def _resolve_openapi_path(
    path_template: str,
    path_params: dict[str, Any] | None,
) -> str:
    supplied = path_params or {}
    required = set(re.findall(r"\{([^{}]+)\}", path_template))
    missing = sorted(required - set(supplied))
    if missing:
        raise RuntimeError("Fehlende OpenAPI-Pfadparameter: " + ", ".join(missing))
    extra = sorted(set(supplied) - required)
    if extra:
        raise RuntimeError("Unbekannte OpenAPI-Pfadparameter: " + ", ".join(extra))
    path = path_template
    for name in required:
        value = urllib.parse.quote(str(supplied[name]), safe="")
        path = path.replace("{" + name + "}", value)
    return path


def _resolve_openapi_schema(schema: dict[str, Any]) -> dict[str, Any]:
    current = schema
    seen: set[str] = set()
    while isinstance(current, dict) and "$ref" in current:
        reference = str(current["$ref"])
        if reference in seen or not reference.startswith("#/components/schemas/"):
            break
        seen.add(reference)
        name = reference.rsplit("/", 1)[-1]
        resolved = (
            _get_openapi_spec().get("components", {}).get("schemas", {}).get(name)
        )
        if not isinstance(resolved, dict):
            break
        current = resolved
    return current if isinstance(current, dict) else {}


def _validate_openapi_request(
    operation: dict[str, Any],
    *,
    query_params: dict[str, Any] | None,
    body: dict[str, Any] | list[Any] | None,
    content_type: str,
) -> None:
    supplied_query = {
        str(key): value
        for key, value in (query_params or {}).items()
        if value is not None and value != ""
    }
    required_query = sorted(
        str(parameter.get("name"))
        for parameter in (operation.get("parameters") or [])
        if isinstance(parameter, dict)
        and parameter.get("in") == "query"
        and parameter.get("required")
        and str(parameter.get("name")) not in supplied_query
    )
    if required_query:
        raise RuntimeError(
            "Fehlende OpenAPI-Queryparameter: " + ", ".join(required_query)
        )
    unsupported_required = sorted(
        f"{parameter.get('in')}:{parameter.get('name')}"
        for parameter in (operation.get("parameters") or [])
        if isinstance(parameter, dict)
        and parameter.get("required")
        and parameter.get("in") in {"header", "cookie"}
    )
    if unsupported_required:
        raise RuntimeError(
            "Nicht unterstützte erforderliche OpenAPI-Parameter: "
            + ", ".join(unsupported_required)
        )

    request_body = operation.get("requestBody") or {}
    content = request_body.get("content") or {}
    media = content.get(content_type) or {}
    if request_body.get("required") and body is None:
        raise RuntimeError("Der OpenAPI-Request-Body ist erforderlich.")
    if body is None or not isinstance(media, dict):
        return
    schema = _resolve_openapi_schema(media.get("schema") or {})
    schema_type = schema.get("type")
    if schema_type == "object" and not isinstance(body, dict):
        raise RuntimeError("Der OpenAPI-Request-Body muss ein Objekt sein.")
    if schema_type == "array" and not isinstance(body, list):
        raise RuntimeError("Der OpenAPI-Request-Body muss eine Liste sein.")
    if isinstance(body, dict):
        required_fields = set(str(item) for item in (schema.get("required") or []))
        allowed_fields = set(str(item) for item in (schema.get("properties") or {}))
        for branch in schema.get("allOf") or []:
            resolved_branch = _resolve_openapi_schema(branch) if isinstance(branch, dict) else {}
            required_fields.update(str(item) for item in (resolved_branch.get("required") or []))
            allowed_fields.update(
                str(item) for item in (resolved_branch.get("properties") or {})
            )
        missing = sorted(
            field
            for field in required_fields
            if field not in body or body[field] is None
        )
        if missing:
            raise RuntimeError(
                "Fehlende erforderliche OpenAPI-Body-Felder: " + ", ".join(missing)
            )
        unknown = sorted(set(body) - allowed_fields) if allowed_fields else []
        if unknown:
            raise RuntimeError(
                "Unbekannte OpenAPI-Body-Felder werden fail-closed blockiert: "
                + ", ".join(unknown)
            )


def _redact(text: str) -> str:
    for secret in (API_TOKEN, PASSWORD, _access_token or ""):
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def _ensure_plausible_token(token: str) -> None:
    # A Mealie token is normally a JWT-like bearer token. A URL is definitely not a token.
    if token.startswith("http://") or token.startswith("https://"):
        raise RuntimeError("MEALIE_API_TOKEN sieht wie eine URL aus, nicht wie ein Mealie API Token.")


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward Mealie credentials through HTTP redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise RuntimeError(
            f"Mealie-Redirect blockiert ({code}): {urllib.parse.urlsplit(newurl).path or '/'}"
        )


_MEALIE_OPENER = urllib.request.build_opener(_RejectRedirectHandler())


def _open_mealie_request(request: urllib.request.Request):
    return _MEALIE_OPENER.open(request, timeout=TIMEOUT)


def _read_bounded_response(response: Any, limit: int, label: str) -> bytes:
    content = response.read(limit + 1)
    if len(content) > limit:
        raise RuntimeError(f"{label}-Antwort überschreitet das Größenlimit von {limit} Bytes.")
    return content


def _read_http_error_payload(error: urllib.error.HTTPError, limit: int = 8192) -> str:
    """Read a bounded HTTP error body without reflecting unlimited upstream data."""
    return error.read(limit + 1)[:limit].decode("utf-8", errors="replace")


def _json_request(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | list[Any] | None = None,
    auth: bool = True,
    form: dict[str, Any] | None = None,
) -> Any:
    if not path.startswith("/"):
        path = "/" + path
    if not path.startswith("/api/"):
        raise RuntimeError("Nur Mealie API-Pfade unter /api/ sind erlaubt.")

    query = ""
    if params:
        clean_params: dict[str, Any] = {}
        for key, value in params.items():
            if value is None or value == "":
                continue
            clean_params[key] = value
        if clean_params:
            query = "?" + urllib.parse.urlencode(clean_params, doseq=True)

    url = BASE_URL + path + query
    headers = {"Accept": "application/json"}
    data: bytes | None = None

    if auth:
        token = _get_token()
        headers["Authorization"] = f"Bearer {token}"

    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with _open_mealie_request(req) as resp:
            raw = _read_bounded_response(resp, MAX_JSON_BYTES, "JSON").decode(
                "utf-8", errors="replace"
            )
            if not raw:
                return {"status": resp.status, "ok": 200 <= resp.status < 300}
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {"status": resp.status, "text": raw}
    except urllib.error.HTTPError as exc:
        payload = _read_http_error_payload(exc)
        raise RuntimeError(_redact(f"Mealie HTTP {exc.code} for {method} {path}: {payload}")) from exc
    except Exception as exc:
        raise RuntimeError(_redact(f"Mealie request failed for {method} {path}: {exc}")) from exc


def _safe_multipart_header_value(value: Any, label: str, *, field_name: bool = False) -> str:
    text = str(value)
    if any(char in text for char in ("\r", "\n", "\x00")):
        raise RuntimeError(f"Ungültiger Multipart-{label}: Steuerzeichen sind nicht erlaubt.")
    if field_name and not re.fullmatch(r"[A-Za-z0-9_.\[\]-]{1,128}", text):
        raise RuntimeError(f"Ungültiger Multipart-{label}: {text!r}")
    return text.replace("\\", "\\\\").replace('"', "\\\"")


def _multipart_field_bytes(value: Any) -> bytes:
    if isinstance(value, bool):
        return ("true" if value else "false").encode("utf-8")
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return str(value).encode("utf-8")


def _multipart_request(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    fields: dict[str, Any] | None = None,
    files: dict[str, tuple[str, bytes, str]] | None = None,
    auth: bool = True,
) -> Any:
    if not path.startswith("/"):
        path = "/" + path
    if not path.startswith("/api/"):
        raise RuntimeError("Nur Mealie API-Pfade unter /api/ sind erlaubt.")

    boundary = "----hermes-mealie-" + uuid.uuid4().hex
    body = bytearray()
    fields = fields or {}
    files = files or {}
    payload_size = 0

    for name, value in fields.items():
        if value is None:
            continue
        safe_name = _safe_multipart_header_value(name, "Feldname", field_name=True)
        value_bytes = _multipart_field_bytes(value)
        payload_size += len(value_bytes)
        if payload_size > MAX_MULTIPART_BYTES:
            raise RuntimeError(
                f"Multipart-Nutzdaten überschreiten das Limit von {MAX_MULTIPART_BYTES} Bytes."
            )
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(
            f'Content-Disposition: form-data; name="{safe_name}"\r\n\r\n'.encode()
        )
        body.extend(value_bytes)
        body.extend(b"\r\n")

    for name, (filename, content, content_type) in files.items():
        safe_name = _safe_multipart_header_value(name, "Feldname", field_name=True)
        safe_filename = _safe_multipart_header_value(
            Path(str(filename)).name, "Dateiname"
        )
        safe_content_type = _safe_multipart_header_value(
            content_type or "application/octet-stream", "Content-Type"
        )
        if not re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+", safe_content_type):
            raise RuntimeError(f"Ungültiger Multipart-Content-Type: {safe_content_type!r}")
        if len(content) > MAX_SOURCE_BYTES:
            raise RuntimeError(
                f"Multipart-Datei überschreitet das Limit von {MAX_SOURCE_BYTES} Bytes."
            )
        payload_size += len(content)
        if payload_size > MAX_MULTIPART_BYTES:
            raise RuntimeError(
                f"Multipart-Nutzdaten überschreiten das Limit von {MAX_MULTIPART_BYTES} Bytes."
            )
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(
            f'Content-Disposition: form-data; name="{safe_name}"; filename="{safe_filename}"\r\n'.encode()
        )
        body.extend(f"Content-Type: {safe_content_type}\r\n\r\n".encode())
        body.extend(content)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    if len(body) > MAX_MULTIPART_BYTES:
        raise RuntimeError(
            f"Multipart-Request überschreitet das Limit von {MAX_MULTIPART_BYTES} Bytes."
        )

    headers = {"Accept": "application/json", "Content-Type": f"multipart/form-data; boundary={boundary}"}
    if auth:
        headers["Authorization"] = f"Bearer {_get_token()}"
    clean_params = {
        key: value
        for key, value in (params or {}).items()
        if value is not None and value != ""
    }
    query = "?" + urllib.parse.urlencode(clean_params, doseq=True) if clean_params else ""
    req = urllib.request.Request(
        BASE_URL + path + query,
        data=bytes(body),
        headers=headers,
        method=method.upper(),
    )
    try:
        with _open_mealie_request(req) as resp:
            raw = _read_bounded_response(resp, MAX_JSON_BYTES, "JSON").decode(
                "utf-8", errors="replace"
            )
            if not raw:
                return {"status": resp.status, "ok": 200 <= resp.status < 300}
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {"status": resp.status, "text": raw}
    except urllib.error.HTTPError as exc:
        payload = _read_http_error_payload(exc)
        raise RuntimeError(_redact(f"Mealie HTTP {exc.code} for {method} {path}: {payload}")) from exc
    except Exception as exc:
        raise RuntimeError(_redact(f"Mealie multipart request failed for {method} {path}: {exc}")) from exc


def _download_api_binary(
    path: str,
    *,
    params: dict[str, Any] | None = None,
) -> tuple[str, bytes, str]:
    if not path.startswith("/api/"):
        raise RuntimeError("Nur Mealie API-Pfade unter /api/ sind erlaubt.")
    clean_params = {
        key: value
        for key, value in (params or {}).items()
        if value is not None and value != ""
    }
    query = "?" + urllib.parse.urlencode(clean_params, doseq=True) if clean_params else ""
    request = urllib.request.Request(
        BASE_URL + path + query,
        headers={
            "Accept": "*/*",
            "Authorization": f"Bearer {_get_token()}",
        },
        method="GET",
    )
    try:
        with _open_mealie_request(request) as response:
            content = response.read(MAX_DOWNLOAD_BYTES + 1)
            if len(content) > MAX_DOWNLOAD_BYTES:
                raise RuntimeError(
                    f"Mealie-Download überschreitet das Limit von {MAX_DOWNLOAD_BYTES} Bytes."
                )
            content_type = response.headers.get_content_type() or "application/octet-stream"
            disposition = response.headers.get("Content-Disposition", "")
            filename_match = re.search(
                r"filename\*?=(?:UTF-8''|\")?([^\";]+)", disposition, re.IGNORECASE
            )
            filename = (
                urllib.parse.unquote(filename_match.group(1).strip())
                if filename_match
                else Path(urllib.parse.urlparse(path).path).name or "mealie-download.bin"
            )
            return filename, content, content_type
    except urllib.error.HTTPError as exc:
        payload = _read_http_error_payload(exc, 2000)
        raise RuntimeError(
            _redact(f"Mealie HTTP {exc.code} for GET {path}: {payload}")
        ) from exc
    except Exception as exc:
        if isinstance(exc, RuntimeError):
            raise
        raise RuntimeError(
            _redact(f"Mealie binary download failed for GET {path}: {exc}")
        ) from exc


def _validate_remote_source_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("Nur vollständige öffentliche HTTP(S)-Quellen sind erlaubt.")
    if parsed.username or parsed.password:
        raise RuntimeError("HTTP(S)-Quellen mit eingebetteten Zugangsdaten sind nicht erlaubt.")
    try:
        addresses = socket.getaddrinfo(
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise RuntimeError(f"Host der Bildquelle konnte nicht aufgelöst werden: {parsed.hostname}") from exc
    if not addresses:
        raise RuntimeError(f"Host der Bildquelle lieferte keine Adresse: {parsed.hostname}")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0].split("%", 1)[0])
        if not ip.is_global:
            raise RuntimeError(
                "HTTP(S)-Quellen in private oder lokale Netze sind nicht erlaubt."
            )
    return urllib.parse.urlunsplit(parsed)


class _SafeSourceRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        safe_url = _validate_remote_source_url(urllib.parse.urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, safe_url)


def _is_allowed_local_source(path: Path) -> bool:
    return any(path.is_relative_to(root.resolve(strict=False)) for root in ALLOWED_LOCAL_SOURCE_ROOTS)


def _open_local_source_descriptor(path: Path) -> int:
    """Open a source beneath an allowed root via no-follow directory descriptors."""
    root = next(
        (
            candidate.resolve(strict=True)
            for candidate in ALLOWED_LOCAL_SOURCE_ROOTS
            if path.is_relative_to(candidate.resolve(strict=False))
        ),
        None,
    )
    if root is None:
        raise RuntimeError(
            "Lokale Bildquelle liegt außerhalb der freigegebenen Import-Verzeichnisse."
        )
    relative_parts = path.relative_to(root).parts
    if not relative_parts:
        raise RuntimeError("Lokale Bildquelle ist keine reguläre Datei.")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(root, directory_flags | no_follow)
    try:
        for part in relative_parts[:-1]:
            next_fd = os.open(
                part,
                directory_flags | no_follow,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(
            relative_parts[-1],
            os.O_RDONLY | no_follow,
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)


def _read_binary_source(source: str) -> tuple[str, bytes, str]:
    """Read a bounded file from approved local roots or a public HTTP(S) URL."""
    if not source:
        raise RuntimeError("Leere Bildquelle übergeben.")
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        if not ALLOW_REMOTE_SOURCES:
            raise RuntimeError(
                "Remote-Dateiquellen sind deaktiviert; setze MEALIE_MCP_ALLOW_REMOTE_SOURCES=true bewusst."
            )
        safe_url = _validate_remote_source_url(source)
        opener = urllib.request.build_opener(_SafeSourceRedirectHandler())
        request = urllib.request.Request(
            safe_url,
            headers={"User-Agent": "Hermes-Mealie-MCP/1.0", "Accept": "*/*"},
        )
        with opener.open(request, timeout=TIMEOUT) as resp:
            content_length = resp.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > MAX_SOURCE_BYTES:
                        raise RuntimeError(
                            f"Bildquelle überschreitet das Größenlimit von {MAX_SOURCE_BYTES} Bytes."
                        )
                except ValueError:
                    pass
            content = resp.read(MAX_SOURCE_BYTES + 1)
            if len(content) > MAX_SOURCE_BYTES:
                raise RuntimeError(
                    f"Bildquelle überschreitet das Größenlimit von {MAX_SOURCE_BYTES} Bytes."
                )
            content_type = resp.headers.get_content_type() or "application/octet-stream"
        filename = Path(urllib.parse.urlsplit(safe_url).path).name or "image"
    else:
        if parsed.scheme not in {"", "file"}:
            raise RuntimeError(f"Nicht unterstütztes Quellschema: {parsed.scheme}")
        if parsed.scheme == "file" and parsed.netloc not in {"", "localhost"}:
            raise RuntimeError("file://-Quellen mit Hostnamen sind nicht erlaubt.")
        raw_path = urllib.request.url2pathname(parsed.path) if parsed.scheme == "file" else source
        path = Path(raw_path).expanduser()
        try:
            resolved = path.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise RuntimeError(f"Bildquelle nicht gefunden: {source}") from exc
        if not resolved.is_file():
            raise RuntimeError(f"Bildquelle nicht gefunden: {source}")
        if not _is_allowed_local_source(resolved):
            raise RuntimeError(
                "Lokale Bildquelle liegt außerhalb der freigegebenen Import-Verzeichnisse."
            )
        descriptor = _open_local_source_descriptor(resolved)
        try:
            source_stat = os.fstat(descriptor)
            if not stat.S_ISREG(source_stat.st_mode):
                raise RuntimeError("Lokale Bildquelle ist keine reguläre Datei.")
            if source_stat.st_size > MAX_SOURCE_BYTES:
                raise RuntimeError(
                    f"Bildquelle überschreitet das Größenlimit von {MAX_SOURCE_BYTES} Bytes."
                )
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                content = handle.read(MAX_SOURCE_BYTES + 1)
            if len(content) > MAX_SOURCE_BYTES:
                raise RuntimeError(
                    f"Bildquelle überschreitet das Größenlimit von {MAX_SOURCE_BYTES} Bytes."
                )
        finally:
            os.close(descriptor)
        filename = resolved.name or "image"
        content_type = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
    return filename, content, content_type


def _extension_from_filename(filename: str, content_type: str = "") -> str:
    suffix = Path(filename).suffix.lower().lstrip(".")
    if suffix in {"jpg", "jpeg", "png", "webp", "gif"}:
        return "jpg" if suffix == "jpeg" else suffix
    guessed = mimetypes.guess_extension(content_type or "") or ".jpg"
    return guessed.lower().lstrip(".").replace("jpeg", "jpg") or "jpg"


def _normalize_crop_box(
    crop_box: list[float] | tuple[float, ...] | None,
    crop_units: str,
    image_width: int,
    image_height: int,
) -> tuple[int, int, int, int]:
    """Return a clamped pixel crop box from [left, top, right, bottom].

    `crop_units` may be:
    - percent: values 0..100; values 0..1 are also accepted as fractions.
    - fraction: values 0..1.
    - pixels: raw pixel coordinates.
    """
    if not crop_box or len(crop_box) != 4:
        raise RuntimeError("cover_crop_box muss vier Werte enthalten: [left, top, right, bottom].")

    try:
        left, top, right, bottom = [float(v) for v in crop_box]
    except (TypeError, ValueError) as exc:
        raise RuntimeError("cover_crop_box enthält keine gültigen Zahlen.") from exc

    units = (crop_units or "percent").strip().lower()
    values = [left, top, right, bottom]
    if units in {"percent", "%"}:
        # Be forgiving: [0.10, 0.15, 0.85, 0.90] is likely fractional input.
        factor = 1.0 if all(0 <= v <= 1 for v in values) else 100.0
        left = left / factor * image_width
        right = right / factor * image_width
        top = top / factor * image_height
        bottom = bottom / factor * image_height
    elif units in {"fraction", "ratio", "normalized", "normalised"}:
        left = left * image_width
        right = right * image_width
        top = top * image_height
        bottom = bottom * image_height
    elif units in {"pixel", "pixels", "px"}:
        pass
    else:
        raise RuntimeError("cover_crop_units muss 'percent', 'fraction' oder 'pixels' sein.")

    left_px = max(0, min(image_width, int(round(left))))
    top_px = max(0, min(image_height, int(round(top))))
    right_px = max(0, min(image_width, int(round(right))))
    bottom_px = max(0, min(image_height, int(round(bottom))))
    if right_px <= left_px or bottom_px <= top_px:
        raise RuntimeError(
            "Ungültiger Bildausschnitt nach Normalisierung: "
            f"{(left_px, top_px, right_px, bottom_px)} bei Bildgröße {(image_width, image_height)}."
        )
    if (right_px - left_px) < 64 or (bottom_px - top_px) < 64:
        raise RuntimeError(
            f"Bildausschnitt ist zu klein: {(right_px - left_px)}x{(bottom_px - top_px)} px. "
            "Wähle einen größeren Titelbild-Ausschnitt."
        )
    return left_px, top_px, right_px, bottom_px


def _crop_image_for_cover(
    filename: str,
    content: bytes,
    content_type: str,
    crop_box: list[float] | tuple[float, ...],
    crop_units: str,
) -> tuple[str, bytes, str, dict[str, Any]]:
    """Crop image bytes and return a JPEG suitable for Mealie's recipe cover."""
    try:
        with Image.open(BytesIO(content)) as image:
            image = ImageOps.exif_transpose(image)
            width, height = image.size
            if width * height > MAX_IMAGE_PIXELS:
                raise RuntimeError(
                    f"Bild überschreitet das Pixellimit von {MAX_IMAGE_PIXELS}."
                )
            pixel_box = _normalize_crop_box(crop_box, crop_units, width, height)
            cropped = image.crop(pixel_box)
            if cropped.mode not in {"RGB", "L"}:
                cropped = cropped.convert("RGB")
            elif cropped.mode == "L":
                cropped = cropped.convert("RGB")
            out = BytesIO()
            cropped.save(out, format="JPEG", quality=90, optimize=True)
            stem = Path(filename).stem or "cover"
            return (
                f"{stem}-cover-crop.jpg",
                out.getvalue(),
                "image/jpeg",
                {
                    "source_filename": filename,
                    "source_content_type": content_type,
                    "source_size": [width, height],
                    "crop_box_pixels": list(pixel_box),
                    "crop_size": [pixel_box[2] - pixel_box[0], pixel_box[3] - pixel_box[1]],
                    "crop_units": crop_units or "percent",
                },
            )
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Bild konnte nicht zugeschnitten werden: {exc}") from exc


# ---------------------------------------------------------------------------
# OCR helpers
# ---------------------------------------------------------------------------

_OCR_LANG = "deu+eng"
_OCR_CONFIG = "--psm 4 --oem 3"


def _preprocess_for_ocr(image_bytes: bytes) -> Image.Image:
    """Preprocess an image for better OCR results."""
    with Image.open(BytesIO(image_bytes)) as img:
        img = ImageOps.exif_transpose(img)
        if img.width * img.height > MAX_IMAGE_PIXELS:
            raise RuntimeError(f"Bild überschreitet das Pixellimit von {MAX_IMAGE_PIXELS}.")
        # Grayscale
        if img.mode not in {"L", "1"}:
            img = img.convert("L")
        # Increase contrast
        enhancer = ImageEnhance.Contrast(img)
        img = enhancer.enhance(1.8)
        # Adaptive threshold via sharpen
        img = img.filter(ImageFilter.SHARPEN)
        img = img.filter(ImageFilter.UnsharpMask(radius=1, percent=150, threshold=2))
        # Binarize (simple threshold at 160/255)
        img = img.point(lambda x: 255 if x > 160 else 0, mode="1")
        return img


def _ocr_extract_text(image_bytes: bytes, lang: str = _OCR_LANG) -> dict[str, Any]:
    """Run Tesseract OCR on image bytes and return extracted text + metadata."""
    processed = _preprocess_for_ocr(image_bytes)
    config = _OCR_CONFIG

    try:
        raw_text = pytesseract.image_to_string(
            processed, lang=lang, config=config, timeout=OCR_TIMEOUT
        )
        raw_text = raw_text[:MAX_OCR_TEXT_CHARS]
        data = pytesseract.image_to_data(
            processed,
            lang=lang,
            config=config,
            output_type=pytesseract.Output.DICT,
            timeout=OCR_TIMEOUT,
        )

        # Calculate a rough confidence over non-empty words
        confidences = [
            int(conf)
            for conf, text in zip(data.get("conf", []), data.get("text", []))
            if text.strip() and isinstance(conf, (int, float)) and conf >= 0
        ]
        avg_conf = round(sum(confidences) / len(confidences), 1) if confidences else 0.0

        word_count = len([t for t in data.get("text", []) if t.strip()])
        line_count = len([line for line in raw_text.splitlines() if line.strip()])

        return {
            "raw_text": raw_text.strip(),
            "word_count": word_count,
            "line_count": line_count,
            "avg_confidence": avg_conf,
            "ocr_lang": lang,
            "ocr_engine": "tesseract-5.5.0",
        }
    except Exception as exc:
        # Fallback: try without preprocessing
        try:
            with Image.open(BytesIO(image_bytes)) as img:
                if img.width * img.height > MAX_IMAGE_PIXELS:
                    raise RuntimeError(
                        f"Bild überschreitet das Pixellimit von {MAX_IMAGE_PIXELS}."
                    )
                raw_text = pytesseract.image_to_string(
                    img, lang=lang, timeout=OCR_TIMEOUT
                )
                raw_text = raw_text[:MAX_OCR_TEXT_CHARS]
                return {
                    "raw_text": raw_text.strip(),
                    "word_count": len(raw_text.split()),
                    "line_count": len(
                        [line for line in raw_text.splitlines() if line.strip()]
                    ),
                    "avg_confidence": 0.0,
                    "ocr_lang": lang,
                    "ocr_engine": "tesseract-5.5.0 (fallback)",
                    "fallback_message": str(exc),
                }
        except Exception as fallback_exc:
            raise RuntimeError(f"OCR fehlgeschlagen: {exc} (fallback: {fallback_exc})") from exc


# ---------------------------------------------------------------------------


def _items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        value = payload.get("items") or payload.get("data") or []
        return value if isinstance(value, list) else []
    return payload if isinstance(payload, list) else []


def _resolve_ingredient_reference(
    value: Any,
    endpoint: str,
    label: str,
) -> dict[str, Any] | None:
    """Return a complete Mealie food/unit object containing its database id."""
    if value is None:
        return None

    if isinstance(value, dict):
        if value.get("id"):
            return dict(value)
        name = str(value.get("name") or value.get("abbreviation") or "").strip()
    elif isinstance(value, str):
        name = value.strip()
    else:
        raise RuntimeError(f"{label} hat ein nicht unterstütztes Format: {type(value).__name__}")

    if not name:
        raise RuntimeError(f"{label} enthält weder eine ID noch einen Namen.")

    candidates = _items(
        _json_request(
            "GET",
            endpoint,
            params={"page": 1, "perPage": 100, "search": name},
        )
    )
    wanted = name.casefold()
    for candidate in candidates:
        aliases = (
            candidate.get("name"),
            candidate.get("pluralName"),
            candidate.get("abbreviation"),
        )
        if candidate.get("id") and any(
            isinstance(alias, str) and alias.casefold() == wanted for alias in aliases
        ):
            return candidate

    raise RuntimeError(
        f"{label} '{name}' wurde in Mealie nicht mit einer gültigen ID gefunden."
    )


def _slug_from_create_response(response: Any, name: str) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        for key in ("slug", "recipeSlug", "id"):
            value = response.get(key)
            if value:
                return str(value)
    found = _items(mealie_search_recipes(search=name, per_page=10))
    for recipe in found:
        if str(recipe.get("name", "")).casefold() == name.casefold() and recipe.get("slug"):
            return str(recipe["slug"])
    raise RuntimeError("Mealie-Rezept wurde angelegt, aber kein Slug konnte bestimmt werden.")


def _ensure_tag(name: str) -> dict[str, Any] | None:
    tag_name = (name or "").strip()
    if not tag_name:
        return None
    existing = _items(_json_request("GET", "/api/organizers/tags", params={"page": 1, "perPage": 1000}))
    for tag in existing:
        if str(tag.get("name", "")).casefold() == tag_name.casefold():
            return tag
    return _json_request("POST", "/api/organizers/tags", body={"name": tag_name})


def _get_token() -> str:
    global _access_token, _access_token_obtained_at

    if API_TOKEN:
        _ensure_plausible_token(API_TOKEN)
        return API_TOKEN

    # Short-lived login fallback. Refresh every 30 minutes; Mealie usually grants longer.
    if _access_token and time.time() - _access_token_obtained_at < 1800:
        return _access_token

    if not USERNAME or not PASSWORD:
        raise RuntimeError(
            "Mealie credentials fehlen. Setze MEALIE_API_TOKEN oder MEALIE_USERNAME + MEALIE_PASSWORD."
        )

    result = _json_request(
        "POST",
        "/api/auth/token",
        auth=False,
        form={"username": USERNAME, "password": PASSWORD},
    )
    token = result.get("access_token") if isinstance(result, dict) else None
    if not token:
        raise RuntimeError("Mealie Login lieferte keinen access_token.")
    _access_token = str(token)
    _access_token_obtained_at = time.time()
    return _access_token


def _mutation_allowed_by_scope(method: str, path: str) -> bool:
    scope_list = [s.strip() for s in MUTATION_SCOPE.replace(",", " ").split() if s.strip()]
    if not scope_list or scope_list == ["none"]:
        return False
    if "all" in scope_list:
        return True

    method = method.upper()
    clean_path = path if path.startswith("/") else "/" + path

    # --- recipe_import / recipes ---
    if any(s in scope_list for s in ("recipes", "recipe", "recipe_import")):
        if method == "POST" and clean_path in {
            "/api/recipes",
            "/api/recipes/create/url",
            "/api/recipes/create/image",
            "/api/recipes/create/zip",
            "/api/recipes/create/html-or-json",
            "/api/organizers/tags",
        }:
            return True
        if method == "PATCH" and re.fullmatch(r"/api/recipes/[^/]+", clean_path):
            return True
        if method == "PUT" and re.fullmatch(r"/api/recipes/[^/]+/image", clean_path):
            return True
        if method == "POST" and re.fullmatch(
            r"/api/recipes/[^/]+/(assets|duplicate)", clean_path
        ):
            return True
        if method == "PATCH" and re.fullmatch(
            r"/api/recipes/[^/]+/last-made", clean_path
        ):
            return True
        if method == "DELETE" and re.fullmatch(
            r"/api/recipes/[^/]+/image", clean_path
        ):
            return True

    # Ingredient parsing is part of an approved recipe-import workflow. The
    # parser only resolves text against Mealie's foods/units; recipe changes
    # still require the separately scoped PATCH above.
    if "recipe_import" in scope_list:
        if method == "POST" and clean_path in {
            "/api/parser/ingredient",
            "/api/parser/ingredients",
        }:
            return True

    # --- shopping ---
    if "shopping" in scope_list:
        if method == "POST" and clean_path in {
            "/api/households/shopping/lists",
            "/api/households/shopping/items",
            "/api/households/shopping/items/create-bulk",
        }:
            return True
        if method in ("PUT", "DELETE") and re.fullmatch(
            r"/api/households/shopping/items(?:/[^/]+)?", clean_path
        ):
            return True
        if method in ("PUT", "DELETE") and re.fullmatch(
            r"/api/households/shopping/lists/[^/]+", clean_path
        ):
            return True
        if method == "PUT" and re.fullmatch(
            r"/api/households/shopping/lists/[^/]+/label-settings", clean_path
        ):
            return True
        if method == "POST" and re.fullmatch(
            r"/api/households/shopping/lists/[^/]+/recipe(?:/[^/]+(?:/delete)?)?",
            clean_path,
        ):
            return True

    # --- mealplan ---
    if "mealplan" in scope_list:
        if method == "POST" and clean_path in {
            "/api/households/mealplans",
            "/api/households/mealplans/random",
            "/api/households/mealplans/rules",
        }:
            return True
        if method in ("PUT", "DELETE") and re.fullmatch(
            r"/api/households/mealplans/(?:[^/]+|rules/[^/]+)", clean_path
        ):
            return True

    # Optional write scopes remain disabled unless explicitly configured.
    optional_scope_prefixes = {
        "organizers": ("/api/organizers/categories", "/api/organizers/tags", "/api/foods", "/api/units"),
        "cookbooks": ("/api/households/cookbooks",),
        "comments": ("/api/comments",),
        "timeline": ("/api/recipes/timeline/events",),
        "recipe_actions": ("/api/households/recipe-actions",),
    }
    for scope_name, prefixes in optional_scope_prefixes.items():
        if scope_name in scope_list and any(
            clean_path == prefix or clean_path.startswith(prefix + "/")
            for prefix in prefixes
        ):
            return method in {"POST", "PUT", "PATCH", "DELETE"}

    # --- parser ---
    if "parser" in scope_list:
        if method == "POST" and clean_path in {
            "/api/parser/ingredient",
            "/api/parser/ingredients",
        }:
            return True

    return False


def _require_mutations(path: str = "", method: str = "POST") -> None:
    if not ALLOW_MUTATIONS:
        raise RuntimeError(
            "Schreibende Mealie-Aktionen sind deaktiviert. Setze MEALIE_MCP_ALLOW_MUTATIONS=true, wenn gewünscht."
        )
    if path and not _mutation_allowed_by_scope(method, path):
        raise RuntimeError(
            f"Schreibende Mealie-Aktion außerhalb des erlaubten Scopes ({MUTATION_SCOPE}) blockiert: {method} {path}"
        )


def _require_user_confirmation(confirmed_by_user: bool) -> None:
    if not confirmed_by_user:
        raise RuntimeError(
            "Schreibende Aktion blockiert: Es fehlt die explizite Bestätigung des Benutzers."
        )


def _pagination_params(
    page: int = 1,
    per_page: int = 10,
    order_by: str | None = None,
    order_direction: str = "asc",
    query_filter: str | None = None,
) -> dict[str, Any]:
    if page < 1:
        raise RuntimeError("page muss mindestens 1 sein.")
    if per_page < 1 or per_page > 200:
        raise RuntimeError("per_page muss zwischen 1 und 200 liegen.")
    if order_direction not in {"asc", "desc"}:
        raise RuntimeError("order_direction muss 'asc' oder 'desc' sein.")
    return {
        "page": page,
        "perPage": per_page,
        "orderBy": order_by,
        "orderDirection": order_direction,
        "queryFilter": query_filter,
    }


@mcp.tool()
def mealie_about() -> dict[str, Any]:
    """Return public Mealie app/version information."""
    return _json_request("GET", "/api/app/about", auth=False)


@mcp.tool()
def mealie_status() -> dict[str, Any]:
    """Check server reachability and whether authentication works."""
    about = _json_request("GET", "/api/app/about", auth=False)
    user = _json_request("GET", "/api/users/self")
    return {
        "base_url": BASE_URL,
        "mutations_enabled": ALLOW_MUTATIONS,
        "about": about,
        "authentication": {
            "authenticated": isinstance(user, dict),
            "admin": bool(user.get("admin")) if isinstance(user, dict) else False,
        },
    }


@mcp.tool()
def mealie_search_recipes(
    search: str = "",
    query_filter: str | None = None,
    page: int = 1,
    per_page: int = 10,
    order_by: str = "name",
    order_direction: str = "asc",
) -> dict[str, Any]:
    """Search Mealie recipes. Supports Mealie queryFilter syntax for advanced filters."""
    params = _pagination_params(page, per_page, order_by, order_direction, query_filter)
    params["search"] = search or None
    return _json_request("GET", "/api/recipes", params=params)


@mcp.tool()
def mealie_get_recipe(slug_or_id: str) -> dict[str, Any]:
    """Fetch one recipe by slug or id."""
    safe_slug = urllib.parse.quote(slug_or_id, safe="")
    return _json_request("GET", f"/api/recipes/{safe_slug}")


@mcp.tool()
def mealie_recipe_suggestions(limit: int = 10) -> Any:
    """Return Mealie recipe suggestions."""
    return _json_request("GET", "/api/recipes/suggestions", params={"limit": limit})


@mcp.tool()
def mealie_list_shopping_lists(page: int = 1, per_page: int = 20) -> dict[str, Any]:
    """List household shopping lists."""
    return _json_request(
        "GET",
        "/api/households/shopping/lists",
        params=_pagination_params(page, per_page, "name", "asc"),
    )


@mcp.tool()
def mealie_list_shopping_items(
    shopping_list_id: str | None = None,
    checked: bool | None = None,
    page: int = 1,
    per_page: int = 50,
) -> dict[str, Any]:
    """List shopping list items, optionally filtered by shopping list and checked state."""
    filters: list[str] = []
    if shopping_list_id:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", shopping_list_id):
            raise RuntimeError("shopping_list_id enthält unzulässige Zeichen.")
        filters.append(f'shoppingListId = "{shopping_list_id}"')
    if checked is not None:
        filters.append(f"checked = {str(checked).lower()}")
    query_filter = " AND ".join(filters) if filters else None
    return _json_request(
        "GET",
        "/api/households/shopping/items",
        params=_pagination_params(page, per_page, "position", "asc", query_filter),
    )


@mcp.tool()
def mealie_list_mealplans(
    start_date: str | None = None,
    end_date: str | None = None,
    page: int = 1,
    per_page: int = 30,
) -> dict[str, Any]:
    """List household meal plans. Dates are ISO yyyy-mm-dd strings."""
    params = _pagination_params(page, per_page, "date", "asc")
    params["start_date"] = start_date
    params["end_date"] = end_date
    return _json_request("GET", "/api/households/mealplans", params=params)


@mcp.tool()
def mealie_create_recipe_from_url(
    url: str,
    include_tags: bool = True,
    include_categories: bool = True,
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Import/create a recipe from a public web URL after explicit confirmation."""
    _require_user_confirmation(confirmed_by_user)
    if not ALLOW_URL_IMPORTS:
        raise RuntimeError(
            "URL-Importe sind deaktiviert; setze MEALIE_MCP_ALLOW_URL_IMPORTS=true bewusst."
        )
    safe_url = _validate_remote_source_url(url)
    _require_mutations("/api/recipes/create/url", "POST")
    result = _json_request(
        "POST",
        "/api/recipes/create/url",
        body={
            "url": safe_url,
            "includeTags": include_tags,
            "includeCategories": include_categories,
        },
    )
    # Mealie v3 returns the created slug as a JSON string. FastMCP validates
    # this tool's declared dict return type, so normalize the successful reply.
    if isinstance(result, str):
        slug = result.strip()
        if not slug:
            raise RuntimeError("Mealie meldete Erfolg, lieferte aber keinen Rezept-Slug.")
        safe_slug = urllib.parse.quote(slug, safe="")
        return {
            "success": True,
            "slug": slug,
            "url": f"{PUBLIC_URL}/g/home/r/{safe_slug}",
        }
    if isinstance(result, dict):
        return result
    raise RuntimeError(
        f"Mealie lieferte ein unerwartetes Importformat: {type(result).__name__}"
    )


@mcp.tool()
def mealie_create_shopping_list(
    name: str,
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Create a shopping list after explicit user confirmation."""
    _require_user_confirmation(confirmed_by_user)
    _require_mutations("/api/households/shopping/lists", "POST")
    return _json_request("POST", "/api/households/shopping/lists", body={"name": name})


@mcp.tool()
def mealie_add_shopping_item(
    shopping_list_id: str,
    display: str,
    quantity: float = 1,
    note: str = "",
    checked: bool = False,
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Add an item to a shopping list after explicit user confirmation."""
    _require_user_confirmation(confirmed_by_user)
    _require_mutations("/api/households/shopping/items", "POST")
    return _json_request(
        "POST",
        "/api/households/shopping/items",
        body={
            "shoppingListId": shopping_list_id,
            "display": display,
            "quantity": quantity,
            "note": note,
            "checked": checked,
        },
    )


@mcp.tool()
def mealie_get_shopping_list(shopping_list_id: str) -> dict[str, Any]:
    """Fetch one household shopping list by id."""
    safe_id = urllib.parse.quote(shopping_list_id, safe="")
    return _json_request("GET", f"/api/households/shopping/lists/{safe_id}")


@mcp.tool()
def mealie_get_shopping_item(item_id: str) -> dict[str, Any]:
    """Fetch one household shopping list item by id."""
    safe_id = urllib.parse.quote(item_id, safe="")
    return _json_request("GET", f"/api/households/shopping/items/{safe_id}")


@mcp.tool()
def mealie_update_shopping_item(
    item_id: str,
    updates: dict[str, Any],
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Update a shopping item using Mealie v3's full-model PUT endpoint."""
    _require_user_confirmation(confirmed_by_user)
    safe_id = urllib.parse.quote(item_id, safe="")
    path = f"/api/households/shopping/items/{safe_id}"
    current = _json_request("GET", path)
    if not isinstance(current, dict):
        raise RuntimeError("Mealie lieferte kein gültiges Einkaufslisten-Element.")
    allowed = {
        "quantity",
        "unit",
        "food",
        "referencedRecipe",
        "note",
        "display",
        "shoppingListId",
        "checked",
        "position",
        "foodId",
        "labelId",
        "unitId",
        "extras",
        "recipeReferences",
    }
    unknown = sorted(set(updates) - allowed)
    if unknown:
        raise RuntimeError("Unbekannte Shopping-Update-Felder: " + ", ".join(unknown))
    body = {key: value for key, value in current.items() if key in allowed}
    body.update(updates)
    if not body.get("shoppingListId"):
        raise RuntimeError("shoppingListId fehlt im vollständigen Update-Modell.")
    _require_mutations(path, "PUT")
    result = _json_request("PUT", path, body=body)
    if not isinstance(result, dict):
        raise RuntimeError("Mealie lieferte kein gültiges aktualisiertes Einkaufslisten-Element.")
    return result


@mcp.tool()
def mealie_delete_shopping_item(
    item_id: str,
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Delete one shopping list item after explicit confirmation."""
    _require_user_confirmation(confirmed_by_user)
    safe_id = urllib.parse.quote(item_id, safe="")
    path = f"/api/households/shopping/items/{safe_id}"
    _require_mutations(path, "DELETE")
    result = _json_request("DELETE", path)
    return {"deleted": True, "item_id": item_id, "response": result}


@mcp.tool()
def mealie_add_recipe_to_shopping_list(
    shopping_list_id: str,
    recipe_id: str,
    recipe_increment_quantity: float = 1,
    confirmed_by_user: bool = False,
) -> Any:
    """Add a recipe's ingredients to a shopping list using Mealie v3."""
    _require_user_confirmation(confirmed_by_user)
    safe_list_id = urllib.parse.quote(shopping_list_id, safe="")
    safe_recipe_id = urllib.parse.quote(recipe_id, safe="")
    path = (
        f"/api/households/shopping/lists/{safe_list_id}/recipe/{safe_recipe_id}"
    )
    _require_mutations(path, "POST")
    return _json_request(
        "POST",
        path,
        body={"recipeIncrementQuantity": recipe_increment_quantity},
    )


@mcp.tool()
def mealie_get_todays_meals() -> Any:
    """Fetch today's household meal plan entries."""
    return _json_request("GET", "/api/households/mealplans/today")


@mcp.tool()
def mealie_create_mealplan(
    date: str,
    entry_type: str = "dinner",
    title: str = "",
    text: str = "",
    recipe_id: str | None = None,
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Create a household mealplan entry. Date must be ISO yyyy-mm-dd."""
    _require_user_confirmation(confirmed_by_user)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise RuntimeError("Mealplan-Datum muss das Format yyyy-mm-dd haben.")
    path = "/api/households/mealplans"
    body = {
        "date": date,
        "entryType": entry_type,
        "title": title,
        "text": text,
        "recipeId": recipe_id,
    }
    _require_mutations(path, "POST")
    result = _json_request("POST", path, body=body)
    if not isinstance(result, dict):
        raise RuntimeError("Mealie lieferte keinen gültigen Mealplan-Eintrag.")
    return result


@mcp.tool()
def mealie_update_mealplan(
    item_id: int,
    updates: dict[str, Any],
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Update a mealplan entry using Mealie v3's full-model PUT endpoint."""
    _require_user_confirmation(confirmed_by_user)
    path = f"/api/households/mealplans/{int(item_id)}"
    current = _json_request("GET", path)
    if not isinstance(current, dict):
        raise RuntimeError("Mealie lieferte keinen gültigen Mealplan-Eintrag.")
    allowed = {"date", "entryType", "title", "text", "recipeId", "id", "groupId", "userId"}
    unknown = sorted(set(updates) - allowed)
    if unknown:
        raise RuntimeError("Unbekannte Mealplan-Update-Felder: " + ", ".join(unknown))
    body = {key: value for key, value in current.items() if key in allowed}
    body.update(updates)
    missing = [key for key in ("date", "id", "groupId", "userId") if body.get(key) is None]
    if missing:
        raise RuntimeError("Pflichtfelder fehlen im Mealplan-Update: " + ", ".join(missing))
    _require_mutations(path, "PUT")
    result = _json_request("PUT", path, body=body)
    if not isinstance(result, dict):
        raise RuntimeError("Mealie lieferte keinen gültigen aktualisierten Mealplan-Eintrag.")
    return result


@mcp.tool()
def mealie_delete_mealplan(
    item_id: int,
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Delete a mealplan entry after explicit confirmation."""
    _require_user_confirmation(confirmed_by_user)
    path = f"/api/households/mealplans/{int(item_id)}"
    _require_mutations(path, "DELETE")
    result = _json_request("DELETE", path)
    return {"deleted": True, "item_id": item_id, "response": result}


@mcp.tool()
def mealie_create_recipe_from_text(
    name: str,
    ingredients: list[str],
    instructions: list[str],
    confirmed_by_user: bool = False,
    servings: float | None = None,
    recipe_yield: str | None = None,
    description: str = "",
    tags: list[str] | None = None,
    prep_time: str | None = None,
    cook_time: str | None = None,
    total_time: str | None = None,
    source_note: str = "Imported from a cookbook photo or screenshot via Mealie MCP.",
    main_image_url: str | None = None,
    source_image_url: str | None = None,
    cover_crop_box: list[float] | None = None,
    cover_crop_units: str = "percent",
    cover_crop_source_url: str | None = None,
    source_asset_name: str = "Original-Kochbuchfoto",
    overwrite_existing: bool = False,
) -> dict[str, Any]:
    """Create a Mealie recipe from OCR/vision-extracted text and optional images.

    Requires mutations enabled AND confirmed_by_user=True. Use this after showing
    the user a preview of title, ingredients, steps, tags, and asking for explicit
    confirmation. Ingredient lines are stored in display and note so Mealie mobile
    renders them correctly.

    For cookbook/photo imports, the agent may choose a title-image crop itself:
    pass `cover_crop_box=[left, top, right, bottom]` with `cover_crop_units="percent"`
    (default, 0..100; fractional 0..1 is accepted too) or `"pixels"`. The crop is
    taken from `cover_crop_source_url`, otherwise `main_image_url`, otherwise
    `source_image_url`, and uploaded as the Mealie recipe cover. The full
    `source_image_url` can still be uploaded as the original cookbook asset.
    """
    _require_user_confirmation(confirmed_by_user)
    _require_mutations("/api/recipes", "POST")

    recipe_name = (name or "").strip()
    ingredient_lines = [str(line).strip() for line in (ingredients or []) if str(line).strip()]
    step_lines = [str(line).strip() for line in (instructions or []) if str(line).strip()]
    if not recipe_name:
        raise RuntimeError("Rezeptname fehlt.")
    if not ingredient_lines:
        raise RuntimeError("Zutatenliste fehlt.")
    if not step_lines:
        raise RuntimeError("Zubereitungsschritte fehlen.")

    slug: str | None = None
    created = False
    existing = _items(mealie_search_recipes(search=recipe_name, per_page=10))
    for recipe in existing:
        if str(recipe.get("name", "")).casefold() == recipe_name.casefold() and recipe.get("slug"):
            slug = str(recipe["slug"])
            break

    if slug and not overwrite_existing:
        return {
            "created": False,
            "updated": False,
            "exists": True,
            "slug": slug,
            "url": f"{PUBLIC_URL}/g/home/r/{slug}",
            "message": "Ein Rezept mit diesem Namen existiert bereits; ohne overwrite_existing wurde nichts geändert.",
        }

    if not slug:
        create_response = _json_request("POST", "/api/recipes", body={"name": recipe_name})
        slug = _slug_from_create_response(create_response, recipe_name)
        created = True

    safe_slug = urllib.parse.quote(slug, safe="")
    recipe_obj = _json_request("GET", f"/api/recipes/{safe_slug}")
    if not isinstance(recipe_obj, dict):
        raise RuntimeError("Mealie lieferte beim Rezeptabruf kein Objekt.")

    tag_names = [str(tag).strip() for tag in (tags or []) if str(tag).strip()]
    for default_tag in ("Kochbuch", "Import"):
        if default_tag.casefold() not in {t.casefold() for t in tag_names}:
            tag_names.append(default_tag)
    tag_objects = [tag for tag in (_ensure_tag(tag_name) for tag_name in tag_names) if isinstance(tag, dict)]

    description_parts = []
    if description.strip():
        description_parts.append(description.strip())
    if source_note.strip():
        description_parts.append("Quelle/Hinweis: " + source_note.strip())
    recipe_obj["name"] = recipe_name
    recipe_obj["description"] = "\n\n".join(description_parts)
    if servings is not None:
        recipe_obj["recipeServings"] = servings
    if recipe_yield:
        recipe_obj["recipeYield"] = recipe_yield
    elif servings is not None:
        recipe_obj["recipeYield"] = f"{servings:g} Portionen"
    if prep_time:
        recipe_obj["prepTime"] = prep_time
    if cook_time:
        recipe_obj["cookTime"] = cook_time
    if total_time:
        recipe_obj["totalTime"] = total_time

    recipe_obj["recipeIngredient"] = [
        {
            "quantity": 0,
            "unit": None,
            "food": None,
            "note": line,
            "display": line,
            "title": None,
            "originalText": None,
            "referenceId": str(uuid.uuid4()),
        }
        for line in ingredient_lines
    ]
    recipe_obj["recipeInstructions"] = [
        {"title": "", "summary": "", "text": step, "ingredientReferences": []}
        for step in step_lines
    ]
    recipe_obj["tags"] = tag_objects
    settings = recipe_obj.get("settings") if isinstance(recipe_obj.get("settings"), dict) else {}
    settings["showAssets"] = True
    recipe_obj["settings"] = settings

    _require_mutations(f"/api/recipes/{safe_slug}", "PATCH")
    _json_request("PATCH", f"/api/recipes/{safe_slug}", body=recipe_obj)

    image_uploaded = False
    asset_uploaded = False
    cover_crop_applied = False
    cover_crop_info: dict[str, Any] | None = None
    warnings: list[str] = []

    if cover_crop_box:
        cover_source = cover_crop_source_url or main_image_url or source_image_url
        if not cover_source:
            warnings.append(
                "Titelbild-Ausschnitt wurde angefragt, aber keine Bildquelle übergeben "
                "(cover_crop_source_url, main_image_url oder source_image_url)."
            )
        else:
            try:
                filename, content, content_type = _read_binary_source(cover_source)
                filename, content, content_type, cover_crop_info = _crop_image_for_cover(
                    filename,
                    content,
                    content_type,
                    cover_crop_box,
                    cover_crop_units,
                )
                extension = _extension_from_filename(filename, content_type)
                _require_mutations(f"/api/recipes/{safe_slug}/image", "PUT")
                _multipart_request(
                    "PUT",
                    f"/api/recipes/{safe_slug}/image",
                    fields={"extension": extension},
                    files={"image": (filename, content, content_type)},
                )
                image_uploaded = True
                cover_crop_applied = True
            except Exception as exc:
                warnings.append(_redact(f"Titelbild-Ausschnitt konnte nicht erzeugt/hochgeladen werden: {exc}"))

    if not image_uploaded and main_image_url:
        try:
            filename, content, content_type = _read_binary_source(main_image_url)
            extension = _extension_from_filename(filename, content_type)
            _require_mutations(f"/api/recipes/{safe_slug}/image", "PUT")
            _multipart_request(
                "PUT",
                f"/api/recipes/{safe_slug}/image",
                fields={"extension": extension},
                files={"image": (filename, content, content_type)},
            )
            image_uploaded = True
        except Exception as exc:
            warnings.append(_redact(f"Hauptbild konnte nicht hochgeladen werden: {exc}"))

    if source_image_url:
        try:
            filename, content, content_type = _read_binary_source(source_image_url)
            extension = _extension_from_filename(filename, content_type)
            _require_mutations(f"/api/recipes/{safe_slug}/assets", "POST")
            _multipart_request(
                "POST",
                f"/api/recipes/{safe_slug}/assets",
                fields={
                    "name": source_asset_name or "Original-Kochbuchfoto",
                    "icon": "mdi-book-open-page-variant",
                    "extension": extension,
                },
                files={"file": (filename, content, content_type)},
            )
            asset_uploaded = True
        except Exception as exc:
            warnings.append(_redact(f"Originalfoto-Asset konnte nicht hochgeladen werden: {exc}"))

    verified = _json_request("GET", f"/api/recipes/{safe_slug}")
    verified_ingredients = verified.get("recipeIngredient", []) if isinstance(verified, dict) else []
    verified_steps = verified.get("recipeInstructions", []) if isinstance(verified, dict) else []
    empty_ingredient_displays = sum(
        1 for ingredient in verified_ingredients if isinstance(ingredient, dict) and not ingredient.get("display")
    )

    return {
        "created": created,
        "updated": not created,
        "exists": False,
        "slug": slug,
        "url": f"{PUBLIC_URL}/g/home/r/{slug}",
        "ingredient_count": len(verified_ingredients),
        "instruction_count": len(verified_steps),
        "empty_ingredient_displays": empty_ingredient_displays,
        "tags": [tag.get("name") for tag in tag_objects if isinstance(tag, dict)],
        "image_uploaded": image_uploaded,
        "cover_crop_applied": cover_crop_applied,
        "cover_crop_info": cover_crop_info,
        "asset_uploaded": asset_uploaded,
        "warnings": warnings,
    }


@mcp.tool()
def mealie_update_recipe_image(
    slug_or_id: str,
    image_source: str,
    confirmed_by_user: bool = False,
    crop_box: list[float] | None = None,
    crop_units: str = "percent",
) -> dict[str, Any]:
    """Upload or replace the cover image of an existing Mealie recipe.

    The image is read from an HTTP(S) URL, file:// URL, or local path and sent
    to Mealie as a real multipart file upload. It is never stored as an external
    URL in the recipe object. Requires mutations enabled and an explicit user
    confirmation. An optional crop uses [left, top, right, bottom] in percent
    (default), fraction, or pixels.
    """
    if not confirmed_by_user:
        raise RuntimeError(
            "Bildänderung blockiert: erst eine Vorschau/Quelle zeigen und eine explizite Bestätigung "
            "des Nutzers einholen. Rufe dieses Tool danach mit confirmed_by_user=true auf."
        )

    requested_identifier = (slug_or_id or "").strip()
    if not requested_identifier:
        raise RuntimeError("Rezept-Slug oder -ID fehlt.")
    if not (image_source or "").strip():
        raise RuntimeError("Bildquelle fehlt.")

    safe_identifier = urllib.parse.quote(requested_identifier, safe="")
    recipe = _json_request("GET", f"/api/recipes/{safe_identifier}")
    if not isinstance(recipe, dict):
        raise RuntimeError("Mealie lieferte beim Rezeptabruf kein Objekt.")

    slug = str(recipe.get("slug") or requested_identifier).strip()
    if not slug:
        raise RuntimeError("Mealie-Rezept besitzt keinen verwendbaren Slug.")
    safe_slug = urllib.parse.quote(slug, safe="")
    upload_path = f"/api/recipes/{safe_slug}/image"
    _require_mutations(upload_path, "PUT")

    filename, content, content_type = _read_binary_source(image_source.strip())
    if not content:
        raise RuntimeError("Die Bildquelle ist leer.")

    crop_applied = False
    crop_info: dict[str, Any] | None = None
    if crop_box:
        filename, content, content_type, crop_info = _crop_image_for_cover(
            filename,
            content,
            content_type,
            crop_box,
            crop_units,
        )
        crop_applied = True

    extension = _extension_from_filename(filename, content_type)
    upload_response = _multipart_request(
        "PUT",
        upload_path,
        fields={"extension": extension},
        files={"image": (filename, content, content_type)},
    )

    verified = _json_request("GET", f"/api/recipes/{safe_slug}")
    verified_image = verified.get("image") if isinstance(verified, dict) else None
    if not verified_image and isinstance(upload_response, dict):
        verified_image = upload_response.get("image")
    if not verified_image:
        raise RuntimeError("Mealie meldete nach dem Upload kein Rezeptbild.")

    return {
        "image_uploaded": True,
        "slug": slug,
        "url": f"{PUBLIC_URL}/g/home/r/{safe_slug}",
        "image": verified_image,
        "source_filename": filename,
        "source_content_type": content_type,
        "uploaded_bytes": len(content),
        "extension": extension,
        "crop_applied": crop_applied,
        "crop_info": crop_info,
    }


@mcp.tool()
def mealie_upload_recipe_asset(
    slug_or_id: str,
    asset_source: str,
    asset_name: str = "",
    icon: str = "",
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Upload a real file asset to an existing recipe via multipart."""
    _require_user_confirmation(confirmed_by_user)
    identifier = slug_or_id.strip()
    if not identifier:
        raise RuntimeError("Rezept-Slug oder -ID darf nicht leer sein.")
    source = asset_source.strip()
    if not source:
        raise RuntimeError("Asset-Quelle darf nicht leer sein.")

    safe_identifier = urllib.parse.quote(identifier, safe="")
    current = _json_request("GET", f"/api/recipes/{safe_identifier}")
    if not isinstance(current, dict):
        raise RuntimeError("Mealie lieferte kein gültiges Rezept.")
    slug = str(current.get("slug") or identifier).strip()
    safe_slug = urllib.parse.quote(slug, safe="")
    path = f"/api/recipes/{safe_slug}/assets"
    _require_mutations(path, "POST")

    filename, content, content_type = _read_binary_source(source)
    display_name = asset_name.strip() or Path(filename).stem or "Asset"
    upload_result = _multipart_request(
        "POST",
        path,
        fields={"name": display_name, "icon": icon},
        files={"file": (filename, content, content_type)},
    )
    return {
        "asset_uploaded": True,
        "slug": slug,
        "url": f"{PUBLIC_URL}/g/home/r/{safe_slug}",
        "asset_name": display_name,
        "source_filename": filename,
        "uploaded_bytes": len(content),
        "response": upload_result,
    }


@mcp.tool()
def mealie_delete_recipe_image(
    slug_or_id: str,
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Delete an existing recipe cover image after explicit confirmation."""
    _require_user_confirmation(confirmed_by_user)
    safe_identifier = urllib.parse.quote(slug_or_id.strip(), safe="")
    current = _json_request("GET", f"/api/recipes/{safe_identifier}")
    if not isinstance(current, dict):
        raise RuntimeError("Mealie lieferte kein gültiges Rezept.")
    slug = str(current.get("slug") or slug_or_id).strip()
    safe_slug = urllib.parse.quote(slug, safe="")
    path = f"/api/recipes/{safe_slug}/image"
    _require_mutations(path, "DELETE")
    result = _json_request("DELETE", path)
    return {"image_deleted": True, "slug": slug, "response": result}


@mcp.tool()
def mealie_duplicate_recipe(
    slug_or_id: str,
    new_name: str | None = None,
    confirmed_by_user: bool = False,
) -> Any:
    """Duplicate a recipe, optionally assigning a new name."""
    _require_user_confirmation(confirmed_by_user)
    safe_identifier = urllib.parse.quote(slug_or_id.strip(), safe="")
    current = _json_request("GET", f"/api/recipes/{safe_identifier}")
    if not isinstance(current, dict):
        raise RuntimeError("Mealie lieferte kein gültiges Rezept.")
    slug = str(current.get("slug") or slug_or_id).strip()
    path = f"/api/recipes/{urllib.parse.quote(slug, safe='')}/duplicate"
    _require_mutations(path, "POST")
    return _json_request("POST", path, body={"name": new_name})


@mcp.tool()
def mealie_mark_recipe_made(
    slug_or_id: str,
    timestamp: str,
    confirmed_by_user: bool = False,
) -> Any:
    """Set a recipe's last-made timestamp using an ISO 8601 date-time."""
    _require_user_confirmation(confirmed_by_user)
    if "T" not in timestamp:
        raise RuntimeError("timestamp muss ein ISO-8601-Datum mit Uhrzeit sein.")
    safe_identifier = urllib.parse.quote(slug_or_id.strip(), safe="")
    current = _json_request("GET", f"/api/recipes/{safe_identifier}")
    if not isinstance(current, dict):
        raise RuntimeError("Mealie lieferte kein gültiges Rezept.")
    slug = str(current.get("slug") or slug_or_id).strip()
    path = f"/api/recipes/{urllib.parse.quote(slug, safe='')}/last-made"
    _require_mutations(path, "PATCH")
    return _json_request("PATCH", path, body={"timestamp": timestamp})


@mcp.tool()
def mealie_list_organizers(
    kind: str,
    search: str = "",
    page: int = 1,
    per_page: int = 50,
) -> Any:
    """List tags, categories, foods, units, cookbooks, comments, or timeline events."""
    paths = {
        "tags": "/api/organizers/tags",
        "categories": "/api/organizers/categories",
        "foods": "/api/foods",
        "units": "/api/units",
        "cookbooks": "/api/households/cookbooks",
        "comments": "/api/comments",
        "timeline": "/api/recipes/timeline/events",
    }
    normalized = kind.strip().lower()
    if normalized not in paths:
        raise RuntimeError(
            "kind muss tags, categories, foods, units, cookbooks, comments oder timeline sein."
        )
    order_by = "name" if normalized in {"tags", "categories", "foods", "units", "cookbooks"} else ""
    params = _pagination_params(page, per_page, order_by, "asc")
    params["search"] = search or None
    return _json_request("GET", paths[normalized], params=params)


@mcp.tool()
def mealie_api_operations(
    query: str = "",
    tag: str = "",
    method: str = "",
    include_sensitive: bool = False,
    limit: int = 50,
) -> dict[str, Any]:
    """Search the live Mealie OpenAPI operation catalog.

    Returns operation IDs, methods, paths, tags, parameters, and content types.
    Admin/auth/user/backup/maintenance operations are hidden by default and are
    documentation-only even when include_sensitive=True.
    """
    spec = _get_openapi_spec()
    query_lower = query.strip().lower()
    tag_lower = tag.strip().lower()
    method_upper = method.strip().upper()
    if method_upper and method_upper not in _HTTP_METHODS:
        raise RuntimeError(f"Nicht unterstützte HTTP-Methode: {method}")

    all_operations = list(_iter_openapi_operations(spec))
    matches: list[dict[str, Any]] = []
    for operation_method, path, operation_id, operation in all_operations:
        tags = list(dict.fromkeys(str(item) for item in (operation.get("tags") or [])))
        sensitive = _is_sensitive_operation(path, tags)
        if sensitive and not include_sensitive:
            continue
        if method_upper and operation_method != method_upper:
            continue
        if tag_lower and not any(tag_lower in item.lower() for item in tags):
            continue
        summary = str(operation.get("summary") or "")
        haystack = " ".join((operation_id, path, summary, *tags)).lower()
        if query_lower and query_lower not in haystack:
            continue

        parameters = []
        for parameter in operation.get("parameters") or []:
            if isinstance(parameter, dict):
                parameters.append(
                    {
                        "name": parameter.get("name"),
                        "in": parameter.get("in"),
                        "required": bool(parameter.get("required")),
                    }
                )
        request_types = sorted(
            (operation.get("requestBody") or {}).get("content", {}).keys()
        )
        response_types = sorted(
            {
                content_type
                for response in (operation.get("responses") or {}).values()
                if isinstance(response, dict)
                for content_type in (response.get("content") or {}).keys()
            }
        )
        matches.append(
            {
                "operation_id": operation_id,
                "method": operation_method,
                "path": path,
                "summary": summary,
                "tags": tags,
                "parameters": parameters,
                "request_content_types": request_types,
                "response_content_types": response_types,
                "sensitive": sensitive,
            }
        )

    safe_limit = max(1, min(int(limit), 100))
    return {
        "openapi_version": spec.get("info", {}).get("version"),
        "total_available": len(all_operations),
        "total_matching": len(matches),
        "returned": min(len(matches), safe_limit),
        "operations": matches[:safe_limit],
    }


@mcp.tool()
def mealie_api_operation_request(
    operation_id: str,
    path_params: dict[str, Any] | None = None,
    query_params: dict[str, Any] | None = None,
    body: dict[str, Any] | list[Any] | None = None,
    confirmed_by_user: bool = False,
) -> Any:
    """Execute a non-sensitive JSON Mealie operation by OpenAPI operation ID.

    Use mealie_api_operations first. Mutations require explicit confirmation
    and remain restricted by MEALIE_MCP_MUTATION_SCOPE. Multipart/binary
    operations require a dedicated MCP tool.
    """
    method, path_template, operation = _find_openapi_operation(operation_id)
    tags = list(dict.fromkeys(str(item) for item in (operation.get("tags") or [])))
    if _is_sensitive_operation(path_template, tags):
        raise RuntimeError(
            "Diese Operation gehört zu einem sensiblen Admin/Auth/User-Bereich und ist im Mealie-MCP blockiert."
        )

    request_types = set(
        (operation.get("requestBody") or {}).get("content", {}).keys()
    )
    if request_types and "application/json" not in request_types:
        raise RuntimeError(
            "Diese OpenAPI-Operation verwendet Multipart- oder Binärdaten. Nutze dafür ein dediziertes Mealie-MCP-Tool."
        )
    response_types = {
        content_type
        for response in (operation.get("responses") or {}).values()
        if isinstance(response, dict)
        for content_type in (response.get("content") or {}).keys()
    }
    if "text/event-stream" in response_types:
        raise RuntimeError(
            "Streaming-/SSE-Endpunkte werden vom synchronen Mealie-MCP nicht ausgeführt."
        )
    if method == "GET" and response_types and not any(
        content_type == "application/json" or content_type.endswith("+json")
        for content_type in response_types
    ):
        raise RuntimeError(
            "Diese Operation liefert Binärdaten. Nutze mealie_api_download."
        )

    path = _resolve_openapi_path(path_template, path_params)
    _validate_openapi_request(
        operation,
        query_params=query_params,
        body=body,
        content_type="application/json",
    )

    if method != "GET":
        if not confirmed_by_user:
            raise RuntimeError(
                "Schreibende API-Operation blockiert: Es fehlt die explizite Bestätigung des Benutzers."
            )
        _require_mutations(path, method)
    return _json_request(method, path, params=query_params, body=body)


@mcp.tool()
def mealie_api_multipart_operation_request(
    operation_id: str,
    path_params: dict[str, Any] | None = None,
    query_params: dict[str, Any] | None = None,
    fields: dict[str, Any] | None = None,
    file_sources: dict[str, str] | None = None,
    confirmed_by_user: bool = False,
) -> Any:
    """Execute a non-sensitive multipart Mealie operation by OpenAPI operation ID.

    file_sources maps multipart field names to direct HTTP(S)/file URLs or local
    paths. Mutations require explicit confirmation and an enabled scope.
    """
    method, path_template, operation = _find_openapi_operation(operation_id)
    tags = list(dict.fromkeys(str(item) for item in (operation.get("tags") or [])))
    if _is_sensitive_operation(path_template, tags):
        raise RuntimeError(
            "Diese Operation gehört zu einem sensiblen Admin/Auth/User-Bereich und ist im Mealie-MCP blockiert."
        )
    request_types = set(
        (operation.get("requestBody") or {}).get("content", {}).keys()
    )
    if "multipart/form-data" not in request_types:
        raise RuntimeError(
            "Diese OpenAPI-Operation ist kein multipart/form-data-Endpunkt."
        )
    if method == "GET":
        raise RuntimeError("Multipart-GET-Operationen werden nicht unterstützt.")
    _require_user_confirmation(confirmed_by_user)
    path = _resolve_openapi_path(path_template, path_params)
    sources = file_sources or {}
    multipart_body: dict[str, Any] = dict(fields or {})
    multipart_body.update({str(name): "<file>" for name in sources})
    _validate_openapi_request(
        operation,
        query_params=query_params,
        body=multipart_body,
        content_type="multipart/form-data",
    )
    _require_mutations(path, method)

    if not sources:
        raise RuntimeError("Mindestens eine Datei muss in file_sources angegeben werden.")
    if len(sources) > 10:
        raise RuntimeError("Pro Multipart-Aufruf sind höchstens 10 Dateien erlaubt.")
    files: dict[str, tuple[str, bytes, str]] = {}
    for field_name, source in sources.items():
        clean_field_name = str(field_name).strip()
        if not clean_field_name:
            raise RuntimeError("Multipart-Dateifeld darf nicht leer sein.")
        files[clean_field_name] = _read_binary_source(str(source))
    request_kwargs: dict[str, Any] = {
        "fields": fields or {},
        "files": files,
    }
    if query_params:
        request_kwargs["params"] = query_params
    return _multipart_request(method, path, **request_kwargs)


@mcp.tool()
def mealie_api_download(
    operation_id: str,
    path_params: dict[str, Any] | None = None,
    query_params: dict[str, Any] | None = None,
    output_name: str = "",
) -> dict[str, Any]:
    """Download a non-sensitive binary GET operation to a controlled local directory."""
    method, path_template, operation = _find_openapi_operation(operation_id)
    tags = list(dict.fromkeys(str(item) for item in (operation.get("tags") or [])))
    if _is_sensitive_operation(path_template, tags):
        raise RuntimeError(
            "Diese Operation gehört zu einem sensiblen Admin/Auth/User-Bereich und ist im Mealie-MCP blockiert."
        )
    if method != "GET":
        raise RuntimeError("mealie_api_download unterstützt ausschließlich GET-Operationen.")
    response_types = {
        content_type
        for response in (operation.get("responses") or {}).values()
        if isinstance(response, dict)
        for content_type in (response.get("content") or {}).keys()
    }
    if "text/event-stream" in response_types:
        raise RuntimeError("Streaming-/SSE-Endpunkte können nicht heruntergeladen werden.")
    if response_types and all(
        content_type == "application/json" or content_type.endswith("+json")
        for content_type in response_types
    ):
        raise RuntimeError(
            "Diese Operation liefert JSON. Nutze mealie_api_operation_request."
        )

    path = _resolve_openapi_path(path_template, path_params)
    suggested_name, content, content_type = _download_api_binary(
        path, params=query_params
    )
    raw_name = Path(output_name.strip() or suggested_name).name
    safe_name = re.sub(r"[^\w.()\- ]+", "_", raw_name, flags=re.UNICODE).strip(". ")
    if not safe_name:
        safe_name = f"mealie-download-{uuid.uuid4().hex[:8]}.bin"
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    if DOWNLOAD_DIR.is_symlink():
        raise RuntimeError("Das Mealie-Downloadverzeichnis darf kein Symlink sein.")
    DOWNLOAD_DIR.chmod(0o700)
    target = DOWNLOAD_DIR / safe_name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for attempt in range(10):
        if attempt:
            target = DOWNLOAD_DIR / (
                f"{Path(safe_name).stem}-{uuid.uuid4().hex[:8]}{Path(safe_name).suffix}"
            )
        try:
            file_descriptor = os.open(target, flags, 0o600)
            break
        except FileExistsError:
            continue
    else:
        raise RuntimeError("Konnte keinen kollisionsfreien Download-Dateinamen erzeugen.")
    try:
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(content)
    except Exception:
        try:
            target.unlink(missing_ok=True)
        finally:
            raise
    return {
        "downloaded": True,
        "operation_id": operation_id,
        "path": str(target.resolve()),
        "filename": target.name,
        "content_type": content_type,
        "bytes": len(content),
    }


@mcp.tool()
def mealie_api_get(path: str, params: dict[str, Any] | None = None) -> Any:
    """Generic authenticated GET validated against live OpenAPI and security tags."""
    clean_path = _validate_raw_api_operation("GET", path)
    return _json_request("GET", clean_path, params=params)


@mcp.tool()
def mealie_api_request(
    method: str,
    path: str,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | list[Any] | None = None,
    confirmed_by_user: bool = False,
) -> Any:
    """Generic JSON Mealie API request for non-sensitive paths.

    Non-GET methods require explicit user confirmation and an enabled mutation
    scope. Prefer mealie_api_operation_request because it validates against the
    live OpenAPI document.
    """
    method = method.upper()
    if method not in _HTTP_METHODS:
        raise RuntimeError(f"Nicht unterstützte HTTP-Methode: {method}")
    if method != "GET":
        _require_user_confirmation(confirmed_by_user)
    clean_path = _validate_raw_api_operation(method, path)
    if method != "GET":
        _require_mutations(clean_path, method)
    return _json_request(method, clean_path, params=params, body=body)


@mcp.tool()
def mealie_extract_recipe_text_from_image(
    image_url: str,
    ocr_lang: str = "deu+eng",
) -> dict[str, Any]:
    """OCR: Extrahiere Rohtext aus einem Kochbuchfoto/Screenshot.

    Lädt das Bild von einer URL oder lokalem Pfad, bereitet es für OCR auf
    (Graustufen, Kontrast, Binarisierung) und gibt den erkannten Text zurück.

    Der Rohtext kann dann per Text-LLM in Zutaten/Anweisungen strukturiert
    und mit mealie_create_recipe_from_text importiert werden.

    Das spart teure Vision-API-Aufrufe.
    """
    if not image_url.strip():
        return {"raw_text": "", "word_count": 0, "line_count": 0, "error": "Keine Bild-URL angegeben."}

    try:
        filename, content, content_type = _read_binary_source(image_url)
        result = _ocr_extract_text(content, lang=ocr_lang)
        result["source_filename"] = filename
        result["source_size"] = len(content)
        return result
    except Exception as exc:
        return {"error": _redact(str(exc)[:500])}


def _validate_chefkoch_recipe_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme != "https" or parsed.hostname not in {"chefkoch.de", "www.chefkoch.de"}:
        raise RuntimeError("Nur HTTPS-Rezept-URLs von chefkoch.de sind erlaubt.")
    if parsed.username or parsed.password:
        raise RuntimeError("Chefkoch-URLs mit eingebetteten Zugangsdaten sind nicht erlaubt.")
    if not re.fullmatch(r"/rezepte/\d+(?:/[^?#]*)?", parsed.path):
        raise RuntimeError("Die URL ist keine gültige Chefkoch-Rezept-URL.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _bounded_chefkoch_get(url: str, *args: Any, **kwargs: Any):
    kwargs["timeout"] = min(float(kwargs.get("timeout", TIMEOUT)), TIMEOUT)
    kwargs["stream"] = True
    response = _CHEFKOCH_ORIGINAL_GET(url, *args, **kwargs)
    content = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            content.extend(chunk)
            if len(content) > MAX_CHEFKOCH_BYTES:
                raise RuntimeError(
                    f"Chefkoch-Antwort überschreitet das Größenlimit von {MAX_CHEFKOCH_BYTES} Bytes."
                )
    except Exception:
        response.close()
        raise
    response._content = bytes(content)
    response._content_consumed = True
    return response


_chefkoch_impl.requests.get = _bounded_chefkoch_get


@mcp.tool()
def mealie_search_chefkoch(
    query: str,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Suche Rezepte auf Chefkoch.de.

    Durchsucht Chefkoch.de nach Rezepten passend zur Suchanfrage und gibt
    eine Liste mit Grundinformationen zurueck (Titel, URL, Beschreibung,
    Bild, Kategorie, Zubereitungszeit, Bewertung).

    Verwendung: Vor einem Mealie-Import die Rezeptsuche, um das passende
    Rezept zu finden. Der Benutzer kann dann per URL oder per
    `mealie_get_chefkoch_recipe` die vollstaendigen Details abrufen.
    """
    if not query.strip():
        return [{"error": "Keine Suchanfrage angegeben."}]
    safe_query = query.strip()[:200]
    safe_limit = max(1, min(int(limit), 20))

    try:
        search = get_chefkoch.Search(safe_query)
        recipes = search.recipes(limit=safe_limit)
        results: list[dict[str, Any]] = []
        for r in recipes:
            try:
                name = r.name  # triggers metadata load
                dd = r.data_dump()
                agg = dd.get("aggregateRating", {}) or {}
                results.append({
                    "name": name,
                    "id": r.id,
                    "url": f"https://www.chefkoch.de/rezepte/{r.id}/",
                    "description": str(r.description or "")[:300],
                    "image": r.image or "",
                    "category": r.category or "",
                    "prep_time": str(r.prepTime) if r.prepTime else "",
                    "cook_time": str(r.cookTime) if r.cookTime else "",
                    "total_time": str(r.totalTime) if r.totalTime else "",
                    "rating": str(agg.get("ratingValue", "")),
                    "rating_count": str(agg.get("ratingCount", "")),
                })
            except Exception:
                # Skip recipes whose pages fail to parse
                continue
        return results
    except Exception as exc:
        return [{"error": _redact(str(exc)[:300])}]


@mcp.tool()
def mealie_get_chefkoch_recipe(
    url: str,
) -> dict[str, Any]:
    """Rufe ein vollstaendiges Chefkoch-Rezept mit allen Details ab.

    Liefert Zutaten-Liste, Schritt-fuer-Schritt-Anleitung, Zubereitungszeit,
    Kategorie, Bewertung und Naehrwerte (falls vorhanden) fuer ein Rezept.

    Der Bot nutzt diese Daten, um das Rezept strukturiert anzuzeigen oder
    in Mealie zu importieren.
    """
    if not url.strip():
        return {"error": "Keine URL angegeben."}

    try:
        safe_url = _validate_chefkoch_recipe_url(url)
        recipe = get_chefkoch.Recipe(safe_url)
        name = recipe.name  # triggers metadata load
        dd = recipe.data_dump()
        agg = dd.get("aggregateRating", {}) or {}

        instructions: list[str] = []
        raw_instructions = dd.get("recipeInstructions", [])
        if isinstance(raw_instructions, list):
            for step in raw_instructions:
                if isinstance(step, dict):
                    text = step.get("text", step.get("name", ""))
                    if text:
                        instructions.append(str(text))
                elif isinstance(step, str):
                    instructions.append(step)

        return {
            "name": name,
            "id": recipe.id,
            "url": safe_url.rstrip("/") + "/",
            "description": str(recipe.description or "")[:500],
            "image": recipe.image or "",
            "category": recipe.category or "",
            "cuisine": dd.get("recipeCuisine", ""),
            "prep_time": str(recipe.prepTime) if recipe.prepTime else "",
            "cook_time": str(recipe.cookTime) if recipe.cookTime else "",
            "total_time": str(recipe.totalTime) if recipe.totalTime else "",
            "yield_amount": dd.get("recipeYield", ""),
            "rating": str(agg.get("ratingValue", "")),
            "rating_count": str(agg.get("ratingCount", "")),
            "ingredients": list(dd.get("recipeIngredient", []))[:500],
            "instructions": instructions[:500],
            "keywords": dd.get("keywords", ""),
            "date_published": str(dd.get("datePublished", "")),
        }
    except get_chefkoch.exceptions.ParserError:
        return {"error": "Rezeptseite konnte nicht geparst werden (keine JSON-LD-Daten gefunden)."}
    except get_chefkoch.exceptions.InvalidUrl:
        return {"error": "Die URL ist keine gueltige Chefkoch-URL."}
    except RuntimeError as exc:
        return {"error": _redact(str(exc)[:500])}
    except Exception as exc:
        return {"error": _redact(str(exc)[:500])}


@mcp.tool()
def mealie_parse_ingredients(ingredients: list[str]) -> dict[str, Any]:
    """Parse ingredient lines via Mealie's ingredient parser.

    Accepts a list of raw ingredient strings (e.g. '650 g Süßkartoffeln,
    in etwa 4 cm große Würfel geschnitten') and returns structured results
    with quantity, unit, food, and note fields.

    The parsed results can be passed directly to
    `mealie_update_recipe_ingredients` for updating existing recipes.
    """
    if not ingredients:
        return {"ingredients": [], "count": 0}
    # Mealie v3.20 expects a list of raw strings.
    body = {"ingredients": ingredients}
    result = _json_request("POST", "/api/parser/ingredients", body=body)
    if isinstance(result, list):
        parsed = result
    elif isinstance(result, dict):
        value = result.get("ingredients", result.get("parsed", []))
        parsed = value if isinstance(value, list) else [result]
    else:
        parsed = []

    # Mealie v3.20 wraps each parsed item as
    # {"input": ..., "confidence": ..., "ingredient": {...}}.
    # Expose only the actual ingredient objects so callers can pass this list
    # directly to mealie_update_recipe_ingredients.
    normalized: list[dict[str, Any]] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        ingredient = item.get("ingredient")
        normalized.append(ingredient if isinstance(ingredient, dict) else item)

    return {"ingredients": normalized, "count": len(normalized)}


@mcp.tool()
def mealie_update_recipe_ingredients(
    slug: str,
    ingredients: list[dict[str, Any] | str],
    update_fields: dict[str, Any] | None = None,
    confirmed_by_user: bool = False,
) -> dict[str, Any]:
    """Replace the ingredient list of an existing Mealie recipe with
    structured data.

    Each ingredient dict must contain at least 'quantity', 'unit', 'food',
    and optionally 'note' and 'display'. Supports both structured inputs
    (as returned by mealie_parse_ingredients) and raw strings (which get
    stored in the display/note format for backward compatibility).

    The tool fetches the current recipe, replaces its ingredient list,
    applies any additional update_fields, and patches it back via the
    Mealie API.

    Typical structured ingredient format:
      {"quantity": 650, "unit": {"name": "g"}, "food": {"name": "Süßkartoffeln"},
       "note": "in etwa 4 cm große Würfel geschnitten"}

    Raw string fallback:
      "650 g Süßkartoffeln, in etwa 4 cm große Würfel geschnitten"

    Returns the updated recipe slug and ingredient count.
    """
    import uuid as _uuidlib

    _require_user_confirmation(confirmed_by_user)
    allowed_update_fields = {
        "name",
        "description",
        "recipeServings",
        "recipeYield",
        "prepTime",
        "cookTime",
        "totalTime",
        "orgURL",
    }
    update_dict = dict(update_fields or {})
    unknown_fields = sorted(set(update_dict) - allowed_update_fields)
    if unknown_fields:
        raise RuntimeError(
            "Unbekannte Rezept-Update-Felder: " + ", ".join(unknown_fields)
        )

    safe_slug = urllib.parse.quote(slug, safe="")
    _require_mutations(f"/api/recipes/{safe_slug}", "PATCH")

    # Fetch current recipe
    recipe = _json_request("GET", f"/api/recipes/{safe_slug}")
    if not isinstance(recipe, dict):
        return {"error": f"Rezept {slug} nicht gefunden.", "slug": slug}

    # Convert ingredients to Mealie's internal format
    structured: list[dict[str, Any]] = []
    for ing in ingredients:
        if isinstance(ing, str):
            # Raw string fallback
            structured.append({
                "quantity": 0,
                "unit": None,
                "food": None,
                "note": ing,
                "display": ing,
                "title": None,
                "originalText": None,
                "referenceId": str(_uuidlib.uuid4()),
            })
        elif isinstance(ing, dict):
            # Try to extract structured values
            qty = ing.get("quantity", 0)
            unit_obj = ing.get("unit")
            food_obj = ing.get("food")
            note_str = ing.get("note", ing.get("display", ""))
            display_str = ing.get("display", note_str)

            # Mealie v3 requires complete food/unit objects with an id. Keep
            # parser objects intact; resolve name-only values through the API.
            unit_to_store = _resolve_ingredient_reference(
                unit_obj, "/api/units", "Einheit"
            )
            food_to_store = _resolve_ingredient_reference(
                food_obj, "/api/foods", "Lebensmittel"
            )

            structured.append({
                "quantity": float(qty) if qty else 0,
                "unit": unit_to_store,
                "food": food_to_store,
                "note": note_str,
                "display": display_str,
                "title": ing.get("title"),
                "originalText": ing.get("originalText"),
                "referenceId": str(_uuidlib.uuid4()),
            })
        else:
            continue

    if not structured:
        return {"error": "Keine gültigen Zutaten übergeben.", "slug": slug}

    # Preserve existing fields unless explicitly overridden
    for key in ("name", "description", "recipeServings", "recipeYield",
                "prepTime", "cookTime", "totalTime", "orgURL"):
        if key not in update_dict and key in recipe:
            update_dict[key] = recipe[key]

    # Build the patch body
    patch_body: dict[str, Any] = {
        **update_dict,
        "recipeIngredient": structured,
    }

    # Preserve existing instructions (they remain unchanged)
    if "recipeInstructions" not in update_dict and "recipeInstructions" in recipe:
        patch_body["recipeInstructions"] = recipe["recipeInstructions"]

    # Preserve existing tags
    if "tags" not in update_dict and "tags" in recipe:
        patch_body["tags"] = recipe["tags"]

    # Preserve settings
    if "settings" not in update_dict and "settings" in recipe:
        patch_body["settings"] = recipe["settings"]

    _json_request("PATCH", f"/api/recipes/{safe_slug}", body=patch_body)

    # Verify
    verified = _json_request("GET", f"/api/recipes/{safe_slug}")
    verified_ings = verified.get("recipeIngredient", []) if isinstance(verified, dict) else []

    return {
        "slug": slug,
        "url": f"{PUBLIC_URL}/g/home/r/{safe_slug}",
        "ingredient_count": len(verified_ings),
        "parsed_ingredients": sum(
            1 for ing in verified_ings
            if isinstance(ing, dict) and ing.get("food") is not None
        ),
        "success": True,
    }


def main() -> None:
    """Run the MCP server over stdio while keeping stdout JSON-RPC clean."""
    try:
        mcp.run(transport="stdio")
    except Exception as exc:  # keep stdout clean for MCP
        print(_redact(f"mealie MCP server failed: {exc}"), file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
