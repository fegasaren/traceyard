#!/usr/bin/env python3
"""Traceyard HTTP UI, authenticated Tempo proxy, audit and Prometheus endpoint."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import mimetypes
import os
import re
import socket
import signal
import secrets
import ssl
import time
import threading
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from demo import DemoStore, QueryError
from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST, ProcessCollector, GCCollector, PlatformCollector
from security import Security, SecurityError

ROOT = Path(__file__).resolve().parent
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
INPUT_TIMEOUT_SECONDS = 15
LOG = logging.getLogger("otel-ui")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Config:
    def __init__(self):
        self.mode = os.environ.get("TRACE_MODE", "tempo").lower()
        if self.mode not in ("tempo", "demo"):
            raise ValueError("TRACE_MODE must be tempo or demo")
        self.auth_mode = os.environ.get("AUTH_MODE", "disabled" if self.mode == "demo" else "ldap")
        if self.auth_mode not in ("ldap", "disabled"):
            raise ValueError("AUTH_MODE must be ldap or disabled")
        self.public_origin = os.environ.get("PUBLIC_ORIGIN", "").rstrip("/")
        if self.auth_mode == "ldap":
            origin = urlsplit(self.public_origin)
            if (origin.scheme not in ("http", "https") or not origin.netloc or origin.path
                    or origin.username or origin.password or origin.query or origin.fragment):
                raise ValueError("PUBLIC_ORIGIN must be the browser's http(s) origin")
        self.security = Security.from_env() if self.auth_mode == "ldap" else None
        try:
            self.trusted_proxies = [ipaddress.ip_network(value.strip()) for value in os.environ.get("TRUSTED_PROXY_CIDRS", "").split(",") if value.strip()]
        except ValueError:
            raise ValueError("TRUSTED_PROXY_CIDRS must contain explicit IP networks") from None
        if any(network.prefixlen == 0 for network in self.trusted_proxies):
            raise ValueError("TRUSTED_PROXY_CIDRS must not trust every address")
        self.max_concurrency = int(os.environ.get("HTTP_MAX_CONCURRENCY", "16"))
        if not 1 <= self.max_concurrency <= 128:
            raise ValueError("HTTP_MAX_CONCURRENCY must be in [1,128]")
        self.tempo_url = os.environ.get("TEMPO_URL", "").rstrip("/")
        self.headers = {"Accept": "application/json", "User-Agent": "traceyard/0.3.1"}
        self.max_response = int(os.environ.get("TEMPO_MAX_RESPONSE_BYTES", str(8 * 1024 * 1024)))
        if not 1024 <= self.max_response <= MAX_RESPONSE_BYTES:
            raise ValueError("TEMPO_MAX_RESPONSE_BYTES must be between 1024 and 33554432")
        self.secrets = []
        self.timeout = float(os.environ.get("TEMPO_TIMEOUT_SECONDS", "30"))
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= 300:
            raise ValueError("TEMPO_TIMEOUT_SECONDS must be in (0, 300]")
        if self.mode == "tempo":
            parts = urlsplit(self.tempo_url)
            if (parts.scheme not in ("http", "https") or not parts.hostname
                    or parts.username or parts.password or parts.query or parts.fragment):
                raise ValueError("Set TEMPO_URL to an http(s) Tempo query endpoint without credentials or query")
            tenant = os.environ.get("TEMPO_TENANT_ID", "")
            bearer = os.environ.get("TEMPO_BEARER_TOKEN", "")
            username = os.environ.get("TEMPO_USERNAME", "")
            password = os.environ.get("TEMPO_PASSWORD", "")
            if bearer and (username or password):
                raise ValueError("Choose bearer token OR basic authentication")
            if bool(username) != bool(password):
                raise ValueError("TEMPO_USERNAME and TEMPO_PASSWORD must both be set")
            if any("\r" in value or "\n" in value for value in (tenant, bearer, username, password)):
                raise ValueError("Authentication settings cannot contain line breaks")
            if tenant:
                self.headers["X-Scope-OrgID"] = tenant
            if bearer:
                self.headers["Authorization"] = "Bearer " + bearer
                self.secrets.append(bearer)
            elif username:
                encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
                self.headers["Authorization"] = "Basic " + encoded
                self.secrets.extend([username, password, encoded])
        context = ssl.create_default_context(cafile=os.environ.get("TEMPO_CA_FILE") or None)
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=context))
        self.demo = DemoStore() if self.mode == "demo" else None

    def safe_error(self, body: bytes) -> str:
        message = body[:2048].decode("utf-8", "replace").strip()
        try:
            parsed = json.loads(message)
            if isinstance(parsed, dict):
                message = str(parsed.get("error") or parsed.get("message") or "")
        except ValueError:
            pass
        if "<html" in message.lower() or "<!doctype" in message.lower():
            return "Tempo отклонил запрос. Проверьте TraceQL и настройки подключения."
        for secret in self.secrets:
            message = message.replace(secret, "[redacted]")
        return message[:1000] or "Tempo отклонил запрос."


class AppServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True

    def __init__(self, address, config):
        self.config = config
        self.slots = threading.BoundedSemaphore(config.max_concurrency)
        self.tempo_slots = threading.BoundedSemaphore(2)
        self.readiness_slots = threading.BoundedSemaphore(1)
        self.registry = CollectorRegistry()
        self.requests = Counter("traceyard_http_requests_total", "Completed HTTP requests", ["method", "route", "status"], registry=self.registry)
        self.duration = Histogram("traceyard_http_request_duration_seconds", "HTTP request duration", ["route"], registry=self.registry)
        self.active = Gauge("traceyard_http_requests_active", "Active HTTP connections", registry=self.registry)
        self.rejected = Counter("traceyard_http_connections_rejected_total", "Connections rejected at concurrency limit", registry=self.registry)
        self.tempo = Histogram("traceyard_tempo_request_duration_seconds", "Tempo request duration", ["operation", "outcome"], registry=self.registry)
        self.login = Histogram("traceyard_login_duration_seconds", "LDAP login and session creation duration", ["outcome"], registry=self.registry)
        self.audit_failures = Counter("traceyard_audit_failures_total", "Failed audit writes", registry=self.registry)
        ProcessCollector(registry=self.registry); GCCollector(registry=self.registry); PlatformCollector(registry=self.registry)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.rejected.inc()
            self.shutdown_request(request)
            return
        self.active.inc()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.active.dec(); self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(15)
            super().process_request_thread(request, client_address)
        finally:
            self.active.dec(); self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "Traceyard/0.3.1"
    sys_version = ""

    def setup(self):
        super().setup()
        # A socket idle timeout alone allows a client to hold a slot by sending
        # one byte at a time. Bound the complete request headers + body instead.
        self.input_expired = False
        self.input_timer = threading.Timer(INPUT_TIMEOUT_SECONDS, self.expire_input)
        self.input_timer.daemon = True
        self.input_timer.start()

    def expire_input(self):
        self.input_expired = True
        try:
            # Wake blocked readers while leaving writes available for a 408.
            self.connection.shutdown(socket.SHUT_RD)
        except OSError:
            pass

    def input_complete(self):
        self.input_timer.cancel()

    def finish(self):
        self.input_complete()
        super().finish()

    @property
    def config(self):
        return self.server.config

    def log_message(self, fmt, *args):
        # Query strings may contain sensitive attribute values; do not log them.
        LOG.info("%s %s %s", self.safe_method(), self.route(), getattr(self, "response_status", ""))

    def safe_method(self):
        method = getattr(self, "command", "")
        return method if method in ("GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT") else "other"

    def route(self):
        try:
            path = urlsplit(getattr(self, "path", "")).path
        except ValueError:
            return "other"
        if re.fullmatch(r"/api/traces/[0-9a-fA-F]+(?:/download)?", path):
            return "/api/traces/{id}/download" if path.endswith("/download") else "/api/traces/{id}"
        known = {"/", "/index.html", "/app.js", "/styles.css", "/healthz", "/readyz", "/metrics", "/api/me", "/api/login", "/api/logout", "/api/events", "/api/admin/users", "/api/admin/users/block", "/api/admin/audit", "/api/config", "/api/search", "/api/tags", "/api/tag-values"}
        return path if path in known else "other"

    def send_body(self, status, body, content_type="application/json; charset=utf-8"):
        self.response_status = status
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if getattr(self, "request_id", None):
            self.send_header("X-Request-ID", self.request_id)
        if getattr(self, "session_cookie", None):
            self.send_header("Set-Cookie", self.session_cookie)
        if status == 200 and getattr(self, "download_id", None):
            self.send_header("Content-Disposition", f'attachment; filename="trace-{self.download_id}.json"')
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def json(self, status, payload):
        self.send_body(status, json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode())

    def fail(self, status, message):
        self.json(status, {"error": message})

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def unsupported(self):
        self.handle_request()

    do_PUT = unsupported
    do_PATCH = unsupported
    do_DELETE = unsupported
    do_OPTIONS = unsupported
    do_TRACE = unsupported
    do_CONNECT = unsupported

    def handle_request(self):
        started = time.monotonic()
        self.identity = None
        self.request_id = secrets.token_hex(12)
        self.response_status = 500
        try:
            if self.input_expired:
                self.fail(408, "Время передачи запроса истекло.")
            else:
                self.dispatch()
        except SecurityError as exc:
            self.fail(exc.status, exc.message)
        except (ValueError, QueryError) as exc:
            self.fail(400, str(exc))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            LOG.error("Internal request failure", exc_info=False)
            self.fail(500, "Ошибка сервера UI.")
        finally:
            self.input_complete()
            elapsed = time.monotonic() - started
            self.server.requests.labels(self.command if self.command in ("GET", "POST", "HEAD") else "other", self.route(), str(self.response_status)).inc()
            self.server.duration.labels(self.route()).observe(elapsed)
            if self.config.security and self.route().startswith("/api/"):
                try:
                    self.config.security.audit(self.actor(), "request.completed", self.client_ip(), self.route(), "success" if self.response_status < 400 else "denied" if self.response_status in (401,403) else "error", {"request_id": self.request_id, "method": self.safe_method(), "status": self.response_status, "duration_ms": round(elapsed * 1000, 2)})
                except SecurityError:
                    self.server.audit_failures.inc()
                    LOG.error("audit_write_failed route=%s", self.route())

    def actor(self):
        return self.identity["user"]["username"] if self.identity else "anonymous"

    def client_ip(self):
        peer = ipaddress.ip_address(self.client_address[0])
        trusted = lambda address: any(address in network for network in self.config.trusted_proxies)
        if not trusted(peer):
            return str(peer)
        forwarded = self.headers.get("X-Forwarded-For", "")
        if len(forwarded) > 1024:
            return str(peer)
        try:
            chain = [ipaddress.ip_address(value.strip()) for value in forwarded.split(",") if value.strip()]
        except ValueError:
            return str(peer)
        if not chain or len(chain) > 10:
            return str(peer)
        for address in reversed(chain):
            if not trusted(address):
                return str(address)
        return str(chain[0])

    def token(self):
        raw = self.headers.get("Cookie", "")
        if len(raw) > 4096:
            return ""
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
            return cookie["traceyard_session"].value if "traceyard_session" in cookie else ""
        except CookieError:
            return ""

    def require_user(self, admin=False):
        if not self.config.security:
            self.identity = {"user": {"username": "demo", "role": "viewer", "blocked": False}, "csrf": ""}
        else:
            self.identity = self.config.security.session(self.token())
        if not self.identity:
            raise SecurityError(401, "Войдите через корпоративный LDAP.")
        if admin and self.identity["user"]["role"] != "admin":
            raise SecurityError(403, "Доступно только администратору.")
        return self.identity

    def audit(self, event, target="", details=None):
        if self.config.security:
            try:
                self.config.security.audit(self.actor(), event, self.client_ip(), target, "requested", {"request_id": self.request_id, **(details or {})})
            except SecurityError:
                self.server.audit_failures.inc()
                raise

    def mutation(self, csrf=True):
        origin = self.headers.get("Origin")
        if self.headers.get("Sec-Fetch-Site", "") not in ("", "same-origin", "none"):
            raise SecurityError(403, "Разрешены только запросы с сайта Traceyard.")
        if origin is not None and origin != self.config.public_origin:
            raise SecurityError(403, "Недопустимый Origin.")
        if csrf and self.config.security and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), self.identity["csrf"]):
            raise SecurityError(403, "Недействительный CSRF-токен. Обновите страницу.")
        if (self.headers.get_content_type() != "application/json" or self.headers.get("Transfer-Encoding")
                or len(self.headers.get_all("Content-Length", [])) != 1):
            raise ValueError("Требуется application/json с Content-Length.")
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isdecimal() or not 0 < int(raw_length) <= 8192:
            raise ValueError("Размер тела запроса должен быть от 1 до 8192 байт.")
        body = self.rfile.read(int(raw_length))
        self.input_complete()
        if self.input_expired:
            raise SecurityError(408, "Время передачи запроса истекло.")
        if len(body) != int(raw_length):
            raise ValueError("Неполное тело запроса.")
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            raise ValueError("Некорректный JSON.") from None
        if not isinstance(data, dict):
            raise ValueError("Требуется JSON-объект.")
        return data

    def dispatch(self):
        if self.command != "POST":
            self.input_complete()
        if self.command not in ("GET", "HEAD", "POST"):
            return self.fail(405, "Метод HTTP не поддерживается.")
        if len(self.path) > 20000:
            return self.fail(414, "Слишком длинный запрос.")
        parts = urlsplit(self.path)
        path = parts.path
        query = parse_qs(parts.query, keep_blank_values=True, max_num_fields=24)
        if any(len(values) != 1 for values in query.values()):
            raise ValueError("Параметры запроса не должны повторяться.")
        if self.command == "POST":
            return self.post(path, query)
        if path == "/healthz":
            return self.json(200, {"status": "ok"})
        if path == "/metrics":
            return self.send_body(200, generate_latest(self.server.registry), CONTENT_TYPE_LATEST)
        if path == "/readyz":
            if self.config.security:
                self.config.security.ready()
            if self.config.demo:
                return self.json(200, {"status": "ready", "mode": "demo"})
            return self.proxy("/ready", ready=True)
        if path.startswith("/api/"):
            self.require_user(admin=path.startswith("/api/admin/"))
        if path == "/api/me":
            return self.json(200, {**self.identity, "authEnabled": bool(self.config.security)})
        if path == "/api/admin/users":
            if set(query) - {"limit", "offset", "search"}:
                raise ValueError("Неизвестные параметры запроса.")
            self.audit("admin.users.read")
            return self.json(200, {"users": self.config.security.users(limit=self.integer(query, "limit", 100, 1, 100), offset=self.integer(query, "offset", 0, 0, 1000000), search=query.get("search", [""])[0])})
        if path == "/api/admin/audit":
            if set(query) - {"limit", "before", "actor", "event"}:
                raise ValueError("Неизвестные параметры запроса.")
            self.audit("admin.audit.read")
            return self.json(200, {"events": self.config.security.audit_rows(limit=self.integer(query, "limit", 100, 1, 100), before=self.integer(query, "before", None, 1), actor=query.get("actor", [""])[0], event=query.get("event", [""])[0])})
        if path == "/api/config":
            return self.json(200, {"mode": self.config.mode, "backend": "Tempo", "defaultLimit": 50})
        if path == "/api/search":
            params = self.search_params(query, {"q", "start", "end", "limit"})
            params["limit"] = self.integer(query, "limit", 50, 1, 1000)
            q = query.get("q", [""])[0].strip()
            if len(q) > 16000:
                raise ValueError("TraceQL ограничен 16000 символами.")
            if q:
                params["q"] = q
            self.audit("trace.search", details={"query_sha256": hashlib.sha256(q.encode()).hexdigest(), **{k: v for k, v in params.items() if k != "q"}})
            if self.config.demo:
                return self.json(200, self.config.demo.search(params))
            return self.proxy("/api/search", params)
        if path == "/api/tags":
            params = self.search_params(query, {"start", "end", "scope"})
            if "scope" in query:
                if query["scope"][0] not in ("resource", "span", "intrinsic"):
                    raise ValueError("Некорректный scope.")
                params["scope"] = query["scope"][0]
            self.audit("tags.list", details=params)
            if self.config.demo:
                return self.json(200, self.config.demo.tags(params))
            return self.proxy("/api/v2/search/tags", params)
        if path == "/api/tag-values":
            params = self.search_params(query, {"start", "end", "tag"})
            tag = query.get("tag", [""])[0]
            if not tag or len(tag) > 300 or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.:/-]*', tag):
                raise ValueError("Некорректное имя атрибута.")
            self.audit("tags.values", target=tag, details=params)
            if self.config.demo:
                return self.json(200, self.config.demo.values(tag, params))
            return self.proxy("/api/v2/search/tag/" + quote(tag, safe="") + "/values", params)
        if path.startswith("/api/traces/"):
            trace_id = path.removeprefix("/api/traces/")
            download = trace_id.endswith("/download")
            if download:
                trace_id = trace_id.removesuffix("/download")
            if not re.fullmatch(r"(?:[0-9a-fA-F]{16}|[0-9a-fA-F]{32})", trace_id):
                raise ValueError("Trace ID должен содержать 16 или 32 hex-символа.")
            if query:
                raise ValueError("Неизвестные параметры запроса.")
            self.audit("trace.download" if download else "trace.view", target=trace_id.lower())
            if download:
                self.download_id = trace_id.lower()
            if self.config.demo:
                trace = self.config.demo.trace(trace_id.lower())
                return self.json(200, trace) if trace else self.fail(404, "Трейс не найден.")
            return self.proxy("/api/traces/" + trace_id.lower())
        if path.startswith("/api/"):
            return self.fail(404, "Метод API не найден.")
        filename = "index.html" if path == "/" else path.lstrip("/")
        # Serve only shipped frontend assets, never source, configuration or dotfiles.
        static = ROOT / "static"
        candidate = (static / filename).resolve()
        if (not candidate.is_relative_to(static.resolve()) or any(p.startswith(".") for p in Path(filename).parts)
                or candidate.suffix not in (".html", ".js", ".css", ".svg", ".png", ".ico", ".woff2")
                or not candidate.is_file()):
            return self.fail(404, "Файл не найден.")
        mime = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        return self.send_body(200, candidate.read_bytes(), mime + ("; charset=utf-8" if mime.startswith("text/") or mime == "application/javascript" else ""))

    def post(self, path, query):
        if query:
            raise ValueError("Параметры URL для POST не поддерживаются.")
        if path == "/api/login":
            if not self.config.security:
                return self.fail(400, "LDAP отключён в демонстрационном режиме.")
            data = self.mutation(csrf=False)
            if set(data) != {"username", "password"} or not all(isinstance(v, str) for v in data.values()):
                raise ValueError("Передайте username и password.")
            started = time.monotonic(); outcome = "failure"
            try:
                result = self.config.security.login(data["username"], data["password"], self.client_ip())
                # Rotate any previously authenticated browser session on login.
                if self.token():
                    self.config.security.logout(self.token(), self.client_ip())
                self.identity = {k: v for k, v in result.items() if k != "token"}
                secure = "; Secure" if self.config.public_origin.startswith("https://") else ""
                self.session_cookie = f'traceyard_session={result["token"]}; Path=/; HttpOnly; SameSite=Strict; Max-Age={self.config.security.session_ttl}{secure}'
                outcome = "success"
                return self.json(200, {**self.identity, "authEnabled": True})
            finally:
                data.clear()
                self.server.login.labels(outcome).observe(time.monotonic() - started)
        if path not in {"/api/logout", "/api/admin/users/block", "/api/events"}:
            return self.fail(405, "Метод HTTP не поддерживается.")
        self.require_user(admin=path.startswith("/api/admin/"))
        data = self.mutation()
        if path == "/api/logout":
            if data:
                raise ValueError("Logout не принимает параметры.")
            if self.config.security:
                self.config.security.logout(self.token(), self.client_ip())
            self.session_cookie = "traceyard_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            return self.json(200, {"ok": True})
        if path == "/api/admin/users/block":
            if set(data) != {"username", "blocked"} or not isinstance(data["username"], str) or not isinstance(data["blocked"], bool):
                raise ValueError("Передайте username и blocked (true/false).")
            user = self.config.security.set_blocked(self.actor(), data["username"], data["blocked"], self.client_ip())
            return self.json(200, {"user": user})
        allowed = {"span.select", "span.tab", "query.copy", "trace.copy", "trace.link.copy"}
        if set(data) - {"event", "traceId", "spanId", "tab"} or not isinstance(data.get("event"), str) or data["event"] not in allowed:
            raise ValueError("Неизвестное событие интерфейса.")
        for key, sizes in (("traceId", (16,32)), ("spanId", (16,))):
            if key in data and (not isinstance(data[key], str) or len(data[key]) not in sizes or not re.fullmatch("[0-9a-fA-F]+", data[key])):
                raise ValueError("Некорректный идентификатор события.")
        if "tab" in data and data["tab"] not in ("attributes", "events", "links"):
            raise ValueError("Неизвестная вкладка.")
        self.audit(data["event"], target=data.get("traceId", ""), details={k:v for k,v in data.items() if k != "event"} | {"source": "browser"})
        return self.json(200, {"ok": True})

    @staticmethod
    def integer(query, name, default=None, minimum=0, maximum=99999999999):
        if name not in query:
            return default
        raw = query[name][0]
        if not re.fullmatch(r"\d+", raw):
            raise ValueError(f"{name}: требуется целое число.")
        value = int(raw)
        if not minimum <= value <= maximum:
            raise ValueError(f"{name}: допустимо от {minimum} до {maximum}.")
        return value

    def search_params(self, query, allowed):
        if set(query) - allowed:
            raise ValueError("Неизвестные параметры запроса.")
        params = {}
        for key in ("start", "end"):
            value = self.integer(query, key)
            if value is not None:
                params[key] = value
        if "start" in params and "end" in params and params["end"] <= params["start"]:
            raise ValueError("Конец периода должен быть позже начала.")
        return params

    def proxy(self, path, params=None, ready=False):
        slots = self.server.readiness_slots if ready else self.server.tempo_slots
        if not slots.acquire(blocking=False):
            return self.fail(503 if ready else 429, "Слишком много запросов к Tempo. Повторите позже.")
        started = time.monotonic()
        try:
            return self.tempo_request(path, params, ready)
        finally:
            slots.release()
            self.server.tempo.labels("ready" if ready else "trace" if path.startswith("/api/traces/") else "search" if path == "/api/search" else "tags", "success" if self.response_status < 400 else "error").observe(time.monotonic() - started)

    def tempo_request(self, path, params=None, ready=False):
        url = self.config.tempo_url + path
        if params:
            url += "?" + urlencode(params)
        request = Request(url, headers=self.config.headers)
        try:
            with self.config.opener.open(request, timeout=min(2, self.config.timeout) if ready else self.config.timeout) as response:
                if ready:
                    return self.json(200, {"status": "ready", "mode": "tempo"})
                body = response.read(self.config.max_response + 1)
                if len(body) > self.config.max_response:
                    return self.fail(502, "Ответ Tempo превышает допустимый размер. Уменьшите период или лимит.")
                try:
                    decoded = json.loads(body)
                except (ValueError, UnicodeError):
                    return self.fail(502, "Tempo вернул ответ не в формате JSON. Проверьте query endpoint.")
                if not isinstance(decoded, dict):
                    return self.fail(502, "Неожиданный формат ответа Tempo.")
                return self.json(200, decoded)
        except HTTPError as exc:
            if ready:
                return self.fail(503, "Tempo пока не готов или недоступен.")
            if exc.code == 400:
                return self.fail(400, self.config.safe_error(exc.read(2048)))
            if exc.code == 404:
                return self.fail(404, "Трейс или API Tempo не найден.")
            if exc.code in (401, 403):
                return self.fail(502, "Tempo отклонил авторизацию. Проверьте tenant и учётные данные на сервере.")
            if 300 <= exc.code < 400:
                return self.fail(502, "Tempo ответил перенаправлением. Укажите конечный query endpoint в TEMPO_URL.")
            if exc.code == 429:
                return self.fail(429, "Tempo ограничил число запросов. Повторите позже.")
            return self.fail(502, f"Tempo вернул HTTP {exc.code}.")
        except (TimeoutError, socket.timeout):
            return self.fail(503 if ready else 504, "Tempo не ответил вовремя. Уменьшите период поиска.")
        except URLError as exc:
            timeout = isinstance(exc.reason, (TimeoutError, socket.timeout))
            return self.fail(503 if ready else (504 if timeout else 502), "Tempo не ответил вовремя." if timeout else "Не удалось подключиться к Tempo. Проверьте адрес, сеть и TLS на сервере.")
        except (ConnectionError, OSError):
            return self.fail(503 if ready else 502, "Соединение с Tempo прервано.")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = Config()
        host = os.environ.get("HOST", "0.0.0.0")
        port = int(os.environ.get("PORT", "8080"))
        if not 1 <= port <= 65535:
            raise ValueError("PORT must be in [1, 65535]")
        server = AppServer((host, port), config)
    except (ValueError, OSError, SecurityError) as exc:
        # Configuration validation errors do not include the supplied secret values.
        LOG.error("Startup failed: %s", str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
        raise SystemExit(1)
    shutdown_requested = False

    def request_shutdown(_signum, _frame):
        nonlocal shutdown_requested
        if shutdown_requested:
            return
        shutdown_requested = True
        # shutdown() waits for serve_forever(), so it must run in another thread.
        threading.Thread(target=server.shutdown, name="http-shutdown", daemon=True).start()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    LOG.info("Otel UI listening on port %s, mode=%s", port, config.mode)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        # Non-daemon request threads finish their responses and final audit writes.
        server.server_close()


if __name__ == "__main__":
    main()
