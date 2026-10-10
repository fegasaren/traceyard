"""LDAP authentication and shared PostgreSQL security state for Traceyard.

Passwords are used for a single directory bind and are never persisted. Roles
come from deployment configuration, never from a browser or an editable DB field.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import ssl
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from urllib.parse import urlsplit

DEFAULT_ADMIN = "admin@example.org"
DEFAULT_REALMS = [
    {"name": "main", "domain": "example.org",
     "url": "ldap://ldap.example.org:3268",
     "base_dn": "DC=example,DC=org", "aliases": ["main"]},
    {"name": "regions", "domain": "regions.example.org",
     "url": "ldap://regions.example.org:3268",
     "base_dn": "DC=regions,DC=example,DC=org", "aliases": []},
]
SCHEMA_LOCK = 874092461
MAINTENANCE_LOCK = 874092462
SCHEMA = """
CREATE TABLE IF NOT EXISTS traceyard_users (
    username TEXT PRIMARY KEY,
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_login TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS traceyard_sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES traceyard_users(username) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS traceyard_sessions_user ON traceyard_sessions(username);
CREATE INDEX IF NOT EXISTS traceyard_sessions_expiry ON traceyard_sessions(expires_at);
CREATE TABLE IF NOT EXISTS traceyard_audit (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    ip TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS traceyard_audit_time ON traceyard_audit(created_at);
CREATE TABLE IF NOT EXISTS traceyard_login_limits (
    key TEXT PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS traceyard_maintenance (
    key TEXT PRIMARY KEY,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
"""


class SecurityError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def _text(value, maximum=256):
    """Bound metadata and remove control characters, including CR/LF."""
    if not isinstance(value, str):
        return ""
    return "".join(c for c in value if c.isprintable())[:maximum]


def _ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return "unknown"


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


def _details(value):
    """Only bounded primitive metadata; never accept secret-bearing field names."""
    if not isinstance(value, dict):
        return {}
    result = {}
    for key, item in list(value.items())[:20]:
        if not isinstance(key, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,63}", key):
            continue
        if any(part in key.casefold() for part in ("password", "passwd", "secret", "token", "cookie", "authorization", "csrf")):
            continue
        if isinstance(item, str):
            result[key] = _text(item, 256)
        elif item is None or isinstance(item, (bool, int)):
            result[key] = item if not isinstance(item, int) or abs(item) <= 2**63 - 1 else str(item)[:32]
        elif isinstance(item, float) and math.isfinite(item):
            result[key] = item
    return result


def _realms(raw):
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        raise ValueError("LDAP_REALMS must be a nonempty JSON list of at most 16 realms")
    result = []
    identities = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("Each LDAP realm must be an object")
        domain = str(item.get("domain", "")).strip().casefold()
        base_dn = item.get("base_dn", "")
        url = item.get("url", "")
        aliases = item.get("aliases", [])
        parsed = urlsplit(url) if isinstance(url, str) else None
        if (not re.fullmatch(r"[a-z0-9.-]{1,253}", domain) or not parsed
                or parsed.scheme not in ("ldap", "ldaps") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/") or not isinstance(base_dn, str)
                or not base_dn or len(base_dn) > 1024 or any(ord(c) < 32 for c in base_dn)
                or not isinstance(aliases, list) or len(aliases) > 16):
            raise ValueError("Invalid LDAP realm configuration")
        try:
            port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
        except ValueError:
            raise ValueError("Invalid LDAP realm port") from None
        normalized_aliases = []
        for alias in [domain, *aliases]:
            if not isinstance(alias, str) or not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", alias):
                raise ValueError("Invalid LDAP realm alias")
            alias = alias.casefold()
            if alias in identities:
                raise ValueError("LDAP domains and aliases must be unique")
            identities.add(alias)
            normalized_aliases.append(alias)
        result.append({"name": _text(item.get("name", domain), 64), "domain": domain,
                       "url": url, "host": parsed.hostname, "port": port,
                       "ssl": parsed.scheme == "ldaps", "base_dn": base_dn,
                       "aliases": normalized_aliases})
    return result


class Security:
    def __init__(self, database_url, admin_upn=DEFAULT_ADMIN, realms=None,
                 session_ttl=28800, audit_retention=30, initialize=True):
        if not isinstance(database_url, str) or not database_url.strip():
            raise ValueError("DATABASE_URL is required for LDAP authentication")
        self.database_url = database_url
        self.realms = _realms(DEFAULT_REALMS if realms is None else realms)
        try:
            self.admin_upn = self.canonical(admin_upn)[0]
        except SecurityError:
            raise ValueError("ADMIN_UPN must identify a user in a configured LDAP realm") from None
        if not 60 <= session_ttl <= 604800 or not 1 <= audit_retention <= 3650:
            raise ValueError("Invalid session TTL or audit retention")
        self.session_ttl = session_ttl
        self.audit_retention = audit_retention
        self._maintenance_after = 0.0
        self._maintenance_lock = threading.Lock()
        if initialize:
            with self._db() as conn:
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (SCHEMA_LOCK,))
                conn.execute(SCHEMA)

    @classmethod
    def from_env(cls):
        for name in ("DATABASE_URL", "ADMIN_UPN", "LDAP_REALMS"):
            if not os.environ.get(name, "").strip():
                raise ValueError(f"{name} is required for LDAP authentication")
        try:
            realms = json.loads(os.environ["LDAP_REALMS"])
            ttl = int(os.environ.get("SESSION_TTL_SECONDS", "28800"))
            retention = int(os.environ.get("AUDIT_RETENTION_DAYS", "30"))
        except (ValueError, TypeError):
            raise ValueError("Invalid LDAP_REALMS, SESSION_TTL_SECONDS or AUDIT_RETENTION_DAYS") from None
        return cls(os.environ["DATABASE_URL"], os.environ["ADMIN_UPN"],
                   realms, ttl, retention)

    @contextmanager
    def _db(self, timeout=5):
        try:
            import psycopg
            from psycopg.rows import dict_row
            with psycopg.connect(self.database_url, connect_timeout=timeout, row_factory=dict_row,
                                 options=f"-c statement_timeout={timeout * 1000} -c lock_timeout={timeout * 1000}") as conn:
                yield conn
        except SecurityError:
            raise
        except Exception:
            # Never expose a DSN, LDAP credential, query contents or driver error.
            raise SecurityError(503, "Сервис авторизации временно недоступен.") from None

    def ready(self):
        with self._db(timeout=2) as conn:
            row = conn.execute("SELECT 1 AS ready").fetchone()
        return row["ready"] == 1

    def canonical(self, username):
        if not isinstance(username, str) or len(username) > 320:
            raise SecurityError(401, "Неверный логин или пароль.")
        username = username.strip().casefold()
        if any(not c.isprintable() for c in username):
            raise SecurityError(401, "Неверный логин или пароль.")
        if "\\" in username:
            alias, separator, local = username.partition("\\")
            realm = next((r for r in self.realms if alias in r["aliases"]), None)
        else:
            local, separator, domain = username.partition("@")
            realm = next((r for r in self.realms if domain == r["domain"]), None)
        if not separator or not realm or not re.fullmatch(r"[^@\\\s\x00-\x1f]{1,128}", local):
            raise SecurityError(401, "Неверный логин или пароль.")
        return f"{local}@{realm['domain']}", realm

    def _user(self, row):
        return {"username": row["username"], "role": "admin" if row["username"] == self.admin_upn else "viewer",
                "blocked": bool(row["blocked"]) and row["username"] != self.admin_upn,
                **{key: _iso(row[key]) for key in ("created_at", "last_login") if key in row}}

    def _bind(self, username, password, realm):
        connection = None
        try:
            import ldap3
            from ldap3.utils.conv import escape_filter_chars
            tls = ldap3.Tls(validate=ssl.CERT_REQUIRED) if realm["ssl"] else None
            server = ldap3.Server(realm["host"], port=realm["port"], use_ssl=realm["ssl"],
                                  tls=tls, connect_timeout=5, get_info=ldap3.NONE)
            connection = ldap3.Connection(server, user=username, password=password,
                                          authentication=ldap3.SIMPLE, auto_referrals=False,
                                          receive_timeout=5, read_only=True, check_names=False)
            if not connection.bind():
                return False
            query = "(&(objectClass=user)(userPrincipalName=" + escape_filter_chars(username) + "))"
            if not connection.search(realm["base_dn"], query, search_scope=ldap3.SUBTREE,
                                     attributes=["userPrincipalName"], size_limit=2, time_limit=5):
                return False
            entries = connection.entries
            return (connection.result.get("result") == 0 and len(entries) == 1
                    and str(entries[0]["userPrincipalName"].value).casefold() == username)
        except Exception:
            return False
        finally:
            if connection is not None:
                try:
                    connection.unbind()
                except Exception:
                    pass

    @staticmethod
    def _actor(actor):
        if isinstance(actor, dict):
            actor = actor.get("username", "")
        return _text(actor, 320).casefold()

    def _audit(self, conn, actor, event, ip, target="", outcome="success", details=None):
        from psycopg.types.json import Jsonb
        event = event if isinstance(event, str) and re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", event) else "invalid_event"
        conn.execute("""INSERT INTO traceyard_audit(actor,event,ip,target,outcome,details)
                        VALUES (%s,%s,%s,%s,%s,%s)""",
                     (self._actor(actor), event, _ip(ip), _text(target), _text(outcome, 32), Jsonb(_details(details))))

    def _maintenance(self, conn):
        if time.monotonic() < self._maintenance_after or not self._maintenance_lock.acquire(blocking=False):
            return
        try:
            self._maintenance_after = time.monotonic() + 300
            locked = conn.execute("SELECT pg_try_advisory_xact_lock(%s) AS acquired", (MAINTENANCE_LOCK,)).fetchone()
            if not locked["acquired"]:
                return
            conn.execute("INSERT INTO traceyard_maintenance(key,completed_at) VALUES ('cleanup','epoch') ON CONFLICT DO NOTHING")
            due = conn.execute("""UPDATE traceyard_maintenance SET completed_at=clock_timestamp()
                                  WHERE key='cleanup' AND completed_at < clock_timestamp()-interval '5 minutes'
                                  RETURNING key""").fetchone()
            if not due:
                return
            conn.execute("DELETE FROM traceyard_sessions WHERE expires_at <= clock_timestamp()")
            conn.execute("DELETE FROM traceyard_login_limits WHERE started_at < clock_timestamp()-interval '10 minutes'")
            conn.execute("DELETE FROM traceyard_audit WHERE created_at < clock_timestamp() - (%s * interval '1 day')", (self.audit_retention,))
        finally:
            self._maintenance_lock.release()

    @staticmethod
    def _limit_keys(username, ip):
        digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
        # All transactions acquire the IP lock before its account/IP lock.
        return [("ip:" + digest(ip), 20), ("account:" + digest(username + "\0" + ip), 5)]

    def _reserve_login(self, username, ip):
        keys = self._limit_keys(username, ip)
        with self._db() as conn:
            self._maintenance(conn)
            for key, limit in keys:
                conn.execute("INSERT INTO traceyard_login_limits(key) VALUES (%s) ON CONFLICT DO NOTHING", (key,))
                row = conn.execute("""UPDATE traceyard_login_limits SET
                    attempts=CASE WHEN started_at <= clock_timestamp()-interval '5 minutes' THEN 0 ELSE attempts END,
                    started_at=CASE WHEN started_at <= clock_timestamp()-interval '5 minutes' THEN clock_timestamp() ELSE started_at END
                    WHERE key=%s RETURNING attempts""", (key,)).fetchone()
                if row["attempts"] >= limit:
                    self._audit(conn, username, "login.rate_limited", ip, outcome="denied")
                    return False
            for key, _ in keys:
                conn.execute("UPDATE traceyard_login_limits SET attempts=attempts+1 WHERE key=%s", (key,))
        return True

    def login(self, username, password, ip):
        ip = _ip(ip)
        realm = None
        try:
            canonical, realm = self.canonical(username)
        except SecurityError:
            canonical = _text(username).casefold() or "unknown"
        if not self._reserve_login(canonical, ip):
            raise SecurityError(429, "Слишком много попыток входа. Повторите через 5 минут.")
        valid_password = (isinstance(password, str) and 1 <= len(password) <= 1024
                          and "\0" not in password)
        if realm is None or not valid_password or not self._bind(canonical, password, realm):
            self.audit(canonical, "login.failed", ip, outcome="denied")
            raise SecurityError(401, "Неверный логин или пароль.")
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        blocked = False
        with self._db() as conn:
            # Locking the user serializes login against an administrator's ban.
            conn.execute("INSERT INTO traceyard_users(username) VALUES (%s) ON CONFLICT DO NOTHING", (canonical,))
            row = conn.execute("SELECT * FROM traceyard_users WHERE username=%s FOR UPDATE", (canonical,)).fetchone()
            blocked = bool(row["blocked"]) and canonical != self.admin_upn
            if blocked:
                self._audit(conn, canonical, "login.blocked", ip, outcome="denied")
            else:
                row = conn.execute("""UPDATE traceyard_users SET last_login=clock_timestamp(),
                                      blocked=CASE WHEN username=%s THEN FALSE ELSE blocked END
                                      WHERE username=%s RETURNING *""", (self.admin_upn, canonical)).fetchone()
                session = conn.execute("""INSERT INTO traceyard_sessions(token_hash,username,csrf,expires_at)
                                          VALUES (%s,%s,%s,clock_timestamp()+(%s * interval '1 second'))
                                          RETURNING expires_at""",
                                       (hashlib.sha256(token.encode()).hexdigest(), canonical, csrf, self.session_ttl)).fetchone()
                self._audit(conn, canonical, "login.success", ip)
                # Successful authentication does not consume the failed-login budget.
                for key, _ in self._limit_keys(canonical, ip):
                    conn.execute("UPDATE traceyard_login_limits SET attempts=GREATEST(0,attempts-1) WHERE key=%s", (key,))
        if blocked:
            raise SecurityError(403, "Доступ к Traceyard заблокирован администратором.")
        return {"token": token, "csrf": csrf, "user": self._user(row), "expires": _iso(session["expires_at"])}

    @staticmethod
    def _token_hash(token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        return hashlib.sha256(token.encode()).hexdigest()

    def session(self, rawtoken):
        token_hash = self._token_hash(rawtoken)
        if token_hash is None:
            return None
        with self._db() as conn:
            self._maintenance(conn)
            row = conn.execute("""SELECT u.*,s.csrf,s.expires_at FROM traceyard_sessions s
                                  JOIN traceyard_users u USING(username)
                                  WHERE s.token_hash=%s AND s.expires_at > clock_timestamp()
                                  AND (NOT u.blocked OR u.username=%s)""", (token_hash, self.admin_upn)).fetchone()
        if not row:
            return None
        return {"csrf": row["csrf"], "user": self._user(row), "expires": _iso(row["expires_at"])}

    def logout(self, token, ip):
        token_hash = self._token_hash(token)
        with self._db() as conn:
            row = (conn.execute("DELETE FROM traceyard_sessions WHERE token_hash=%s RETURNING username", (token_hash,)).fetchone()
                   if token_hash else None)
            self._audit(conn, row["username"] if row else "anonymous", "logout", ip)

    @staticmethod
    def _page(limit, offset=0):
        if (isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200
                or isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 1000000):
            raise SecurityError(400, "Некорректные параметры страницы.")
        return limit, offset

    def users(self, limit=100, offset=0, search=""):
        self._page(limit, offset)
        if not isinstance(search, str) or len(search) > 256:
            raise SecurityError(400, "Слишком длинная строка поиска.")
        with self._db() as conn:
            rows = conn.execute("""SELECT * FROM traceyard_users WHERE strpos(username,%s)>0
                                   ORDER BY username LIMIT %s OFFSET %s""", (search.casefold(), limit, offset)).fetchall()
        return [self._user(row) for row in rows]

    def set_blocked(self, actor, target, blocked, ip):
        actor = self._actor(actor)
        if actor != self.admin_upn:
            self.audit(actor, "user.block.denied", ip, target=_text(target), outcome="denied")
            raise SecurityError(403, "Требуется роль администратора.")
        if not isinstance(blocked, bool):
            raise SecurityError(400, "blocked должен быть true или false.")
        try:
            target = self.canonical(target)[0]
        except SecurityError:
            raise SecurityError(400, "Некорректный пользователь.") from None
        if target == self.admin_upn:
            self.audit(actor, "user.block.denied", ip, target=target, outcome="denied")
            raise SecurityError(400, "Нельзя заблокировать единственного администратора.")
        with self._db() as conn:
            # Update obtains the same user row lock as login before touching sessions.
            row = conn.execute("UPDATE traceyard_users SET blocked=%s WHERE username=%s RETURNING *", (blocked, target)).fetchone()
            if row:
                if blocked:
                    conn.execute("DELETE FROM traceyard_sessions WHERE username=%s", (target,))
                self._audit(conn, actor, "user.blocked" if blocked else "user.unblocked", ip, target=target)
            else:
                self._audit(conn, actor, "user.block.denied", ip, target=target, outcome="not_found")
        if not row:
            raise SecurityError(404, "Пользователь не найден.")
        return self._user(row)

    def audit(self, actor, event, ip, target="", outcome="success", details=None):
        with self._db() as conn:
            self._maintenance(conn)
            self._audit(conn, actor, event, ip, target, outcome, details)

    def audit_rows(self, limit=100, before=None, actor="", event=""):
        self._page(limit)
        if before is not None and (isinstance(before, bool) or not isinstance(before, int) or not 1 <= before <= 2**63 - 1):
            raise SecurityError(400, "Некорректный курсор аудита.")
        if not isinstance(actor, str) or len(actor) > 256 or not isinstance(event, str) or len(event) > 80:
            raise SecurityError(400, "Некорректные фильтры аудита.")
        with self._db() as conn:
            rows = conn.execute("""SELECT * FROM traceyard_audit
                                   WHERE (%s::bigint IS NULL OR id < %s)
                                   AND (%s='' OR actor=%s) AND (%s='' OR event=%s)
                                   ORDER BY id DESC LIMIT %s""",
                                (before, before, actor, actor.casefold(), event, event, limit)).fetchall()
        return [{key: _iso(value) for key, value in row.items()} for row in rows]
