"""Security boundary tests. Directory traffic is mocked; no live AD binds."""
import hashlib
import json
import os
import sys
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security import DEFAULT_ADMIN, DEFAULT_REALMS, Security, SecurityError, _details, _ip, _realms


class StubConnection:
    def __init__(self, responder):
        self.calls = []
        self.responder = responder

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        result = self.responder(sql, params)
        return SimpleNamespace(fetchone=lambda: result, fetchall=lambda: result)


@contextmanager
def database(connection):
    yield connection


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.security = Security("postgresql://unused", initialize=False)
        self.now = datetime(2026, 10, 10, tzinfo=timezone.utc)

    def user(self, name="viewer@example.org", blocked=False):
        return {"username": name, "blocked": blocked, "last_login": self.now, "created_at": self.now}

    def test_upn_and_netbios_names_have_one_canonical_account(self):
        canonical = self.security.canonical("MAIN\\Some.User")[0]
        self.assertEqual(canonical, "some.user@example.org")
        self.assertEqual(canonical, self.security.canonical("Some.User@EXAMPLE.ORG")[0])
        self.assertEqual(self.security.canonical("user@regions.example.org")[1]["host"], "regions.example.org")

    def test_unsupported_identity_shapes_are_rejected(self):
        for username in (None, "", "user", "evil\\user", "u@attacker.test", "u@example.org@evil",
                         "main\\user\\other", "a\0b@example.org", "a\x7fb@regions.example.org", "x" * 129 + "@regions.example.org"):
            with self.subTest(username=username), self.assertRaises(SecurityError) as caught:
                self.security.canonical(username)
            self.assertEqual(caught.exception.status, 401)

    def test_admin_is_derived_from_config_and_never_a_db_role(self):
        admin = self.user(DEFAULT_ADMIN, blocked=True)
        admin["role"] = "viewer"
        self.assertEqual(self.security._user(admin)["role"], "admin")
        self.assertFalse(self.security._user(admin)["blocked"])
        viewer = self.user()
        viewer["role"] = "admin"
        self.assertEqual(self.security._user(viewer)["role"], "viewer")
        other = Security("postgresql://unused", admin_upn="other@regions.example.org", initialize=False)
        self.assertEqual(other._user(admin)["role"], "viewer")

    def test_config_validation_rejects_ambiguous_or_credential_urls(self):
        for changes in ({"url": "ldap://user:password@example.test"}, {"url": "http://example.test"},
                        {"url": "ldap://example.test/query"}, {"aliases": "main"}, {"base_dn": "a\nb"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                _realms([{**DEFAULT_REALMS[0], **changes}])
        with self.assertRaises(ValueError):
            _realms([DEFAULT_REALMS[0], DEFAULT_REALMS[0]])
        with self.assertRaisesRegex(ValueError, "ADMIN_UPN"):
            Security("postgresql://unused", admin_upn="user@unknown.test", initialize=False)

    def test_ldap_environment_requires_explicit_deployment_identity(self):
        complete = {"DATABASE_URL": "postgresql://unused", "ADMIN_UPN": DEFAULT_ADMIN,
                    "LDAP_REALMS": json.dumps(DEFAULT_REALMS)}
        for missing in complete:
            configured = {key: value for key, value in complete.items() if key != missing}
            with self.subTest(missing=missing), patch.dict(os.environ, configured, clear=True):
                with self.assertRaisesRegex(ValueError, missing):
                    Security.from_env()

    def test_ldap_uses_own_bind_no_referrals_and_escaped_single_user_lookup(self):
        import ldap3
        username, realm = self.security.canonical("u*(x)@example.org")
        conn = MagicMock()
        conn.bind.return_value = True
        conn.search.return_value = True
        conn.result = {"result": 0}
        entry = MagicMock()
        entry.__getitem__.return_value.value = username.upper()
        conn.entries = [entry]
        with patch.object(ldap3, "Server") as server, patch.object(ldap3, "Connection", return_value=conn) as factory:
            self.assertTrue(self.security._bind(username, "temporary-password", realm))
        kwargs = factory.call_args.kwargs
        self.assertEqual(kwargs["user"], username)
        self.assertEqual(kwargs["password"], "temporary-password")
        self.assertFalse(kwargs["auto_referrals"])
        self.assertEqual(kwargs["receive_timeout"], 5)
        self.assertEqual(server.call_args.kwargs["connect_timeout"], 5)
        self.assertIn(r"u\2a\28x\29@", conn.search.call_args.args[1])
        self.assertEqual(conn.search.call_args.kwargs["size_limit"], 2)
        self.assertEqual(conn.search.call_args.kwargs["time_limit"], 5)
        conn.unbind.assert_called_once()

    def test_ldap_rejects_duplicate_and_partial_search_results(self):
        import ldap3
        username, realm = self.security.canonical(DEFAULT_ADMIN)
        conn = MagicMock()
        conn.bind.return_value = conn.search.return_value = True
        entry = MagicMock()
        entry.__getitem__.return_value.value = username
        with patch.object(ldap3, "Server"), patch.object(ldap3, "Connection", return_value=conn):
            for entries, code in (([entry, entry], 0), ([entry], 4), ([], 0)):
                conn.entries, conn.result = entries, {"result": code}
                self.assertFalse(self.security._bind(username, "temporary-password", realm))

    def test_password_validation_happens_before_directory_bind(self):
        with patch.object(self.security, "_reserve_login", return_value=True), patch.object(self.security, "audit"), patch.object(self.security, "_bind") as bind:
            for password in (None, "", "x\0y", "x" * 1025):
                with self.subTest(length=len(password) if password else 0), self.assertRaises(SecurityError) as caught:
                    self.security.login(DEFAULT_ADMIN, password, "127.0.0.1")
                self.assertEqual(caught.exception.status, 401)
            bind.assert_not_called()

    def test_rate_limited_login_does_not_call_ldap(self):
        with patch.object(self.security, "_reserve_login", return_value=False), patch.object(self.security, "_bind") as bind:
            with self.assertRaises(SecurityError) as caught:
                self.security.login(DEFAULT_ADMIN, "temporary-password", "127.0.0.1")
        self.assertEqual(caught.exception.status, 429)
        bind.assert_not_called()

    def test_failed_auth_is_audited_without_password(self):
        with patch.object(self.security, "_reserve_login", return_value=True), patch.object(self.security, "_bind", return_value=False), patch.object(self.security, "audit") as audit:
            with self.assertRaises(SecurityError):
                self.security.login(DEFAULT_ADMIN, "private-not-for-audit", "127.0.0.1")
        self.assertEqual(audit.call_args.args[1], "login.failed")
        self.assertNotIn("private-not-for-audit", str(audit.call_args))

    def test_login_returns_raw_token_only_to_caller_and_persists_hash(self):
        def responder(sql, params):
            if sql.startswith("SELECT * FROM traceyard_users") or sql.startswith("UPDATE traceyard_users"):
                return self.user()
            if "INSERT INTO traceyard_sessions" in sql:
                return {"expires_at": self.now}
            return None
        conn = StubConnection(responder)
        with patch.object(self.security, "_reserve_login", return_value=True), patch.object(self.security, "_bind", return_value=True), patch.object(self.security, "_db", lambda: database(conn)), patch.object(self.security, "_audit") as audit:
            result = self.security.login("MAIN\\viewer", "private-password", "127.0.0.1")
        self.assertEqual(result["user"]["role"], "viewer")
        self.assertEqual(len(result["token"]), 43)
        self.assertEqual(len(result["csrf"]), 43)
        self.assertNotEqual(result["token"], result["csrf"])
        stored = next(params for sql, params in conn.calls if "INSERT INTO traceyard_sessions" in sql)
        self.assertEqual(stored[0], hashlib.sha256(result["token"].encode()).hexdigest())
        self.assertNotIn(result["token"], str(conn.calls))
        self.assertNotIn("private-password", str(conn.calls) + str(audit.call_args))

    def test_blocked_login_creates_no_session_and_records_denial(self):
        conn = StubConnection(lambda sql, params: self.user(blocked=True))
        with patch.object(self.security, "_reserve_login", return_value=True), patch.object(self.security, "_bind", return_value=True), patch.object(self.security, "_db", lambda: database(conn)), patch.object(self.security, "_audit") as audit:
            with self.assertRaises(SecurityError) as caught:
                self.security.login("MAIN\\viewer", "private-password", "127.0.0.1")
        self.assertEqual(caught.exception.status, 403)
        self.assertFalse(any("INSERT INTO traceyard_sessions" in sql for sql, _ in conn.calls))
        self.assertEqual(audit.call_args.args[2], "login.blocked")

    def test_invalid_sessions_do_not_open_database_connections(self):
        with patch.object(self.security, "_db") as db:
            for token in (None, "", "x" * 42, "x" * 44, "a/b" + "x" * 40):
                self.assertIsNone(self.security.session(token))
        db.assert_not_called()

    def test_session_checks_ban_and_expiry_in_database_and_serializes_dates(self):
        row = {**self.user(), "csrf": "csrf-value", "expires_at": self.now}
        conn = StubConnection(lambda sql, params: row)
        token = "x" * 43
        with patch.object(self.security, "_db", lambda: database(conn)), patch.object(self.security, "_maintenance"):
            result = self.security.session(token)
        sql, params = conn.calls[0]
        self.assertIn("NOT u.blocked", sql)
        self.assertIn("s.expires_at > clock_timestamp()", sql)
        self.assertEqual(params[0], hashlib.sha256(token.encode()).hexdigest())
        self.assertNotIn(token, str(conn.calls))
        self.assertEqual(result["user"]["last_login"], self.now.isoformat())
        self.assertEqual(result["expires"], self.now.isoformat())

    def test_ban_and_revocation_and_audit_share_one_transaction(self):
        conn = StubConnection(lambda sql, params: self.user(blocked=True) if sql.startswith("UPDATE traceyard_users") else None)
        with patch.object(self.security, "_db", lambda: database(conn)), patch.object(self.security, "_audit") as audit:
            user = self.security.set_blocked(DEFAULT_ADMIN, "MAIN\\viewer", True, "127.0.0.1")
        self.assertTrue(user["blocked"])
        self.assertIn("DELETE FROM traceyard_sessions", conn.calls[1][0])
        self.assertIs(audit.call_args.args[0], conn)
        self.assertEqual(audit.call_args.args[2], "user.blocked")

    def test_viewer_cannot_ban_and_admin_cannot_be_banned(self):
        with patch.object(self.security, "audit"), patch.object(self.security, "_db") as db:
            with self.assertRaises(SecurityError) as caught:
                self.security.set_blocked("viewer@regions.example.org", DEFAULT_ADMIN, True, "127.0.0.1")
            self.assertEqual(caught.exception.status, 403)
            with self.assertRaises(SecurityError) as caught:
                self.security.set_blocked(DEFAULT_ADMIN, "MAIN\\admin", True, "127.0.0.1")
            self.assertEqual(caught.exception.status, 400)
        db.assert_not_called()

    def test_database_exception_is_fail_closed_and_has_no_private_details(self):
        import psycopg
        with patch.object(psycopg, "connect", side_effect=RuntimeError("dsn=password-private")):
            with self.assertRaises(SecurityError) as caught:
                self.security.session("x" * 43)
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn("password-private", str(caught.exception))

    def test_readiness_checks_database_with_two_second_timeouts(self):
        import psycopg
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.execute.return_value.fetchone.return_value = {"ready": 1}
        with patch.object(psycopg, "connect", return_value=conn) as connect:
            self.assertTrue(self.security.ready())
        self.assertEqual(connect.call_args.kwargs["connect_timeout"], 2)
        self.assertIn("statement_timeout=2000", connect.call_args.kwargs["options"])
        conn.execute.assert_called_once_with("SELECT 1 AS ready")

    def test_required_audit_failure_is_fail_closed(self):
        import psycopg
        with patch.object(psycopg, "connect", side_effect=RuntimeError("private-dsn")):
            with self.assertRaises(SecurityError) as caught:
                self.security.audit("viewer@regions.example.org", "search", "127.0.0.1")
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn("private-dsn", str(caught.exception))

    def test_metadata_has_strict_bounds_and_rejects_secret_fields(self):
        data = _details({"password": "private", "access_token": "private", "csrf": "private",
                         "route": "/api/search\nforged log", "count": 4, "nested": {"password": "private"},
                         "long": "a" * 999, "bad\nkey": "x", "duration_ms": 12.34, "invalid": float("nan")})
        self.assertEqual(data, {"route": "/api/searchforged log", "count": 4, "long": "a" * 256, "duration_ms": 12.34})
        self.assertEqual(_ip("127.0.0.1\nforged"), "unknown")
        self.assertLessEqual(len(_details({f"field{i}": i for i in range(100)})), 20)

    def test_pagination_rejects_arbitrary_cursor_and_bool_limits(self):
        for kwargs in ({"before": "2026-01-01"}, {"before": -1}, {"limit": 0}, {"limit": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(SecurityError):
                self.security.audit_rows(**kwargs)


if __name__ == "__main__":
    unittest.main()
