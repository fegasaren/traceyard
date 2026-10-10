"""Opt-in HTTP authentication tests against a disposable PostgreSQL database.

Set TEST_DATABASE_URL to an existing PostgreSQL database whose name ends in
``_test``. Only Traceyard tables in that database are cleared between tests.
Two real HTTP replicas share PostgreSQL; only the LDAP bind is mocked.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.client import HTTPConnection
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ORIGIN = "http://traceyard.test"
ADMIN = "admin@example.org"
ALICE = "alice@example.org"
TEST_PASSWORD = "test-pass"


def validated_test_database(value):
    """Validate the actual libpq database before any connection or mutation."""
    from psycopg.conninfo import conninfo_to_dict
    parsed = urlsplit(value)
    name = unquote(parsed.path.removeprefix("/"))
    if parsed.scheme not in ("postgres", "postgresql") or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*_test", name):
        raise ValueError("TEST_DATABASE_URL must be a PostgreSQL URL with a database name ending in _test")
    info = conninfo_to_dict(value)
    if info.get("dbname") != name:
        raise ValueError("TEST_DATABASE_URL may not override the database name through query parameters")
    return value


class AuthIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get("TEST_DATABASE_URL")
        if not value:
            raise unittest.SkipTest("Set TEST_DATABASE_URL to an isolated PostgreSQL database ending in _test")
        cls.dsn = validated_test_database(value)
        import psycopg
        from security import DEFAULT_REALMS, Security, SecurityError
        from server import AppServer, Config
        cls.psycopg, cls.SecurityError = psycopg, SecurityError
        cls.servers = []
        cls.threads = []
        cls.ldap_patch = patch.object(Security, "_bind", side_effect=lambda username, password, realm: password == TEST_PASSWORD)
        cls.ldap = cls.ldap_patch.start()
        cls.addClassCleanup(cls.ldap_patch.stop)
        for _ in range(2):
            with patch.dict(os.environ, {"TRACE_MODE": "demo", "AUTH_MODE": "ldap", "DATABASE_URL": cls.dsn,
                                         "PUBLIC_ORIGIN": ORIGIN, "ADMIN_UPN": ADMIN,
                                         "LDAP_REALMS": json.dumps(DEFAULT_REALMS)}, clear=True):
                config = Config()
            server = AppServer(("127.0.0.1", 0), config)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            cls.servers.append(server)
            cls.threads.append(thread)
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)

    def setUp(self):
        self.wait_idle()
        with self.psycopg.connect(self.dsn, connect_timeout=3) as conn:
            conn.execute("""TRUNCATE traceyard_sessions,traceyard_users,traceyard_audit,
                            traceyard_login_limits,traceyard_maintenance RESTART IDENTITY CASCADE""")
        self.ldap.reset_mock()

    def wait_idle(self):
        deadline = time.monotonic() + 5
        while any(server.active.collect()[0].samples[0].value for server in self.servers):
            if time.monotonic() > deadline:
                self.fail("HTTP replicas did not become idle")
            time.sleep(0.005)

    def request(self, path, *, replica=0, method="GET", body=None, cookie=None, csrf=None, origin=ORIGIN, headers=None, wait=True):
        request_headers = dict(headers or {})
        if cookie:
            request_headers["Cookie"] = cookie
        if csrf is not None:
            request_headers["X-CSRF-Token"] = csrf
        if body is not None:
            request_headers["Content-Type"] = "application/json"
        if origin is not None:
            request_headers["Origin"] = origin
        data = json.dumps(body).encode() if body is not None else None
        connection = HTTPConnection("127.0.0.1", self.servers[replica].server_port, timeout=10)
        try:
            connection.request(method, path, body=data, headers=request_headers)
            response = connection.getresponse()
            status, response_headers, content = response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()
        if wait:
            self.wait_idle()
        if response_headers.get("Content-Type", "").startswith("application/json"):
            content = json.loads(content)
        else:
            content = content.decode()
        return status, response_headers, content

    def login(self, username=ALICE, *, replica=0):
        status, headers, body = self.request("/api/login", replica=replica, method="POST",
                                            body={"username": username, "password": TEST_PASSWORD})
        self.assertEqual(status, 200, body)
        cookie = SimpleCookie()
        cookie.load(headers["Set-Cookie"])
        return {"cookie": "traceyard_session=" + cookie["traceyard_session"].value,
                "token": cookie["traceyard_session"].value, "csrf": body["csrf"],
                "user": body["user"], "headers": headers}

    def block(self, admin, username, blocked, *, replica=0):
        return self.request("/api/admin/users/block", replica=replica, method="POST",
                            cookie=admin["cookie"], csrf=admin["csrf"], body={"username": username, "blocked": blocked})

    def test_database_guard_rejects_non_test_or_query_override(self):
        for dsn in ("postgresql://localhost/traceyard", "postgresql://localhost/production_test?dbname=production", "dbname=production_test"):
            with self.subTest(dsn=dsn), self.assertRaises(ValueError):
                validated_test_database(dsn)

    def test_sessions_and_roles_work_across_two_replicas(self):
        viewer = self.login("MAIN\\ALICE")
        self.assertEqual(viewer["user"]["username"], ALICE)
        self.assertEqual(viewer["user"]["role"], "viewer")
        status, _, me = self.request("/api/me", replica=1, cookie=viewer["cookie"])
        self.assertEqual(status, 200)
        self.assertEqual(me["csrf"], viewer["csrf"])
        self.assertEqual(me["user"]["username"], ALICE)
        self.assertEqual(self.request("/api/admin/users", replica=1, cookie=viewer["cookie"])[0], 403)
        for username in ("MAIN\\ADMIN", ADMIN.upper()):
            admin = self.login(username, replica=1)
            self.assertEqual(admin["user"]["role"], "admin")
            self.assertEqual(self.request("/api/admin/users", cookie=admin["cookie"])[0], 200)

    def test_http_cookie_flags_and_logout_revoke_other_replica(self):
        viewer = self.login()
        header = viewer["headers"]["Set-Cookie"]
        self.assertIn("HttpOnly", header)
        self.assertIn("SameSite=Strict", header)
        self.assertNotIn("Secure", header)
        self.assertIn("Path=/", header)
        status, headers, _ = self.request("/api/logout", replica=1, method="POST", cookie=viewer["cookie"], csrf=viewer["csrf"], body={})
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(self.request("/api/me", cookie=viewer["cookie"])[0], 401)

    def test_ban_and_unban_never_resurrect_an_old_session(self):
        viewer, admin = self.login(), self.login(ADMIN)
        self.assertEqual(self.block(admin, ALICE, True)[0], 200)
        self.assertEqual(self.request("/api/me", replica=1, cookie=viewer["cookie"])[0], 401)
        self.assertEqual(self.request("/api/login", replica=1, method="POST", body={"username": ALICE, "password": TEST_PASSWORD})[0], 403)
        self.assertEqual(self.block(admin, ALICE, False, replica=1)[0], 200)
        self.assertEqual(self.request("/api/me", cookie=viewer["cookie"])[0], 401)
        replacement = self.login(replica=1)
        self.assertNotEqual(viewer["token"], replacement["token"])
        self.assertEqual(self.request("/api/me", cookie=replacement["cookie"])[0], 200)

    def test_admin_self_ban_and_viewer_mutation_are_rejected(self):
        admin, viewer = self.login(ADMIN), self.login()
        self.assertEqual(self.block(admin, "MAIN\\admin", True)[0], 400)
        self.assertEqual(self.block(viewer, ADMIN, True, replica=1)[0], 403)
        self.assertEqual(self.request("/api/me", replica=1, cookie=admin["cookie"])[0], 200)

    def test_wrong_origin_and_csrf_cannot_login_or_mutate(self):
        status, _, _ = self.request("/api/login", method="POST", origin="https://attacker.invalid",
                                    body={"username": ALICE, "password": TEST_PASSWORD})
        self.assertEqual(status, 403)
        self.ldap.assert_not_called()
        viewer = self.login()
        for csrf, origin in ((None, ORIGIN), ("invalid", ORIGIN), (viewer["csrf"], "https://attacker.invalid")):
            self.assertEqual(self.request("/api/logout", replica=1, method="POST", cookie=viewer["cookie"], csrf=csrf, origin=origin, body={})[0], 403)
        self.assertEqual(self.request("/api/me", cookie=viewer["cookie"])[0], 200)

    def test_trace_export_is_an_authenticated_json_attachment(self):
        viewer = self.login()
        status, _, results = self.request("/api/search?q=%7B%7D", cookie=viewer["cookie"])
        self.assertEqual(status, 200)
        trace_id = results["traces"][0]["traceID"]
        route = "/api/traces/" + trace_id + "/download"
        self.assertEqual(self.request(route)[0], 401)
        status, headers, data = self.request(route, replica=1, cookie=viewer["cookie"])
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Disposition"], f'attachment; filename="trace-{trace_id}.json"')
        self.assertTrue(data.get("resourceSpans") or data.get("batches") or data.get("trace"), data)

    def test_audit_is_serializable_paginated_and_omits_credentials_and_raw_query(self):
        viewer, admin = self.login(), self.login(ADMIN)
        query = '{ name = "audit-query-sensitive-marker" }'
        status, headers, _ = self.request("/api/search?" + urlencode({"q": query}), cookie=viewer["cookie"])
        self.assertEqual(status, 200)
        status, _, body = self.request("/api/admin/audit?limit=100", replica=1, cookie=admin["cookie"])
        self.assertEqual(status, 200)
        events = body["events"]
        serialized = json.dumps(events)
        for private in ("audit-query-sensitive-marker", TEST_PASSWORD, viewer["token"], viewer["csrf"]):
            self.assertNotIn(private, serialized)
        event = next(item for item in events if item["event"] == "trace.search")
        self.assertEqual(event["details"]["query_sha256"], hashlib.sha256(query.encode()).hexdigest())
        self.assertEqual(event["details"]["request_id"], headers["X-Request-ID"])
        self.assertEqual(event["actor"], ALICE)
        self.assertTrue(isinstance(event["created_at"], str))
        ids = [event["id"] for event in events]
        self.assertEqual(ids, sorted(ids, reverse=True))
        before = ids[len(ids) // 2]
        status, _, older = self.request(f"/api/admin/audit?before={before}", cookie=admin["cookie"])
        self.assertEqual(status, 200)
        self.assertTrue(all(item["id"] < before for item in older["events"]))
        with self.psycopg.connect(self.dsn, connect_timeout=3) as conn:
            stored = conn.execute("SELECT token_hash FROM traceyard_sessions WHERE username=%s", (ALICE,)).fetchall()
        self.assertEqual(stored, [(hashlib.sha256(viewer["token"].encode()).hexdigest(),)])

    def test_metrics_are_unauthenticated_and_route_cardinality_is_bounded(self):
        viewer = self.login()
        trace_ids = [f"{number:032x}" for number in range(8)]
        for trace_id in trace_ids:
            self.assertEqual(self.request("/api/traces/" + trace_id, cookie=viewer["cookie"])[0], 404)
        for number in range(8):
            self.assertEqual(self.request(f"/unknown-route-{number}")[0], 404)
        status, _, metrics = self.request("/metrics", origin=None)
        self.assertEqual(status, 200)
        for private in (ALICE, TEST_PASSWORD, viewer["token"], viewer["csrf"], *trace_ids):
            self.assertNotIn(private, metrics)
        route_values = set(re.findall(r'route="([^"]+)"', metrics))
        self.assertIn("/api/traces/{id}", route_values)
        self.assertIn("other", route_values)
        self.assertFalse(any(value.startswith("/unknown-route-") for value in route_values))
        self.assertLessEqual(len(route_values), 24)

    def test_login_failures_are_rate_limited_across_replicas(self):
        statuses = [self.request("/api/login", replica=number % 2, method="POST",
                                 body={"username": ALICE if number % 2 else "MAIN\\alice", "password": "wrong"})[0]
                    for number in range(6)]
        self.assertEqual(statuses, [401, 401, 401, 401, 401, 429])
        self.assertEqual(self.ldap.call_count, 5)

    def test_concurrent_login_reservations_do_not_exceed_shared_limit(self):
        def failed_login(number):
            return self.request("/api/login", replica=number % 2, method="POST", wait=False,
                                body={"username": ALICE, "password": "wrong"})[0]
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(failed_login, range(8)))
        self.wait_idle()
        self.assertEqual(statuses.count(401), 5, statuses)
        self.assertEqual(statuses.count(429), 3, statuses)
        self.assertEqual(self.ldap.call_count, 5)

    def test_real_postgres_audit_failure_blocks_data_before_response(self):
        viewer = self.login()
        # PostgreSQL rejects audit INSERTs while session reads remain functional.
        # This exercises real transactional failure without mocking the audit API.
        with self.psycopg.connect(self.dsn, connect_timeout=3) as conn:
            conn.execute("ALTER TABLE traceyard_audit ADD CONSTRAINT traceyard_test_reject_audit CHECK (false) NOT VALID")
        try:
            status, _, body = self.request("/api/search?q=%7B%7D", cookie=viewer["cookie"])
            self.assertEqual(status, 503, body)
            self.assertNotIn("traces", body)
            self.assertNotIn(self.dsn, json.dumps(body))
            self.assertNotIn("traceyard_test_reject_audit", json.dumps(body))
            status, _, metrics = self.request("/metrics")
            self.assertEqual(status, 200)
            failures = re.search(r"^traceyard_audit_failures_total ([0-9.e+]+)$", metrics, re.MULTILINE)
            self.assertIsNotNone(failures)
            self.assertGreaterEqual(float(failures.group(1)), 1)
        finally:
            with self.psycopg.connect(self.dsn, connect_timeout=3) as conn:
                conn.execute("ALTER TABLE traceyard_audit DROP CONSTRAINT traceyard_test_reject_audit")
        self.assertEqual(self.request("/api/search?q=%7B%7D", cookie=viewer["cookie"])[0], 200)


if __name__ == "__main__":
    unittest.main()
