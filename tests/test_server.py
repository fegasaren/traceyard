"""Exercise the public HTTP contract with a real app process and a fake Tempo.

Run from trace-ui: python3 -m unittest discover -s tests -v
No running Tempo instance is required; install requirements.txt first.
"""

from __future__ import annotations

import base64
import contextlib
import http.client
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit


APP_ROOT = Path(__file__).resolve().parents[1]


class FakeTempo:
    """Small programmable upstream that records exactly what reaches it."""

    def __init__(self):
        self.requests = []
        self.responder = self.default_response
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                request = {
                    "path": self.path,
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                }
                owner.requests.append(request)
                status, headers, body, delay = owner.responder(request)
                if delay:
                    time.sleep(delay)
                if not isinstance(body, bytes):
                    body = json.dumps(body).encode()
                try:
                    self.send_response(status)
                    for key, value in headers.items():
                        self.send_header(key, value)
                    if "content-length" not in {key.lower() for key in headers}:
                        self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @staticmethod
    def default_response(request):
        path = urlsplit(request["path"]).path
        if path == "/ready":
            return 200, {"Content-Type": "text/plain"}, b"ready", 0
        if path.endswith("/api/search"):
            body = {"traces": [], "metrics": {"inspectedTraces": 0}}
        elif path.endswith("/api/v2/search/tags"):
            body = {"scopes": [{"name": "resource", "tags": ["service.name"]}]}
        elif "/api/v2/search/tag/" in path:
            body = {"tagValues": [{"type": "string", "value": "checkout"}]}
        else:
            body = {"batches": []}
        return 200, {"Content-Type": "application/json"}, body, 0

    def start(self):
        self.thread.start()
        return self

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class RunningApp:
    def __init__(self, mode="demo", input_timeout=None, startup_code=None, **overrides):
        with contextlib.closing(socket.socket()) as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            self.port = port_socket.getsockname()[1]
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("TEMPO_", "TRACE_"))
        }
        environment.update(HOST="127.0.0.1", PORT=str(self.port), TRACE_MODE=mode, AUTH_MODE="disabled")
        environment.update({key: str(value) for key, value in overrides.items()})
        self.logs = tempfile.TemporaryFile(mode="w+b")
        command = [sys.executable, str(APP_ROOT / "server.py")]
        if input_timeout is not None or startup_code is not None:
            # Shorten only the fixture's deadline; production keeps a fixed 15s.
            setup = ["import server"]
            if input_timeout is not None:
                setup.append(f"server.INPUT_TIMEOUT_SECONDS = {float(input_timeout)!r}")
            if startup_code is not None:
                setup.append(startup_code)
            command = [sys.executable, "-c", "\n".join([*setup, "server.main()"])]
        self.process = subprocess.Popen(
            command,
            cwd=APP_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self.logs,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.logs.seek(0)
                details = self.logs.read().decode(errors="replace")
                self.close()
                raise AssertionError(f"App exited before becoming ready: {details}")
            try:
                if self.request("/healthz")[0] == 200:
                    break
            except (OSError, http.client.HTTPException):
                time.sleep(0.02)
        else:
            self.close()
            raise AssertionError("App did not become healthy within 8 seconds")

    def request(self, path, method="GET", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def json(self, path):
        status, headers, body = self.request(path)
        return status, json.loads(body)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.logs.close()


class ShutdownTests(unittest.TestCase):
    def test_idle_sigterm_and_sigint_exit_cleanly(self):
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum):
                app = RunningApp()
                try:
                    app.process.send_signal(signum)
                    self.assertEqual(app.process.wait(timeout=3), 0)
                finally:
                    app.close()

    def test_sigterm_drains_active_tempo_request_and_tolerates_repeated_signal(self):
        entered, release = threading.Event(), threading.Event()
        tempo = FakeTempo().start()

        def response(request):
            entered.set()
            release.wait(timeout=3)
            return tempo.default_response(request)

        tempo.responder = response
        app = RunningApp(mode="tempo", TEMPO_URL=tempo.url)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(app.request, "/api/search?q=%7B%7D")
                self.assertTrue(entered.wait(timeout=2))
                app.process.send_signal(signal.SIGTERM)
                # Exceed serve_forever's 0.25s poll; otherwise a daemon-worker
                # regression could complete before shutdown reaches server_close.
                with self.assertRaises(subprocess.TimeoutExpired):
                    app.process.wait(timeout=0.75)
                app.process.send_signal(signal.SIGTERM)
                self.assertIsNone(app.process.poll())
                release.set()
                self.assertEqual(result.result(timeout=3)[0], 200)
                self.assertEqual(app.process.wait(timeout=3), 0)
        finally:
            release.set()
            app.close()
            tempo.close()

    def test_sigterm_waits_for_completion_audit_after_response(self):
        with tempfile.TemporaryDirectory() as directory:
            entered = Path(directory) / "entered"
            release = Path(directory) / "release"
            completed = Path(directory) / "completed"
            # A gated audit sink proves shutdown drains work after the HTTP body
            # is delivered; PostgreSQL persistence is covered by integration tests.
            startup = f'''
original_config_init = server.Config.__init__
class GatedAudit:
    def session(self, _token):
        return {{"user": {{"username": "viewer@example.org", "role": "viewer"}}, "csrf": ""}}
    def audit(self, _actor, event, *_args):
        if event == "request.completed":
            server.Path({str(entered)!r}).touch()
            deadline = server.time.monotonic() + 3
            while not server.Path({str(release)!r}).exists():
                if server.time.monotonic() >= deadline:
                    raise RuntimeError("Test audit gate timed out")
                server.time.sleep(0.01)
            server.Path({str(completed)!r}).touch()
def configure(self):
    original_config_init(self)
    self.security = GatedAudit()
server.Config.__init__ = configure
'''
            app = RunningApp(startup_code=startup)
            try:
                self.assertEqual(app.request("/api/search?q=%7B%7D")[0], 200)
                deadline = time.monotonic() + 2
                while not entered.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(entered.exists())
                app.process.send_signal(signal.SIGTERM)
                with self.assertRaises(subprocess.TimeoutExpired):
                    app.process.wait(timeout=0.75)
                self.assertIsNone(app.process.poll())
                self.assertFalse(completed.exists())
                app.process.send_signal(signal.SIGTERM)
                release.touch()
                self.assertEqual(app.process.wait(timeout=3), 0)
                self.assertTrue(completed.exists())
            finally:
                release.touch()
                app.close()


class TempoProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempo = FakeTempo().start()

    @classmethod
    def tearDownClass(cls):
        cls.tempo.close()

    def setUp(self):
        self.tempo.requests.clear()
        self.tempo.responder = self.tempo.default_response
        self.app = None

    def tearDown(self):
        if self.app:
            self.app.close()

    def start_app(self, **overrides):
        settings = {"TEMPO_URL": self.tempo.url}
        settings.update(overrides)
        self.app = RunningApp(mode="tempo", **settings)
        return self.app

    def test_search_forwards_traceql_and_time_range_without_rewriting(self):
        app = self.start_app()
        query = '{ resource.service.name = "checkout" && duration > 25ms }'
        status, payload = app.json(
            "/api/search?q=" + quote(query, safe="") + "&start=1700000000&end=1700000600&limit=75"
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["traces"], [])
        upstream = urlsplit(self.tempo.requests[-1]["path"])
        self.assertEqual(upstream.path, "/api/search")
        self.assertEqual(parse_qs(upstream.query), {
            "q": [query], "start": ["1700000000"], "end": ["1700000600"], "limit": ["75"],
        })

    def test_tags_values_and_trace_have_expected_upstream_paths(self):
        app = self.start_app()
        trace_id = "0123456789abcdef0123456789abcdef"
        pairs = [
            ("/api/tags", "/api/v2/search/tags"),
            ("/api/tag-values?tag=resource.service.name", "/api/v2/search/tag/resource.service.name/values"),
            ("/api/traces/" + trace_id, "/api/traces/" + trace_id),
        ]
        for local, expected in pairs:
            with self.subTest(path=local):
                self.assertEqual(app.request(local)[0], 200)
                self.assertEqual(urlsplit(self.tempo.requests[-1]["path"]).path, expected)

    def test_server_side_bearer_and_tenant_override_browser_headers(self):
        app = self.start_app(TEMPO_BEARER_TOKEN="private-bearer-credential", TEMPO_TENANT_ID="tenant-a")
        status, _, _ = app.request("/api/search", headers={
            "Authorization": "Bearer browser-controlled",
            "X-Scope-OrgID": "untrusted-tenant",
        })
        self.assertEqual(status, 200)
        headers = self.tempo.requests[-1]["headers"]
        self.assertEqual(headers.get("authorization"), "Bearer private-bearer-credential")
        self.assertEqual(headers.get("x-scope-orgid"), "tenant-a")
        status, config = app.json("/api/config")
        self.assertEqual(status, 200)
        self.assertEqual(config["mode"], "tempo")
        self.assertEqual(config["backend"], "Tempo")
        self.assertEqual(config["defaultLimit"], 50)
        config_text = json.dumps(config)
        for sensitive in ("private-bearer-credential", "tenant-a", self.tempo.url):
            self.assertNotIn(sensitive, config_text)

    def test_basic_auth_is_added_only_to_upstream(self):
        app = self.start_app(TEMPO_USERNAME="tempo-user", TEMPO_PASSWORD="private-password")
        self.assertEqual(app.request("/api/tags")[0], 200)
        expected = "Basic " + base64.b64encode(b"tempo-user:private-password").decode()
        self.assertEqual(self.tempo.requests[-1]["headers"].get("authorization"), expected)
        for path in ("/api/config", "/", "/app.js"):
            status, _, body = app.request(path)
            self.assertEqual(status, 200)
            self.assertNotIn(b"private-password", body)
            self.assertNotIn(expected.encode(), body)

    def test_browser_credentials_are_not_forwarded_when_server_has_none(self):
        app = self.start_app()
        self.assertEqual(app.request("/api/search", headers={
            "Authorization": "Bearer browser-secret", "X-Scope-OrgID": "browser-tenant",
            "Cookie": "session=browser-session",
        })[0], 200)
        headers = self.tempo.requests[-1]["headers"]
        for name in ("authorization", "x-scope-orgid", "cookie"):
            self.assertNotIn(name, headers)

    def test_bad_search_bounds_never_reach_tempo(self):
        app = self.start_app()
        invalid = [
            "limit=0", "limit=1001", "limit=wat", "limit=1.5", "start=bad", "end=bad",
            "start=200&end=100", "start=100&end=100",
        ]
        for query in invalid:
            with self.subTest(query=query):
                before = len(self.tempo.requests)
                self.assertEqual(app.request("/api/search?" + query)[0], 400)
                self.assertEqual(len(self.tempo.requests), before)

    def test_invalid_trace_ids_and_unknown_api_paths_are_rejected_locally(self):
        app = self.start_app()
        invalid_ids = ["abc", "g" * 32, "a" * 33, "a" * 31, "../search"]
        for trace_id in invalid_ids:
            with self.subTest(trace_id=trace_id):
                before = len(self.tempo.requests)
                self.assertIn(app.request("/api/traces/" + trace_id)[0], (400, 404))
                self.assertEqual(len(self.tempo.requests), before)
        self.assertEqual(app.request("/api/unknown")[0], 404)
        self.assertEqual(app.request("/api/admin/delete")[0], 403)

    def test_readiness_tracks_tempo_while_liveness_stays_healthy(self):
        app = self.start_app()
        self.assertEqual(app.request("/readyz")[0], 200)
        self.assertEqual(self.tempo.requests[-1]["path"], "/ready")
        self.tempo.responder = lambda _: (503, {}, b"not ready", 0)
        self.assertEqual(app.request("/readyz")[0], 503)
        self.assertEqual(app.request("/healthz")[0], 200)

    def test_readiness_remains_available_during_two_active_searches(self):
        app = self.start_app()
        active = threading.Barrier(3)
        release = threading.Event()

        def respond(request):
            if urlsplit(request["path"]).path == "/api/search":
                active.wait(timeout=3)
                release.wait(timeout=3)
            return self.tempo.default_response(request)

        self.tempo.responder = respond
        with ThreadPoolExecutor(max_workers=2) as workers:
            searches = [workers.submit(app.request, "/api/search") for _ in range(2)]
            try:
                active.wait(timeout=3)
                self.assertEqual(app.request("/readyz")[0], 200)
            finally:
                release.set()
            self.assertEqual([request.result()[0] for request in searches], [200, 200])

    def test_upstream_errors_preserve_actionable_status_without_private_body(self):
        app = self.start_app(TEMPO_BEARER_TOKEN="private-bearer-credential")
        private_body = b"private-bearer-credential secret-stacktrace /private/tempo/config.yaml"
        for upstream_status, expected in ((400, 400), (404, 404), (401, 502), (500, 502)):
            with self.subTest(status=upstream_status):
                upstream_body = (
                    b"parse error at line 1: unexpected token private-bearer-credential"
                    if upstream_status == 400 else private_body
                )
                self.tempo.responder = lambda _, code=upstream_status, content=upstream_body: (code, {}, content, 0)
                status, _, body = app.request("/api/search")
                self.assertEqual(status, expected)
                self.assertTrue(body)
                self.assertNotIn(b"private-bearer-credential", body)
                self.assertNotIn(b"secret-stacktrace", body)
                self.assertNotIn(b"/private/tempo/config.yaml", body)
                if upstream_status == 400:
                    self.assertIn(b"parse error", body)

    def test_upstream_timeout_is_reported_as_gateway_timeout(self):
        app = self.start_app(TEMPO_TIMEOUT_SECONDS="0.05")
        self.tempo.responder = lambda _: (200, {"Content-Type": "application/json"}, {}, 0.25)
        self.assertEqual(app.request("/api/search")[0], 504)

    def test_redirects_are_not_followed_or_exposed_to_browser(self):
        app = self.start_app(TEMPO_BEARER_TOKEN="private-bearer-credential")
        self.tempo.responder = lambda _: (302, {"Location": self.tempo.url + "/redirect-target"}, b"", 0)
        before = len(self.tempo.requests)
        status, headers, _ = app.request("/api/search")
        self.assertEqual(status, 502)
        self.assertEqual(len(self.tempo.requests), before + 1)
        self.assertNotIn("location", {key.lower() for key in headers})

    def test_invalid_or_oversized_upstream_json_is_a_gateway_error(self):
        app = self.start_app()
        replies = [
            (200, {"Content-Type": "text/html"}, b"<html>login</html>", 0),
            (200, {"Content-Type": "application/json"}, b"{broken", 0),
            (200, {"Content-Type": "application/json"}, b'{"padding":"' + b"a" * (32 * 1024 * 1024) + b'"}', 0),
        ]
        for response in replies:
            with self.subTest(response=response[:2]):
                self.tempo.responder = lambda _, result=response: result
                self.assertEqual(app.request("/api/search")[0], 502)


class DemoAndStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = RunningApp(mode="demo")

    @classmethod
    def tearDownClass(cls):
        cls.app.close()

    def search(self, query="{}", **parameters):
        encoded = "q=" + quote(query, safe="")
        for key, value in parameters.items():
            encoded += f"&{key}={quote(str(value), safe='')}"
        status, payload = self.app.json("/api/search?" + encoded)
        self.assertEqual(status, 200, payload)
        return payload["traces"]

    def test_demo_search_trace_and_filter_use_consistent_data(self):
        traces = self.search()
        self.assertGreater(len(traces), 0)
        trace = traces[0]
        trace_id = trace["traceID"]
        status, payload = self.app.json("/api/traces/" + trace_id)
        self.assertEqual(status, 200)
        batches = payload.get("batches", payload.get("resourceSpans", []))
        spans = [
            span
            for batch in batches
            for scope in batch.get("scopeSpans", batch.get("instrumentationLibrarySpans", []))
            for span in scope.get("spans", [])
        ]
        self.assertGreater(len(spans), 1, "Demo must exercise the span waterfall, including children")
        self.assertTrue(any(span.get("parentSpanId") or span.get("parentSpanID") for span in spans))
        service = json.dumps(trace["rootServiceName"])
        filtered = self.search("{ resource.service.name = " + service + " }")
        self.assertIn(trace_id, [item["traceID"] for item in filtered])
        self.assertEqual(self.search('{ resource.service.name = "__missing_service_for_test__" }'), [])
        self.assertEqual(self.search('{ span.__missing_attribute_for_test__ = "absent" }'), [])
        self.assertEqual(self.search('{ resource.__missing_attribute_for_test__ = "absent" }'), [])

    def test_demo_duration_time_and_limit_filters_are_effective(self):
        traces = self.search(limit=1000)
        max_duration = max(trace["durationMs"] for trace in traces)
        self.assertEqual(self.search("{ duration > " + str(max_duration + 1000) + "ms }"), [])
        self.assertEqual(self.search("{ duration < 0ms }"), [])
        self.assertEqual(len(self.search(limit=1)), 1)
        self.assertEqual(self.search(start=1, end=2), [])

    def test_demo_name_and_error_filters_match_span_contents(self):
        trace = self.search()[0]
        matching = self.search("{ name = " + json.dumps(trace["rootTraceName"]) + " }")
        self.assertIn(trace["traceID"], [item["traceID"] for item in matching])
        self.assertEqual(self.search('{ name = "__missing_span_for_test__" }'), [])
        errors = self.search("{ status = error }")
        self.assertGreater(len(errors), 0, "Demo should include failures to exercise the error filter")
        for trace in errors:
            status, payload = self.app.json("/api/traces/" + trace["traceID"])
            self.assertEqual(status, 200)
            batches = payload.get("batches", payload.get("resourceSpans", []))
            spans = [
                span
                for batch in batches
                for scope in batch.get("scopeSpans", batch.get("instrumentationLibrarySpans", []))
                for span in scope.get("spans", [])
            ]
            self.assertTrue(any(
                span.get("status", {}).get("code") in (2, "2", "STATUS_CODE_ERROR")
                for span in spans
            ), "A trace selected by status = error must contain an errored span")

    def test_demo_rejects_unsupported_traceql_instead_of_silently_ignoring_it(self):
        for query in ("{} | count() > 0", "{ duration > 1ms } >> { status = error }"):
            with self.subTest(query=query):
                self.assertEqual(self.app.request("/api/search?q=" + quote(query, safe=""))[0], 400)

    def test_static_allowlist_hides_source_and_path_traversal(self):
        for path in ("/", "/index.html", "/app.js", "/styles.css"):
            with self.subTest(path=path):
                status, _, body = self.app.request(path)
                self.assertEqual(status, 200)
                self.assertGreater(len(body), 0)
        for path in ("/server.py", "/demo.py", "/.env", "/../server.py", "/%2e%2e/server.py"):
            with self.subTest(path=path):
                self.assertIn(self.app.request(path)[0], (400, 404))

    def test_mutating_http_methods_are_rejected(self):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                self.assertEqual(self.app.request("/api/search", method=method)[0], 405)


class RequestBoundaryTests(unittest.TestCase):
    def test_unknown_method_cannot_inject_untrusted_data_into_logs(self):
        app = RunningApp()
        try:
            with socket.create_connection(("127.0.0.1", app.port), timeout=2) as client:
                client.sendall(b"PRIVATE-marker\x1b[31m /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                while client.recv(4096):
                    pass
            app.logs.seek(0)
            logs = app.logs.read().decode(errors="replace")
            self.assertIn("other /healthz", logs)
            self.assertNotIn("PRIVATE-marker", logs)
            self.assertNotIn("\x1b", logs)
        finally:
            app.close()

    def test_dribbled_headers_and_body_have_a_total_input_deadline(self):
        prefixes = {
            "headers": b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Slow: ",
            "body": b"POST /api/events HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 8192\r\n\r\n{\"event\":\"",
        }
        for name, prefix in prefixes.items():
            with self.subTest(part=name):
                app = RunningApp(input_timeout=0.35, HTTP_MAX_CONCURRENCY=1)
                stopped = threading.Event()
                try:
                    # Let the startup probe finish releasing the sole worker slot.
                    time.sleep(0.04)
                    with socket.create_connection(("127.0.0.1", app.port), timeout=2) as client:
                        client.sendall(prefix)

                        def drip():
                            while not stopped.wait(0.04):
                                try:
                                    client.sendall(b"a")
                                except OSError:
                                    break

                        writer = threading.Thread(target=drip, daemon=True)
                        started = time.monotonic()
                        writer.start()
                        response = b""
                        while chunk := client.recv(4096):
                            response += chunk
                        elapsed = time.monotonic() - started
                        stopped.set()
                        writer.join(timeout=1)
                    self.assertLess(elapsed, 1.5)
                    self.assertIn(b"408", response.split(b"\r\n", 1)[0])
                    deadline = time.monotonic() + 1
                    while True:
                        try:
                            self.assertEqual(app.request("/healthz")[0], 200)
                            break
                        except (OSError, http.client.HTTPException):
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.02)
                finally:
                    stopped.set()
                    app.close()


if __name__ == "__main__":
    unittest.main()
