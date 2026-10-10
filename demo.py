"""Explicit, deterministic demonstration data; never a fallback for Tempo errors."""
from __future__ import annotations

import hashlib
import copy
import json
import random
import re
import time


class QueryError(ValueError):
    pass


def identifier(seed, width=16):
    return hashlib.sha256(seed.encode()).hexdigest()[:width]


def otlp_value(value):
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def attributes(values):
    return [{"key": key, "value": otlp_value(value)} for key, value in values.items()]


def parse_query(query):
    """Small honest subset of TraceQL for the offline demo's filter builder."""
    if not query or query.strip() == "{}":
        return []
    query = query.strip()
    if not query.startswith("{") or not query.endswith("}"):
        raise QueryError("Демо поддерживает только {условие && условие}. Полный TraceQL доступен при подключении к Tempo.")
    expression = query[1:-1].strip()
    if not expression:
        return []
    token = re.compile(r'\s*(?P<field>(?:resource\.|span\.)[A-Za-z_][\w.:/-]*|name|status|duration|kind)\s*(?P<op>=~|!~|!=|>=|<=|=|>|<)\s*(?P<value>"(?:[^"\\]|\\.)*"|(?:\d+(?:\.\d+)?)(?:ns|us|ms|s|m|h)?|true|false|error|ok|unset|server|client|internal|producer|consumer)\s*')
    conditions = []
    pos = 0
    while pos < len(expression):
        match = token.match(expression, pos)
        if not match:
            raise QueryError("Это выражение не поддерживается деморежимом. Используйте фильтры или подключите Tempo для полного TraceQL.")
        field, operator, raw = match.group("field", "op", "value")
        if raw.startswith('"'):
            try:
                value = json.loads(raw)
            except ValueError as exc:
                raise QueryError("Некорректная строка TraceQL.") from exc
        elif field == "duration":
            duration = re.fullmatch(r"(\d+(?:\.\d+)?)(ns|us|ms|s|m|h)", raw)
            if not duration:
                raise QueryError("Укажите единицу длительности: ms, s, us или ns.")
            scale = {"ns": 1e-6, "us": 1e-3, "ms": 1, "s": 1000, "m": 60000, "h": 3600000}
            value = float(duration[1]) * scale[duration[2]]
        elif raw in ("true", "false"):
            value = raw == "true"
        elif raw[0].isdigit():
            try:
                value = float(raw)
            except ValueError as exc:
                raise QueryError("Единицы длительности допустимы только для duration.") from exc
        else:
            value = raw
        if operator in ("=~", "!~"):
            # Bound regex complexity for the public demonstration endpoint.
            if not isinstance(value, str) or len(value) > 200 or re.search(r"(?<!\\)[(){}]|\\[1-9]", value):
                raise QueryError("Демо поддерживает простые регулярные выражения без групп и повторений {n}.")
            if re.search(r"(?:\*|\+|\?)\s*(?:\*|\+|\?)", value):
                raise QueryError("Слишком сложное регулярное выражение для деморежима.")
            try:
                value = re.compile(value)
            except re.error as exc:
                raise QueryError("Некорректное регулярное выражение.") from exc
        conditions.append((field, operator, value))
        pos = match.end()
        if pos == len(expression):
            break
        if expression[pos:pos + 2] != "&&":
            raise QueryError("Демо поддерживает объединение условий через &&. Полный TraceQL доступен в Tempo.")
        pos += 2
        if not expression[pos:].strip():
            raise QueryError("После && требуется условие.")
    return conditions


def matches(span, conditions):
    for field, operator, expected in conditions:
        if field.startswith("resource."):
            actual = span["resource"].get(field[9:])
        elif field.startswith("span."):
            actual = span["attrs"].get(field[5:])
        else:
            actual = span.get(field)
        if actual is None:
            return False
        try:
            if operator == "=":
                good = actual == expected
            elif operator == "!=":
                good = actual != expected
            elif operator == "=~":
                good = bool(expected.fullmatch(str(actual)))
            elif operator == "!~":
                good = not expected.fullmatch(str(actual))
            elif operator == ">":
                good = actual > expected
            elif operator == "<":
                good = actual < expected
            elif operator == ">=":
                good = actual >= expected
            else:
                good = actual <= expected
        except TypeError:
            return False
        if not good:
            return False
    return True


class DemoStore:
    def __init__(self):
        self.items = []
        randomizer = random.Random(712)
        now = int(time.time())
        self.generated_at = now
        for index in range(90):
            trace_id = identifier(f"trace-{index}", 32)
            # Dense recent traffic and some older traces for time-range exploration.
            age = 25 + index * 27 if index < 35 else 1200 + (index - 35) * 700
            start_ns = (now - age) * 1_000_000_000 + randomizer.randint(0, 999999) * 1000
            error = index % 7 == 0
            route = ("/api/checkout", "/api/products", "/api/orders", "/api/cart")[index % 4]
            duration = round(randomizer.uniform(160, 1450) if error else randomizer.uniform(22, 420), 2)
            method = "GET" if route in ("/api/products", "/api/orders") else "POST"
            environment = "staging" if index % 9 == 0 else "production"
            services = ["api-gateway", "checkout-api", "inventory-api", "payment-api", "postgres", "redis"]
            specs = [
                (0, None, method + " " + route, 0, 1, "server"),
                (1, 0, "checkout.process" if method == "POST" else "catalog.list", .025, .91, "server"),
                (5, 1, "GET session", .04, .05, "client"),
                (2, 1, "GET /inventory/availability", .12, .25, "client"),
                (4, 3, "SELECT inventory", .14, .19, "client"),
                (3, 1, "POST /payments/authorize", .4, .43, "client"),
                (4, 5, "INSERT payment", .45, .13, "client"),
                (1, 1, "order.publish", .85, .04, "producer"),
            ]
            spans, batches = [], []
            for number, (service_idx, parent_idx, name, offset, fraction, kind) in enumerate(specs):
                span_id = identifier(f"{trace_id}-{number}")
                begin = start_ns + int(duration * offset * 1e6)
                span_duration = duration * fraction
                failed = error and number in (0, 1, 5)
                resource = {"service.name": services[service_idx], "service.version": "1.12.4", "deployment.environment.name": environment,
                            "k8s.namespace.name": "shop", "k8s.cluster.name": "otel-lab", "host.name": "worker-02"}
                attrs = {"http.request.method": method, "http.response.status_code": 503 if failed else 200,
                         "http.route": route, "app.order.id": f"ORD-{10482 + index}"}
                if service_idx == 4:
                    attrs = {"db.system.name": "postgresql", "db.namespace": "shop", "db.query.text": name, "server.address": "postgres.internal"}
                if service_idx == 5:
                    attrs = {"db.system.name": "redis", "db.operation.name": "GET"}
                status = "error" if failed else "ok"
                spans.append({"name": name, "status": status, "duration": span_duration, "kind": kind,
                              "resource": resource, "attrs": attrs, "spanID": span_id})
                otlp = {"traceId": trace_id, "spanId": span_id, "parentSpanId": identifier(f"{trace_id}-{parent_idx}") if parent_idx is not None else "",
                        "name": name, "kind": {"internal": 1, "server": 2, "client": 3, "producer": 4}[kind],
                        "startTimeUnixNano": str(begin), "endTimeUnixNano": str(begin + int(span_duration * 1e6)),
                        "attributes": attributes(attrs), "status": {"code": 2 if failed else 1, "message": "Payment provider timeout" if failed else ""},
                        "events": [{"timeUnixNano": str(begin + int(span_duration * .9e6)), "name": "exception", "attributes": attributes({"exception.type": "TimeoutError", "exception.message": "Payment provider did not respond within deadline"})}] if failed else [], "links": []}
                batches.append({"resource": {"attributes": attributes(resource)}, "scopeSpans": [{"scope": {"name": "opentelemetry.demo", "version": "1.28.0"}, "spans": [otlp]}]})
            self.items.append({"id": trace_id, "start": start_ns, "duration": duration, "name": specs[0][2], "spans": spans, "trace": {"batches": batches}})

    def offset_ns(self):
        # Keep demo traffic recent even when a preview container runs for days.
        return (int(time.time()) - self.generated_at) * 1_000_000_000

    def within(self, params, offset=None):
        offset = self.offset_ns() if offset is None else offset
        start, end = params.get("start", 0), params.get("end", float("inf"))
        return [item for item in self.items if start <= (item["start"] + offset) / 1e9 <= end]

    def search(self, params):
        conditions = parse_query(params.get("q", ""))
        offset = self.offset_ns()
        results = []
        for item in self.within(params, offset):
            found = [s for s in item["spans"] if matches(s, conditions)]
            if found:
                results.append({"traceID": item["id"], "rootServiceName": "api-gateway", "rootTraceName": item["name"],
                                "startTimeUnixNano": str(item["start"] + offset), "durationMs": item["duration"],
                                "spanSets": [{"matched": len(found), "spans": [{"spanID": s["spanID"], "name": s["name"], "durationNanos": str(int(s["duration"] * 1e6)), "attributes": attributes({"service.name": s["resource"]["service.name"], "status": s["status"]})} for s in found]}]})
        results.sort(key=lambda item: int(item["startTimeUnixNano"]), reverse=True)
        return {"traces": results[:int(params.get("limit", 50))], "metrics": {"inspectedTraces": len(self.items), "inspectedBytes": 2194280, "totalBlocks": 3, "completedJobs": 3, "totalJobs": 3}}

    def trace(self, trace_id):
        found = next((item["trace"] for item in self.items if item["id"] == trace_id), None)
        if found is None:
            return None
        result = copy.deepcopy(found)
        offset = self.offset_ns()
        for batch in result["batches"]:
            for scope in batch["scopeSpans"]:
                for span in scope["spans"]:
                    for key in ("startTimeUnixNano", "endTimeUnixNano"):
                        span[key] = str(int(span[key]) + offset)
                    for event in span["events"]:
                        event["timeUnixNano"] = str(int(event["timeUnixNano"]) + offset)
        return result

    def tags(self, params):
        scopes = {"resource": set(), "span": set(), "intrinsic": {"name", "status", "duration", "kind"}}
        for item in self.within(params):
            for span in item["spans"]:
                scopes["resource"].update(span["resource"])
                scopes["span"].update(span["attrs"])
        return {"scopes": [{"name": name, "tags": sorted(tags)} for name, tags in scopes.items() if params.get("scope", name) == name]}

    def values(self, tag, params):
        values = set()
        for item in self.within(params):
            for span in item["spans"]:
                if tag.startswith("resource."):
                    value = span["resource"].get(tag[9:])
                elif tag.startswith("span."):
                    value = span["attrs"].get(tag[5:])
                else:
                    value = span.get(tag)
                if value is not None:
                    values.add(value)
        return {"tagValues": [{"type": "bool" if isinstance(value, bool) else "int" if isinstance(value, int) else "float" if isinstance(value, float) else "string", "value": str(value).lower() if isinstance(value, bool) else str(value)} for value in sorted(values, key=str)]}
