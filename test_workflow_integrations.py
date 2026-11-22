"""Loopback HTTP and schema tests for Stage 4 workflow integrations."""
from collections import deque
from contextlib import contextmanager
from copy import deepcopy
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
from threading import Thread
from time import monotonic, sleep
import unittest
from unittest.mock import patch

from ai_assistant import AIError, analyze_findings, metadata, verify_analysis
import security_dashboard as dashboard
from webhook_receiver import Handler as DemoReceiver
from workflow_engine import ACTIVE, WorkflowRuntime, execute_graph, new_run
from workflow_graph import WorkflowStore, make_edge, make_node, template
from workflow_webhook import WebhookError, deliver, endpoint, notification, public_ip

TEST_ID = "a" * 32
SECRET_CANARY = "synthetic-sensitive-canary-for-test"
FINDINGS = [
    {"category": "SECRET", "path": "src/example.kt", "line": 7, "endLine": 8,
     "class": "password", "severity": "HIGH"},
    {"category": "SCA", "path": "build.gradle.kts", "group": "example", "artifact": "sample",
     "version": "1.0", "advisoryId": "CVE-2026-11111", "severity": "CRITICAL"},
]


def valid_analysis(rows):
    return {
        "summary": "В тестовом ответе объединены результаты анализаторов.",
        "findings": [
            {**{key: row.get(key) for key in ("findingId", "path", "line", "endLine", "advisoryId")},
             "risk": "Проблема требует проверки владельцем проекта.",
             "remediation": "Устранить небезопасное значение или обновить зависимость."}
            for row in rows
        ],
    }


class TestProvider(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.requests.append(body)
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        if self.server.provider_status != 200:
            self.send_error(self.server.provider_status, SECRET_CANARY)
            return
        request = json.loads(body)
        if "response_format" in request:
            rows = json.loads(request["messages"][-1]["content"])["findings"]
            text = json.dumps(valid_analysis(rows), ensure_ascii=False)
        else:
            text = "OK"
        response = json.dumps({"choices": [{"message": {"content": text}, "finish_reason": "stop"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class StatusReceiver(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        self.server.requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        if self.server.delay:
            sleep(self.server.delay)
        status = self.server.responses.pop(0) if len(self.server.responses) > 1 else self.server.responses[0]
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()


@contextmanager
def server(handler):
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as service:
        service.requests = []
        service.received = deque(maxlen=128)
        service.provider_status = 200
        service.responses = [200]
        service.delay = 0
        thread = Thread(target=service.serve_forever, daemon=True)
        thread.start()
        try:
            yield service
        finally:
            service.shutdown()
            thread.join()


def provider_env(port):
    return {"OPENAI_BASE_URL": f"http://127.0.0.1:{port}/v1", "OPENAI_API_KEY": "",
            "OPENAI_MODEL": "integration-test-double"}


def receiver_env(port):
    return {"CYBERGARDEN_WEBHOOK_ALLOW_LOOPBACK_DEMO": "1", "CYBERGARDEN_WEBHOOK_DEMO_PORT": str(port),
            "CYBERGARDEN_WEBHOOK_PROFILES": json.dumps({"demo": {"url": f"http://127.0.0.1:{port}/webhook"}})}


def graph(with_report=False, fallback=False, threshold="0"):
    nodes = [
        make_node("manual", "manual", 0, 0), make_node("secret", "secret", 0, 0),
        make_node("sast", "sast", 0, 0), make_node("sca", "sca", 0, 0),
        make_node("condition", "condition", 0, 0, value=threshold),
        make_node("ai", "ai", 0, 0, maxFindings=15, continueOnError=fallback),
        make_node("notify", "webhook", 0, 0),
    ]
    edges = [make_edge("manual", "secret"), make_edge("secret", "sast"), make_edge("sast", "sca"),
             make_edge("sca", "condition"), make_edge("condition", "ai", "true")]
    if with_report:
        nodes.append(make_node("report", "report", 0, 0))
        edges.extend([make_edge("ai", "report"), make_edge("report", "notify")])
    else:
        edges.append(make_edge("ai", "notify"))
    return template("Stage 4", nodes, edges)


class IntegrationTests(unittest.TestCase):
    def test_ai_selects_metadata_and_validates_real_http_response(self):
        with server(TestProvider) as provider, patch.dict(os.environ, provider_env(provider.server_port)):
            source = [dict(FINDINGS[0], description=SECRET_CANARY, remediation=SECRET_CANARY,
                           secret=SECRET_CANARY, sourceCode=SECRET_CANARY), FINDINGS[1]]
            result = analyze_findings(source, 10, 3)
            body = provider.requests[0]
            self.assertNotIn(SECRET_CANARY.encode(), body)
            self.assertEqual(json.loads(json.loads(body)["messages"][-1]["content"])["findings"],
                             metadata(FINDINGS, 10))
            self.assertEqual(result["analyzedCount"], 2)
            self.assertEqual(result["findings"][1]["advisoryId"], FINDINGS[1]["advisoryId"])
            provider.provider_status = 503
            with self.assertRaises(AIError) as caught:
                analyze_findings(source, 10, 3)
            self.assertIn("HTTP 503", str(caught.exception))
            self.assertNotIn(SECRET_CANARY, str(caught.exception))

    def test_invalid_json_ids_paths_lines_and_advisories_are_rejected(self):
        rows = metadata(FINDINGS, 10)
        with self.assertRaises(AIError):
            verify_analysis("<invalid JSON>", rows)
        base = valid_analysis(rows)
        for index, key, value in (
            (0, "findingId", "F-999"), (0, "path", "renamed.kt"), (0, "line", True),
            (0, "line", 99), (0, "endLine", 15), (1, "advisoryId", "GHSA-aaaa-bbbb-cccc"),
            (1, "risk", "Обнаружен CVE-2026-99999"), (0, "risk", "Указан source.kt"),
            (0, "remediation", "token: " + SECRET_CANARY),
        ):
            with self.subTest(field=key, value=value), self.assertRaises(AIError):
                altered = deepcopy(base)
                altered["findings"][index][key] = value
                verify_analysis(json.dumps(altered), rows)

    def test_webhook_actual_acknowledgement_and_http_failures(self):
        with server(StatusReceiver) as receiver, patch.dict(os.environ, receiver_env(receiver.server_port)):
            payload = notification(TEST_ID, "running", FINDINGS, [])
            receiver.responses = [503, 204]
            result = deliver("demo", payload, 4)
            self.assertEqual((result["status"], result["httpStatus"], result["attempts"]), ("delivered", 204, 2))
            self.assertEqual(receiver.requests, [payload, payload])
            for status, attempts in [(401, 1), (302, 1), (500, 3)]:
                with self.subTest(status=status), self.assertRaises(WebhookError) as caught:
                    receiver.responses = [status]
                    deliver("demo", payload, 4)
                self.assertEqual(caught.exception.delivery["httpStatus"], status)
                self.assertEqual(caught.exception.delivery["attempts"], attempts)
            receiver.delay = 0.55
            with self.assertRaises(WebhookError) as caught:
                deliver("demo", payload, 0.15)
            self.assertIsNone(caught.exception.delivery["httpStatus"])

    def test_webhook_blocks_internal_and_non_allowlisted_addresses(self):
        for url in ("http://127.0.0.1:8767/webhook", "https://public.example:8443/hooks",
                    "https://user@public.example/", "https://public.example/?secret=value"):
            with self.subTest(url=url), patch.dict(os.environ, {
                "CYBERGARDEN_WEBHOOK_ALLOW_LOOPBACK_DEMO": "1",
                "CYBERGARDEN_WEBHOOK_PROFILES": json.dumps({"outside": {"url": url}}),
            }), self.assertRaises(WebhookError):
                endpoint("outside")
        for address in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "::1", "::ffff:127.0.0.1", "224.0.0.1"):
            with self.subTest(address=address), patch("workflow_webhook.socket.getaddrinfo",
                                                      return_value=[(0, 0, 0, "", (address, 443))]):
                with self.assertRaises(WebhookError):
                    public_ip("test.example", 443)
        with patch("workflow_webhook.socket.getaddrinfo",
                   return_value=[(0, 0, 0, "", ("8.8.8.8", 443)), (0, 0, 0, "", ("10.0.0.1", 443))]):
            with self.assertRaises(WebhookError):
                public_ip("mixed.example", 443)
        with patch.dict(os.environ, {**receiver_env(8767), "CYBERGARDEN_WEBHOOK_ALLOW_LOOPBACK_DEMO": "0"}):
            with self.assertRaises(WebhookError):
                endpoint("demo")

    def test_condition_and_explicit_fallback_control_delivery(self):
        def scan(kind, _timeout):
            return [row for row in FINDINGS if row["category"] == kind.upper()]

        with server(TestProvider) as provider, server(StatusReceiver) as receiver, patch.dict(
            os.environ, {**provider_env(provider.server_port), **receiver_env(receiver.server_port)}
        ):
            for workflow, expected in ((graph(threshold="1"), "success"), (graph(), "failed"),
                                       (graph(fallback=True), "failed")):
                provider.provider_status = 503
                run = new_run({"id": "test", "graph": workflow}, ["manual"], "manual")
                execute_graph(workflow, run, lambda _: None, scan)
                self.assertEqual(run["status"], expected)
            self.assertEqual(len(receiver.requests), 1)
            self.assertEqual(receiver.requests[0]["counts"], {"SECRET": 1, "SAST": 0, "SCA": 1})
            self.assertEqual(receiver.requests[0]["status"], "failed")
            self.assertNotIn("ai", receiver.requests[0])

    def test_dashboard_full_run_and_demo_receiver_over_http(self):
        with tempfile.TemporaryDirectory() as directory, server(TestProvider) as provider, server(DemoReceiver) as receiver:
            root = Path(directory)
            workflows = WorkflowStore(root)
            runtime = WorkflowRuntime(workflows, root / "runs.sqlite3")
            with patch.dict(os.environ, {**provider_env(provider.server_port), **receiver_env(receiver.server_port)}), \
                    patch.object(dashboard, "WORKFLOWS", workflows), patch("webhook_receiver.print", create=True) as printed, \
                    server(dashboard.Handler) as app, runtime.running():
                app.workflow_runtime = runtime

                def request(method, path, data=None):
                    connection = HTTPConnection("127.0.0.1", app.server_port, timeout=4)
                    try:
                        connection.request(method, path, json.dumps(data) if data is not None else None,
                                           {"Content-Type": "application/json"})
                        response = connection.getresponse()
                        return response.status, json.loads(response.read())
                    finally:
                        connection.close()

                self.assertTrue(request("GET", "/api/ai/settings")[1]["configured"])
                self.assertTrue(request("POST", "/api/ai/check", {})[1]["connected"])
                baseline = request("GET", "/api/findings")[1]["findings"][0]
                status, _ = request("POST", "/api/ai/explain", {
                    "finding": dict(baseline, description=SECRET_CANARY),
                })
                self.assertEqual(status, 200)
                self.assertNotIn(SECRET_CANARY.encode(), provider.requests[-1])
                status, _ = request("POST", "/api/ai/explain", {"finding": dict(baseline, path="forged.kt")})
                self.assertEqual(status, 404)
                status, record = request("POST", "/api/workflows", {"graph": graph(with_report=True)})
                self.assertEqual(status, 201)
                status, run = request("POST", f"/api/workflows/{record['id']}/run", {})
                self.assertEqual(status, 202)
                path = f"/api/workflow-runs/{run['runId']}"
                deadline = monotonic() + 15
                while monotonic() < deadline:
                    status, run = request("GET", path)
                    if run["status"] not in ACTIVE:
                        break
                    sleep(0.05)
                self.assertEqual((status, run["status"], run["findingCount"]), (200, "success", 15))
                node = next(item for item in run["nodes"] if item["id"] == "notify")
                self.assertEqual((node["status"], node["delivery"]["httpStatus"]), ("success", 200))
                self.assertTrue(node["delivery"]["receiver"]["accepted"])
                results = request("GET", path + "/results")[1]
                self.assertEqual(results["analyses"]["ai"]["analyzedCount"], 15)
                report = results["reports"]["report"]
                self.assertEqual(len(report["json"]["findings"]), 15)
                self.assertEqual(report["markdown"].count("\n| S"), 15)
                delivered = json.loads(printed.call_args.args[0])
                self.assertEqual(delivered["runId"], run["runId"])
                self.assertEqual(delivered["status"], "success")
                self.assertEqual(delivered["counts"], {"SECRET": 5, "SAST": 5, "SCA": 5})
                self.assertGreater(delivered["criticalCount"], 0)
                self.assertEqual(delivered["ai"][0]["analyzedCount"], 15)


if __name__ == "__main__":
    unittest.main()
