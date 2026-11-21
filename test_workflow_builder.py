"""Storage and Dashboard API tests for editable workflows."""
from http.client import HTTPConnection
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

import security_dashboard
from workflow_graph import InvalidWorkflow, WorkflowStore, graph_errors, make_edge, templates


class WorkflowBuilderTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.store = WorkflowStore(self.directory)
        self.quick, self.full, self.alert = templates()

    def test_templates_validate_and_keep_distinct_condition_ports(self):
        self.assertEqual([graph["name"] for graph in templates()],
                         ["Quick Security Scan", "Full Security Audit", "Critical Findings Alert"])
        for graph in (self.quick, self.full, self.alert):
            with self.subTest(template=graph["name"]):
                self.assertEqual(graph_errors(graph), [])
        self.assertEqual({edge["sourcePort"] for edge in self.alert["edges"] if edge["source"] == "condition"},
                         {"true", "false"})

    def test_store_round_trip_after_recreation_and_update(self):
        self.alert["name"] = "Проверка документов"
        self.alert["nodes"][0]["x"] = 41
        self.alert["nodes"][0]["params"]["intervalMinutes"] = 45
        record = self.store.save(self.alert)
        key = record["id"]
        saved = WorkflowStore(self.directory)
        self.assertEqual(saved.load(key)["graph"], self.alert)
        self.assertEqual([(item["id"], item["name"]) for item in saved.list()], [(key, self.alert["name"])])
        self.alert["nodes"][0]["y"] = 145
        self.assertEqual(saved.save(self.alert, key)["id"], key)
        self.assertEqual(WorkflowStore(self.directory).load(key)["graph"], self.alert)
        self.assertEqual(len(list(self.directory.glob("*.json"))), 1)

    def test_invalid_update_preserves_disk_record(self):
        key = self.store.save(self.alert)["id"]
        self.alert["nodes"][0]["params"]["intervalMinutes"] = 0
        with self.assertRaises(InvalidWorkflow):
            self.store.save(self.alert, key)
        self.assertEqual(self.store.load(key)["graph"]["nodes"][0]["params"]["intervalMinutes"], 60)
        with self.assertRaises(FileNotFoundError):
            self.store.load("../outside")

    def test_missing_and_incompatible_ports(self):
        self.quick["edges"].extend([make_edge("missing", "sast"), make_edge("manual", "report")])
        self.quick["edges"].append(make_edge("sast", "report", "true"))
        errors = graph_errors(self.quick)
        self.assertTrue(any("отсутствует" in error for error in errors))
        self.assertEqual(sum("несовместимые порты" in error for error in errors), 2)

    def test_rejects_cycles_duplicates_and_unreachable_nodes(self):
        self.quick["edges"].extend([make_edge("sast", "secret"), make_edge("manual", "secret")])
        errors = graph_errors(self.quick)
        self.assertTrue(any("цикл" in error for error in errors))
        self.assertTrue(any("уже существует" in error for error in errors))
        self.quick["edges"] = self.quick["edges"][1:4]
        self.assertTrue(any("нет пути от триггера" in error for error in graph_errors(self.quick)))

    def test_required_params_missing_trigger_and_invalid_regex(self):
        self.alert["nodes"][0]["type"] = "secret"
        self.alert["nodes"][0]["params"] = {}
        condition = next(node for node in self.alert["nodes"] if node["type"] == "condition")
        condition["params"].update(field="category", operator="regex", value="[")
        errors = graph_errors(self.alert)
        for expected in ("хотя бы один", "выберите значение", "регулярное выражение"):
            self.assertTrue(any(expected in error for error in errors))

    def test_http_workflow_assets_validation_save_and_load(self):
        with patch.object(security_dashboard, "WORKFLOWS", self.store):
            with security_dashboard.ThreadingHTTPServer(("127.0.0.1", 0), security_dashboard.Handler) as server:
                worker = Thread(target=server.serve_forever, daemon=True)
                worker.start()
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)

                def request(method, path, payload=None):
                    if payload is None:
                        connection.request(method, path)
                    else:
                        connection.request(method, path, json.dumps(payload),
                                           {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    return response.status, response.read()

                try:
                    status, page = request("GET", "/")
                    self.assertEqual(status, 200)
                    self.assertIn(b'id="wf-canvas"', page)
                    for path in ("/workflow-builder.js", "/workflow-builder.css"):
                        self.assertEqual(request("GET", path)[0], 200)
                    _, library = request("GET", "/api/workflow-library")
                    self.assertEqual(len(json.loads(library)["nodeTypes"]), 9)
                    status, _ = request("POST", "/api/workflows/validate", {"graph": self.quick})
                    self.assertEqual(status, 200)
                    status, result = request("POST", "/api/workflows", {"graph": self.quick})
                    self.assertEqual(status, 201)
                    key = json.loads(result)["id"]
                    status, rows = request("GET", "/api/workflows")
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(rows)["workflows"][0]["id"], key)
                    status, result = request("GET", "/api/workflows/" + key)
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(result)["graph"], self.quick)
                    status, result = request("POST", "/api/workflows", {"id": key, "graph": self.full})
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(result)["graph"], self.full)
                    self.quick["edges"].append(make_edge("report", "sast"))
                    status, result = request("POST", "/api/workflows", {"graph": self.quick})
                    self.assertEqual(status, 422)
                    self.assertTrue(json.loads(result)["errors"])
                    self.assertEqual(request("GET", "/api/workflows/unknown")[0], 404)
                finally:
                    connection.close()
                    server.shutdown()
                    worker.join()


if __name__ == "__main__":
    unittest.main()
