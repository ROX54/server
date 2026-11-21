"""Regression checks for live data, history exports, and reversible archiving."""
from http.client import HTTPConnection
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

import security_dashboard as dashboard
from workflow_engine import WorkflowRuntime, execute_graph, new_run
from workflow_graph import WorkflowStore, make_edge, make_node, template


class LiveTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.workflows = WorkflowStore(root / "graphs")
        self.runtime = WorkflowRuntime(self.workflows, root / "runs.sqlite3")
        self.graph = template("Live check", [
            make_node("manual", "manual", 0, 0),
            make_node("secret", "secret", 0, 0),
            make_node("condition", "condition", 0, 0, field="findingCount"),
        ], [make_edge("manual", "secret"), make_edge("secret", "condition")])
        self.workflow = self.workflows.save(self.graph)
        self.finding = {"category": "SECRET", "class": "password", "line": 2,
                        "path": "example.kt", "severity": "HIGH", "description": "Example"}

    def record(self):
        run = new_run(self.workflow, ["manual"], "manual")
        self.runtime.store.reserve(run)
        execute_graph(self.graph, run, self.runtime.store.save, lambda *_: [self.finding])
        return run

    def test_live_packets_record_actual_ports_and_safe_counts(self):
        run = self.record()
        condition = run["nodes"][-1]
        self.assertEqual(condition["inputs"], [
            {"nodeId": "secret", "type": "findings", "port": "out", "findingCount": 1,
             "categories": {"SECRET": 1}, "analysisCount": 0},
        ])
        self.assertEqual(condition["outputs"][0]["port"], "true")
        self.assertNotIn("example.kt", json.dumps(condition))
        self.assertEqual(self.runtime.store.history()[0]["workflowName"], "Live check")

    def test_archiving_keeps_run_history_and_both_exports(self):
        run = self.record()
        key = self.workflow["id"]
        with dashboard.ThreadingHTTPServer(("127.0.0.1", 0), dashboard.Handler) as server:
            server.workflow_runtime = self.runtime
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)

            def request(method, path):
                client.request(method, path, "{}" if method == "POST" else None,
                               {"Content-Type": "application/json"})
                reply = client.getresponse()
                return reply.status, reply.read()

            try:
                self.assertEqual(request("POST", f"/api/workflows/{key}/archive")[0], 200)
                self.assertEqual(request("POST", f"/api/workflows/{key}/run")[0], 404)
                self.assertEqual(self.workflows.list(), [])
                self.assertTrue((self.workflows.directory / "archive" / f"{key}.json").is_file())
                self.assertEqual(json.loads(request("GET", "/api/workflow-runs")[1])["runs"][0]["workflowName"],
                                 "Live check")
                prefix = f"/api/workflow-runs/{run['runId']}/exports/"
                status, body = request("GET", prefix + "findings.json")
                self.assertEqual((status, json.loads(body)), (200, {"findings": [self.finding]}))
                status, body = request("GET", prefix + "report.md")
                self.assertEqual(status, 200)
                self.assertIn(b"example.kt", body)
            finally:
                client.close()
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    unittest.main()
