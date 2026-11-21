"""Tests for graph execution, scheduling, and the Dashboard run API."""
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from time import monotonic, sleep
import unittest
from unittest.mock import patch

import security_dashboard as dashboard
from workflow_controls import condition_matches, next_slot
from workflow_engine import ACTIVE, RunError, RunStore, WorkflowRuntime, execute_graph, new_run, subprocess_scanner
from workflow_graph import InvalidWorkflow, WorkflowStore, make_edge, make_node, template, templates


def row(category, severity="HIGH"):
    result = {"category": category, "path": "local.kt", "severity": severity}
    if category == "SCA":
        result.update(group="test", artifact="library", version="1.0", advisoryId="TEST-ADVISORY")
    else:
        result.update({"class": category.lower(), "line": 7})
    return result


def graph_for_branch(threshold):
    return template("Branch", [
        make_node("join", "report", 8, 8),
        make_node("no", "sca", 0, 0),
        make_node("yes", "secret", 0, 0),
        make_node("source", "sast", 0, 0),
        make_node("condition", "condition", 0, 0, value=str(threshold)),
        make_node("manual", "manual", 0, 0),
    ], [
        make_edge("manual", "source"), make_edge("source", "condition"),
        make_edge("condition", "yes", "true"), make_edge("condition", "no", "false"),
        make_edge("yes", "join"), make_edge("no", "join"),
    ])


class EngineTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.workflows = WorkflowStore(self.directory / "graphs")
        self.calls = []

    def scan(self, kind, timeout):
        self.assertGreater(timeout, 0)
        self.calls.append(kind)
        return [row(kind.upper(), "CRITICAL" if kind == "sast" else "HIGH")]

    def execute(self, graph, scan=None, roots=None):
        run = new_run({"id": "test", "graph": graph}, ["manual"] if roots is None else roots, "manual")
        snapshots = []
        execute_graph(graph, run, lambda data: snapshots.append(json.loads(json.dumps(data))), scan or self.scan)
        return run, snapshots

    def test_sequential_execution_topology_and_live_snapshots(self):
        graph = templates()[0]
        graph["nodes"].reverse()
        run, snapshots = self.execute(graph)
        self.assertEqual(self.calls, ["secret", "sast", "sca"])
        self.assertEqual(run["status"], "success")
        self.assertTrue(any(any(node["status"] == "running" for node in state["nodes"])
                            for state in snapshots))
        self.assertEqual(list(run["reports"]["report"]["json"]["findings"]),
                         [row("SECRET"), row("SAST", "CRITICAL"), row("SCA")])

    def test_true_branch_skips_false_and_feeds_join(self):
        run, _ = self.execute(graph_for_branch(0))
        states = {node["id"]: node for node in run["nodes"]}
        self.assertEqual(states["condition"]["branch"], "true")
        self.assertEqual(states["no"]["status"], "skipped")
        self.assertEqual(states["join"]["status"], "success")
        self.assertEqual(self.calls, ["sast", "secret"])

    def test_false_branch_skips_true_and_feeds_join(self):
        run, _ = self.execute(graph_for_branch(1))
        states = {node["id"]: node for node in run["nodes"]}
        self.assertEqual(states["condition"]["branch"], "false")
        self.assertEqual(states["yes"]["status"], "skipped")
        self.assertEqual(states["join"]["status"], "success")
        self.assertEqual(self.calls, ["sast", "sca"])

    def test_multiple_inputs_deduplicate_and_other_triggers_do_not_run(self):
        graph = template("Merge", [
            make_node("manual", "manual", 0, 0), make_node("schedule", "schedule", 0, 0),
            make_node("one", "secret", 0, 0), make_node("two", "secret", 0, 0),
            make_node("unrelated", "sast", 0, 0), make_node("report", "report", 0, 0),
        ], [
            make_edge("manual", "one"), make_edge("manual", "two"), make_edge("schedule", "unrelated"),
            make_edge("one", "report"), make_edge("two", "report"),
        ])
        run, _ = self.execute(graph)
        self.assertEqual(self.calls, ["secret", "secret"])
        self.assertEqual(list(run["findings"]), [row("SECRET")])
        self.assertEqual(list(run["reports"]["report"]["json"]["findings"]), [row("SECRET")])

    def test_scanner_filter_empty_report_and_missing_inputs(self):
        graph = template("Single", [
            make_node("manual", "manual", 0, 0),
            make_node("sast", "sast", 0, 0),
            make_node("report", "report", 0, 0),
        ], [make_edge("manual", "sast"), make_edge("sast", "report")])
        run, _ = self.execute(graph, lambda *_: [])
        self.assertEqual(run["status"], "success")
        self.assertIn("Находок нет.", run["reports"]["report"]["markdown"])

        def fail(*_):
            raise RunError("Сканер превысил допустимое время выполнения.")

        run, _ = self.execute(graph, fail)
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["nodes"][-1]["status"], "skipped")
        self.assertEqual(run["reports"], {})
        graph["nodes"][1]["params"]["minSeverity"] = "CRITICAL"
        run, _ = self.execute(graph, lambda *_: [row("SAST", "LOW")])
        self.assertEqual(len(run["findings"]), 0)

    def test_invalid_condition_and_cycle_are_rejected(self):
        graph = graph_for_branch(0)
        condition = next(node for node in graph["nodes"] if node["type"] == "condition")
        condition["params"].update(field="category", operator="regex", value="^(SAST+)+$")
        with self.assertRaises(InvalidWorkflow):
            self.execute(graph)
        condition["params"].update(value="^(SECRET|SAST)$")
        self.assertTrue(condition_matches(condition["params"], [row("SAST")]))
        graph["edges"].append(make_edge("yes", "condition"))
        with self.assertRaises(InvalidWorkflow):
            self.execute(graph)
        self.assertEqual(self.calls, [])

    def test_condition_presence_severity_and_comparisons(self):
        findings = [row("SAST", "CRITICAL"), row("SECRET", "HIGH")]
        cases = [
            ("hasFindings", "eq", "true", True), ("hasFindings", "ne", "true", False),
            ("findingCount", "gte", "2", True), ("findingCount", "lt", "1", False),
            ("findingCount", "lte", "2", True), ("criticalCount", "gt", "0", True),
            ("category", "ne", "SCA", True), ("category", "eq", "SECRET", True),
            ("severity", "gte", "CRITICAL", True), ("severity", "regex", "^LO.*", False),
        ]
        for field, operation, value, expected in cases:
            with self.subTest(field=field, operation=operation):
                self.assertEqual(condition_matches({"field": field, "operator": operation, "value": value},
                                                   findings), expected)

    def test_unconfigured_ai_and_dependents_have_truthful_states(self):
        with patch.dict("os.environ", {"OPENAI_BASE_URL": "https://api.openai.com/v1",
                                      "OPENAI_API_KEY": "", "OPENAI_MODEL": "not-configured"}):
            run, _ = self.execute(templates()[1])
        statuses = {node["type"]: node["status"] for node in run["nodes"]}
        self.assertEqual((run["status"], statuses["ai"], statuses["report"]), ("failed", "failed", "skipped"))

    def test_schedule_offset_legacy_and_durable_deduplication(self):
        moment = datetime(2036, 4, 12, 6, 30, tzinfo=timezone.utc)
        graph = template("Daily", [make_node("schedule", "schedule", 0, 0, enabled=True,
                                            time="09:30", timezone="UTC+03:00")], [])
        record = self.workflows.save(graph)
        params = graph["nodes"][0]["params"]
        self.assertEqual(next_slot(params, moment), moment)
        self.assertEqual(next_slot(params, moment + timedelta(seconds=1)), moment + timedelta(days=1))
        self.assertIsNone(next_slot({"intervalMinutes": 60}, moment))
        self.assertEqual(next_slot({"intervalMinutes": 5, "enabled": True}, moment), moment)
        legacy = template("Legacy", [dict(graph["nodes"][0], params={"intervalMinutes": 60})], [])
        self.workflows.save(legacy)

        database = self.directory / "runs.sqlite3"
        runtime = WorkflowRuntime(self.workflows, database, self.scan)
        runtime.schedule_tick(moment)
        runtime.schedule_tick(moment + timedelta(seconds=10))
        self.assertEqual(len(runtime.store.history(record["id"])), 1)
        restarted = WorkflowRuntime(self.workflows, database, self.scan)
        restarted.store.recover()
        restarted.schedule_tick(moment + timedelta(seconds=20))
        rows = restarted.store.history(record["id"])
        self.assertEqual([item["status"] for item in rows], ["interrupted"])
        restarted.schedule_tick(moment + timedelta(days=1))
        self.assertEqual(len(restarted.store.history(record["id"])), 2)
        self.assertEqual(restarted.schedules(record["id"], moment + timedelta(seconds=25))[0]["nextAt"],
                         (moment + timedelta(days=1)).isoformat())

    def test_http_manual_run_results_history_restarts_and_repeated_runs(self):
        database = self.directory / "runs.sqlite3"
        graph = templates()[0]
        graph["nodes"].append(make_node("daily", "schedule", 0, 0))
        record = self.workflows.save(graph)
        key = record["id"]

        def serve(actions):
            runtime = WorkflowRuntime(self.workflows, database, subprocess_scanner)
            with patch.object(dashboard, "WORKFLOWS", self.workflows):
                with dashboard.ThreadingHTTPServer(("127.0.0.1", 0), dashboard.Handler) as server, runtime.running():
                    server.workflow_runtime = runtime
                    worker = Thread(target=server.serve_forever, daemon=True)
                    worker.start()
                    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)

                    def request(method, path):
                        connection.request(method, path, "{}" if method == "POST" else None,
                                           {"Content-Type": "application/json"})
                        response = connection.getresponse()
                        return response.status, response.read()

                    try:
                        return actions(request)
                    finally:
                        connection.close()
                        server.shutdown()
                        worker.join()

        def first(request):
            status, payload = request("POST", f"/api/workflows/{key}/run")
            queued = json.loads(payload)
            self.assertEqual((status, queued["status"]), (202, "queued"))
            run_id = queued["runId"]
            path = "/api/workflow-runs/" + run_id
            deadline = monotonic() + 12
            while monotonic() < deadline:
                status, payload = request("GET", path)
                state = json.loads(payload)
                if state["status"] not in ACTIVE:
                    break
                sleep(0.05)
            self.assertEqual((status, state["status"], state["findingCount"]), (200, "success", 15))
            self.assertEqual(next(node for node in state["nodes"] if node["id"] == "daily")["status"], "skipped")
            status, payload = request("GET", path + "/results")
            self.assertEqual((status, len(json.loads(payload)["findings"])), (200, 15))
            status, payload = request("GET", path + "/reports/report/findings.json")
            self.assertEqual((status, len(json.loads(payload)["findings"])), (200, 15))
            status, payload = request("GET", path + "/reports/report/report.md")
            self.assertEqual((status, payload.count(b"\n| S")), (200, 15))
            status, payload = request("GET", f"/api/workflows/{key}/schedule")
            self.assertEqual((status, json.loads(payload)["schedules"][0]["enabled"]), (200, False))
            return run_id

        previous = serve(first)
        repeated = serve(first)
        self.assertNotEqual(previous, repeated)
        history = WorkflowRuntime(self.workflows, database).store.history(key)
        self.assertEqual({item["runId"] for item in history}, {previous, repeated})
        self.assertTrue(all(item["status"] == "success" for item in history))

    def test_background_scheduler_runs_one_real_scanner_once(self):
        moment = datetime(2036, 4, 12, 6, 30, 10, tzinfo=timezone.utc)
        graph = template("Daily SECRET", [
            make_node("daily", "schedule", 0, 0, enabled=True, time="09:30", timezone="UTC+03:00"),
            make_node("secret", "secret", 0, 0),
            make_node("report", "report", 0, 0),
        ], [make_edge("daily", "secret"), make_edge("secret", "report")])
        key = self.workflows.save(graph)["id"]
        database = self.directory / "runs.sqlite3"
        with patch("workflow_engine.now", return_value=moment):
            for _ in range(2):
                with WorkflowRuntime(self.workflows, database).running() as runtime:
                    deadline = monotonic() + 8
                    while monotonic() < deadline:
                        rows = runtime.store.history(key)
                        if rows and rows[0]["status"] not in ACTIVE:
                            break
                        sleep(0.05)
                    runtime.schedule_tick(moment)
                    self.assertEqual(len(runtime.store.history(key)), 1)
                    self.assertEqual((rows[0]["status"], rows[0]["findingCount"]), ("success", 5))
                    run = runtime.store.load(rows[0]["runId"])
                    self.assertEqual({item["category"] for item in run["reports"]["report"]["json"]["findings"]},
                                     {"SECRET"})

    def test_pruning_history_keeps_schedule_claim(self):
        store = RunStore(self.directory / "runs.sqlite3", history_limit=1)
        graph = template("History limit", [make_node("daily", "schedule", 0, 0)], [])
        workflow = self.workflows.save(graph)
        slot = "2036-04-12T06:30:00+00:00"
        old = new_run(workflow, ["daily"], "schedule", slot)
        recent = new_run(workflow, ["daily"], "manual")
        old["queuedAt"], recent["queuedAt"] = slot, "2036-04-12T06:31:00+00:00"
        for run in (old, recent):
            self.assertTrue(store.reserve(run))
            run["status"] = "success"
            store.save(run)
        self.assertEqual([run["runId"] for run in store.history()], [recent["runId"]])
        self.assertFalse(store.reserve(new_run(workflow, ["daily"], "schedule", slot)))


if __name__ == "__main__":
    unittest.main()
