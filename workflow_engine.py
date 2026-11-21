"""Run saved graphs against the fixed local training project."""
from collections import deque
from contextlib import closing, contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from queue import Empty, Queue
import sqlite3
import subprocess
import sys
from threading import Event, Lock, Thread
from time import monotonic
from uuid import uuid4

from ai_assistant import AIError, analyze_findings, check_connection, explain
from security_workflow import (
    DATABASE, ROOT, check_findings, project_root, report_markdown, scan_sast,
    scan_sca, scan_secrets,
)
from workflow_controls import SEVERITIES, condition_matches, next_slot
from workflow_graph import InvalidWorkflow, NODE_TYPES, STORED_ID, graph_errors
from workflow_webhook import WebhookError, deliver, notification

PROJECT = ROOT / "training-project"
UTC = timezone.utc
SCANNERS = {"secret": scan_secrets, "sast": scan_sast, "sca": scan_sca}
SCANNER_TIMEOUT = 25
INTEGRATION_TIMEOUT = 25
INTEGRATIONS = {"ai", "ai-check", "ai-explain", "webhook"}
RUN_TIMEOUT = 90
MAX_FINDINGS = 1000
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_HISTORY = 60
ACTIVE = {"queued", "running"}
RESTART = "Выполнение прервано остановкой сервера."


def now():
    return datetime.now(UTC)


def stamp():
    return now().isoformat()


class RunError(ValueError):
    """An execution failure whose message can be displayed to the operator."""


class QueueBusy(RunError):
    pass


@dataclass(frozen=True)
class Packet:
    kind: str
    findings: tuple = ()
    analyses: tuple = ()


def merge_findings(*groups):
    unique = {}
    for group in groups:
        for row in group:
            location = ((row["group"], row["artifact"], row["version"], row["advisoryId"])
                        if row["category"] == "SCA" else (row["class"], row["line"]))
            unique.setdefault((row["category"], row["path"], *location), row)
    if len(unique) > MAX_FINDINGS:
        raise RunError("Превышен лимит находок для одного запуска.")
    return tuple(unique.values())


def subprocess_scanner(kind, timeout):
    if kind not in SCANNERS:
        raise RunError("Неизвестный тип сканера.")
    try:
        result = subprocess.run(
            [sys.executable, "-B", str(Path(__file__).resolve()), kind],
            cwd=ROOT, capture_output=True, timeout=timeout, check=True,
        )
        findings = json.loads(result.stdout)
        check_findings(findings, PROJECT)
        return findings
    except subprocess.TimeoutExpired:
        raise RunError("Сканер превысил допустимое время выполнения.") from None
    except (ValueError, OSError, subprocess.CalledProcessError):
        raise RunError("Сканер завершился ошибкой или вернул недопустимые данные.") from None


def bounded_integration(kind, payload, timeout):
    if kind not in INTEGRATIONS:
        raise RunError("Неизвестная операция интеграции.")
    error_type = WebhookError if kind == "webhook" else AIError
    try:
        args = [sys.executable, "-B", str(Path(__file__).resolve()), kind]
        work = {"timeout": max(0.1, timeout - 0.35), "payload": payload}
        result = subprocess.run(args, cwd=ROOT, capture_output=True, check=True, timeout=timeout,
                                input=json.dumps(work, ensure_ascii=False).encode("utf-8"))
        reply = json.loads(result.stdout)
        if reply["ok"]:
            return reply["value"]
    except subprocess.TimeoutExpired:
        raise error_type("Сетевой запрос превысил допустимое время.") from None
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
        raise error_type("Не удалось завершить сетевую операцию.") from None
    if kind == "webhook":
        raise WebhookError(reply["error"], reply.get("delivery"))
    raise AIError(reply["error"])


def integration_result(kind, payload, timeout):
    try:
        if kind == "ai":
            value = analyze_findings(payload["findings"], payload["limit"], timeout)
        elif kind == "ai-check":
            value = check_connection(timeout)
        elif kind == "ai-explain":
            value = explain(payload["finding"], timeout)
        else:
            value = deliver(payload["profile"], payload["notification"], timeout, payload["nodeId"])
    except (AIError, WebhookError) as error:
        result = {"ok": False, "error": str(error)}
        if isinstance(error, WebhookError):
            result["delivery"] = error.delivery
        return result
    return {"ok": True, "value": value}


def new_run(workflow, roots, source, slot=None):
    return {
        "runId": uuid4().hex, "workflowId": workflow["id"], "workflowName": workflow["graph"]["name"],
        "trigger": source, "triggerNodes": roots, "scheduledAt": slot, "queuedAt": stamp(),
        "status": "queued", "startedAt": None, "finishedAt": None, "durationMs": None,
        "nodes": [{
            "id": node["id"], "type": node["type"], "status": "pending", "startedAt": None,
            "finishedAt": None, "durationMs": None,
        } for node in workflow["graph"]["nodes"]],
        "errors": [], "findings": [], "reports": {}, "analyses": {}, "deliveries": {},
    }


def interrupt(run):
    finished = now()
    for node in run["nodes"]:
        if node["status"] in {"running", "pending"}:
            node.update(status="failed" if node["status"] == "running" else "skipped",
                        finishedAt=finished.isoformat(), message=RESTART)
            if node["startedAt"]:
                node["durationMs"] = max(0, round((finished - datetime.fromisoformat(
                    node["startedAt"])).total_seconds() * 1000))
    run.update(status="interrupted", finishedAt=finished.isoformat())
    if run["startedAt"]:
        run["durationMs"] = max(0, round((finished - datetime.fromisoformat(run["startedAt"])).total_seconds() * 1000))
    run["errors"].append(RESTART)


def graph_order(graph):
    incoming = {node["id"]: [] for node in graph["nodes"]}
    outgoing = {key: [] for key in incoming}
    for edge in graph["edges"]:
        incoming[edge["target"]].append(edge)
        outgoing[edge["source"]].append(edge["target"])
    degrees = {key: len(edges) for key, edges in incoming.items()}
    ready = deque(key for key, degree in degrees.items() if not degree)
    order = []
    while ready:
        key = ready.popleft()
        order.append(key)
        for successor in outgoing[key]:
            degrees[successor] -= 1
            if not degrees[successor]:
                ready.append(successor)
    if len(order) != len(incoming):
        raise RunError("Граф содержит цикл.")
    return order, incoming


def render_report(title, findings):
    markdown = report_markdown(findings)
    if title != "Отчёт статического анализа":
        heading = " ".join(title.split())
        # Encode punctuation before placing the user-supplied title in Markdown.
        heading = "".join(char if char.isalnum() or char == " " else f"&#{ord(char)};" for char in heading)
        markdown = f"# {heading}\n" + markdown.partition("\n")[2]
    return {"title": title, "json": {"findings": findings}, "markdown": markdown}


def execute_graph(graph, run, persist, scan=subprocess_scanner, stopped=lambda: False,
                  integrate=bounded_integration):
    if errors := graph_errors(graph):
        raise InvalidWorkflow(errors)
    nodes = {node["id"]: node for node in graph["nodes"]}
    roots = set(run["triggerNodes"])
    if not roots or any(key not in nodes or nodes[key]["type"] not in {"manual", "schedule"} for key in roots):
        raise RunError("Нет подходящего входного триггера.")
    order, incoming = graph_order(graph)
    states = {state["id"]: state for state in run["nodes"]}
    outputs = {}
    collected = ()
    artifact_bytes = 0
    start = monotonic()
    run.update(status="running", startedAt=stamp())
    persist(run)
    for key in order:
        if stopped():
            interrupt(run)
            persist(run)
            return
        node, state = nodes[key], states[key]
        kind, params = node["type"], node["params"]
        packets = [
            outputs[(edge["source"], edge["sourcePort"])]
            for edge in incoming[key] if (edge["source"], edge["sourcePort"]) in outputs
        ]
        if key not in roots and not packets:
            state.update(status="skipped", finishedAt=stamp(),
                         message="Нет активных входных данных от выбранного триггера или ветки.")
            persist(run)
            continue
        node_start = monotonic()
        state.update(status="running", startedAt=stamp())
        persist(run)
        try:
            remaining = RUN_TIMEOUT - (monotonic() - start)
            if remaining <= 0:
                raise RunError("Исчерпан лимит времени запуска.")
            if packets and any(packet.kind not in NODE_TYPES[kind]["inputs"]["in"]["types"]
                               for packet in packets):
                raise RunError("Получены данные несовместимого типа.")
            findings = merge_findings(*(packet.findings for packet in packets))
            reviews = tuple(dict.fromkeys(review for packet in packets for review in packet.analyses))
            if kind in {"manual", "schedule"}:
                outputs[key, "out"] = Packet("start")
            elif kind in SCANNERS:
                minimum = SEVERITIES.index(params["minSeverity"])
                matches = scan(kind, min(SCANNER_TIMEOUT, remaining))
                own = tuple(row for row in matches if SEVERITIES.index(row["severity"]) >= minimum)
                findings = merge_findings(findings, own)
                collected = merge_findings(collected, own)
                run["findings"] = collected
                outputs[key, "out"] = Packet("findings", findings, reviews)
            elif kind == "condition":
                branch = "true" if condition_matches(params, findings) else "false"
                state["branch"] = branch
                outputs[key, branch] = Packet("findings", findings, reviews)
            elif kind == "ai":
                try:
                    result = integrate(kind, {"findings": findings, "limit": params["maxFindings"]},
                                       min(INTEGRATION_TIMEOUT, remaining))
                except AIError:
                    if params.get("continueOnError", False):
                        outputs[key, "out"] = Packet("findings", findings, reviews)
                    raise
                size = len(json.dumps(result, ensure_ascii=False).encode())
                if artifact_bytes + size > MAX_REPORT_BYTES:
                    raise RunError("Превышен лимит размера результатов запуска.")
                artifact_bytes += size
                run["analyses"][key] = result
                outputs[key, "out"] = Packet("findings", findings, (*reviews, key))
            elif kind == "report":
                report = render_report(params["title"], findings)
                size = len(json.dumps(report, ensure_ascii=False).encode())
                if artifact_bytes + size > MAX_REPORT_BYTES:
                    raise RunError("Превышен лимит размера результатов запуска.")
                artifact_bytes += size
                run["reports"][key] = report
                outputs[key, "out"] = Packet("report", findings, reviews)
            elif kind == "webhook":
                summaries = [run["analyses"][review] for review in reviews]
                payload = notification(run["runId"], "failed" if run["errors"] else "running", findings, summaries)
                receipt = integrate(kind, {"profile": params["endpointRef"], "notification": payload, "nodeId": key},
                                    min(INTEGRATION_TIMEOUT, remaining))
                run["deliveries"][key] = receipt
                state["delivery"] = receipt
            state.update(status="success", findingCount=len(findings))
        except (AIError, WebhookError) as error:
            state.update(status="failed", message=str(error))
            if isinstance(error, WebhookError):
                receipt = error.delivery or {"status": "failed", "httpStatus": None, "attempts": None}
                run["deliveries"][key] = receipt
                state["delivery"] = receipt
            run["errors"].append(f"{key}: {error}")
        except RunError as error:
            state.update(status="failed", message=str(error))
            run["errors"].append(f"{key}: {error}")
        except (IndexError, KeyError, TypeError, ValueError):
            state.update(status="failed", message="Нода получила недопустимые данные.")
            run["errors"].append(f"{key}: недопустимые данные.")
        state.update(finishedAt=stamp(), durationMs=round((monotonic() - node_start) * 1000))
        persist(run)
    run.update(status="failed" if run["errors"] else "success",
               finishedAt=stamp(), durationMs=round((monotonic() - start) * 1000))
    persist(run)


class RunStore:
    def __init__(self, path, history_limit=MAX_HISTORY):
        self.path = Path(path)
        self.history_limit = history_limit
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, workflow TEXT NOT NULL, queued TEXT NOT NULL,
                    status TEXT NOT NULL, summary TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS schedule_slots (workflow TEXT PRIMARY KEY, slot TEXT NOT NULL);
            """)

    @contextmanager
    def connect(self):
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            yield db

    def reserve(self, run):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            slot = run["scheduledAt"]
            if slot is not None:
                claim = db.execute("""
                    INSERT INTO schedule_slots VALUES (?, ?)
                    ON CONFLICT(workflow) DO UPDATE SET slot=excluded.slot WHERE excluded.slot > schedule_slots.slot
                    """, (run["workflowId"], slot))
                if not claim.rowcount:
                    return False
            db.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)", (
                run["runId"], run["workflowId"], run["queuedAt"], run["status"],
                json.dumps(history_summary(run)), json.dumps(run),
            ))
        return True

    def save(self, run):
        with self.connect() as db:
            db.execute("UPDATE runs SET status=?, summary=?, payload=? WHERE id=?",
                       (run["status"], json.dumps(history_summary(run)), json.dumps(run), run["runId"]))
            if run["status"] not in ACTIVE:
                db.execute("""
                    DELETE FROM runs WHERE id IN (
                        SELECT id FROM runs WHERE status NOT IN ('queued', 'running')
                        ORDER BY queued DESC LIMIT -1 OFFSET ?
                    )
                    """, (self.history_limit,))

    def load(self, run_id):
        if not STORED_ID.fullmatch(run_id):
            raise FileNotFoundError
        with self.connect() as db:
            row = db.execute("SELECT payload FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise FileNotFoundError
        return json.loads(row[0])

    def history(self, workflow_id=None):
        query = "SELECT summary FROM runs"
        arguments = ()
        if workflow_id:
            query += " WHERE workflow=?"
            arguments = (workflow_id,)
        with self.connect() as db:
            records = db.execute(query + " ORDER BY queued DESC", arguments).fetchall()
        return [json.loads(row[0]) for row in records]

    def recover(self):
        with self.connect() as db:
            records = db.execute("SELECT payload FROM runs WHERE status IN ('queued', 'running')").fetchall()
        for row in records:
            run = json.loads(row[0])
            interrupt(run)
            self.save(run)


def run_summary(run):
    return {key: value for key, value in run.items() if key not in {"findings", "reports", "analyses", "deliveries"}} | {
        "findingCount": len(run["findings"]),
        "reportNodes": list(run["reports"]),
    }


def history_summary(run):
    return {key: run[key] for key in ("runId", "workflowId", "queuedAt", "startedAt", "finishedAt",
                                      "trigger", "status", "durationMs")} | {
        "findingCount": len(run["findings"]),
    }


@contextmanager
def runtime_lock(path):
    """Hold one OS-owned lease per history, including across Dashboard processes."""
    with path.open("ab") as handle:
        try:
            if sys.platform == "win32":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RunError("Хранилище запусков уже используется другим Dashboard.") from None
        yield


class WorkflowRuntime:
    def __init__(self, workflows, path, scan=subprocess_scanner):
        self.workflows = workflows
        self.store = RunStore(path)
        self.scan = scan
        self.queue = Queue(maxsize=8)
        self.stop = Event()
        self.gate = Lock()

    @contextmanager
    def running(self):
        with runtime_lock(self.store.path.with_suffix(".lock")):
            self.store.recover()
            threads = [Thread(target=self.work, name="workflow-worker"),
                       Thread(target=self.schedule, name="workflow-scheduler")]
            for thread in threads:
                thread.start()
            try:
                yield self
            finally:
                with self.gate:
                    self.stop.set()
                for thread in threads:
                    thread.join()
                self.store.recover()

    def enqueue(self, workflow, roots, source, slot=None):
        if errors := graph_errors(workflow["graph"]):
            raise InvalidWorkflow(errors)
        if not roots:
            raise RunError("В workflow отсутствует подходящий триггер.")
        with self.gate:
            if self.stop.is_set() or self.queue.full():
                raise QueueBusy("Очередь заполнена или сервер останавливается.")
            run = new_run(workflow, roots, source, slot)
            if not self.store.reserve(run):
                return None
            queued = deepcopy(run)
            self.queue.put_nowait((workflow["graph"], run))
        return queued

    def manual(self, key):
        workflow = self.workflows.load(key)
        nodes = workflow["graph"]["nodes"]
        roots = [node["id"] for node in nodes if node["type"] == "manual"]
        if not roots:
            roots = [node["id"] for node in nodes if node["type"] == "schedule"]
        return self.enqueue(workflow, roots, "manual")

    def work(self):
        while not self.stop.is_set():
            try:
                graph, run = self.queue.get(timeout=0.25)
            except Empty:
                continue
            try:
                execute_graph(graph, run, self.store.save, self.scan, self.stop.is_set)
            except Exception:
                interrupt(run)
                run["status"] = "failed"
                run["errors"] = ["Не удалось завершить workflow. Проверьте доступ к локальному хранилищу."]
                try:
                    self.store.save(run)
                except sqlite3.Error:
                    print("Workflow worker: local storage unavailable.", file=sys.stderr)
            finally:
                self.queue.task_done()

    def schedule_tick(self, moment):
        minute = moment.astimezone(UTC).replace(second=0, microsecond=0)
        for entry in self.workflows.list():
            try:
                workflow = self.workflows.load(entry["id"])
                roots = [node["id"] for node in workflow["graph"]["nodes"]
                         if node["type"] == "schedule" and next_slot(node["params"], minute) == minute]
                if roots:
                    self.enqueue(workflow, roots, "schedule", minute.isoformat())
            except (OSError, ValueError):
                continue

    def schedule(self):
        while not self.stop.is_set():
            try:
                self.schedule_tick(now())
            except (OSError, sqlite3.Error):
                print("Workflow scheduler: local storage unavailable.", file=sys.stderr)
            self.stop.wait(5)

    def schedules(self, key, moment=None):
        workflow = self.workflows.load(key)
        moment = now() if moment is None else moment
        rows = []
        for node in workflow["graph"]["nodes"]:
            if node["type"] != "schedule":
                continue
            slot = next_slot(node["params"], moment)
            rows.append({"nodeId": node["id"], "enabled": node["params"].get("enabled", False),
                         "nextAt": slot.isoformat() if slot else None})
        return rows


if __name__ == "__main__":
    # Worker actions come from fixed registries, never from workflow parameters.
    if len(sys.argv) != 2 or sys.argv[1] not in (SCANNERS.keys() | INTEGRATIONS):
        raise SystemExit(2)
    kind = sys.argv[1]
    if kind in INTEGRATIONS:
        job = json.load(sys.stdin.buffer)
        result = integration_result(kind, job["payload"], job["timeout"])
    else:
        project = project_root(PROJECT)
        result = scan_sca(project, DATABASE) if kind == "sca" else SCANNERS[kind](project)
        check_findings(result, project)
        if len(result) > MAX_FINDINGS:
            raise SystemExit(3)
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))
