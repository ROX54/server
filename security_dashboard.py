#!/usr/bin/env python3
"""Local Cyber Garden security dashboard for the training project."""
from __future__ import annotations
import json
import os
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.parse import parse_qs, urlparse

from ai_assistant import AIError, SAFE_FIELDS, settings as ai_settings
from security_workflow import DATABASE, analyze, read, write_reports, write_text
from validate_results import TRUTH, evaluate, load_findings, validation_markdown
from workflow_graph import (
    MAX_COORDINATE, MAX_EDGES, MAX_NODES, NODE_TYPES, VERSION, InvalidWorkflow,
    WorkflowStore, graph_errors, templates,
)
from workflow_engine import QueueBusy, RunError, WorkflowRuntime, bounded_integration, run_summary

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT / "training-project"
REPORT = ROOT / "security-report"
REPORT_LOCK = Lock()
WORKFLOWS = WorkflowStore(ROOT / "workflow-data")
RUN_DATABASE = WORKFLOWS.directory / "runs.sqlite3"
CLIENT_ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/workflow-builder.css": ("workflow-builder.css", "text/css; charset=utf-8"),
    "/workflow-builder.js": ("workflow-builder.js", "text/javascript; charset=utf-8"),
}


def client_root():
    return Path(os.environ.get("CYBERGARDEN_CLIENT_DIR", ROOT.parent / "client")).resolve()


def contest_results(validation=None):
    path = REPORT / "findings.json"
    if not path.exists():
        return {"findings": [], "generatedAt": None, "validation": None}
    findings = load_findings(path, PROJECT)
    if validation is None:
        validation = evaluate(findings, json.loads(read(TRUTH)))
    return {
        "findings": findings,
        "generatedAt": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
        "validation": validation,
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_bytes(self, data: bytes, content_type: str, status=200, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)

    def send_json(self, data, status=200):
        return self.send_bytes(json.dumps(data, ensure_ascii=False).encode(),
                               "application/json; charset=utf-8", status)

    def do_GET(self):
        url = urlparse(self.path)
        path = url.path
        if path in CLIENT_ASSETS:
            name, content_type = CLIENT_ASSETS[path]
            asset = client_root() / name
            try:
                data = asset.read_bytes()
            except FileNotFoundError:
                return self.send_json({"error": "Set CYBERGARDEN_CLIENT_DIR to the CyberGarden client checkout."}, 404)
            return self.send_bytes(data, content_type)
        if path == "/api/ai/settings":
            return self.send_json(ai_settings())
        if path == "/api/workflow-library":
            return self.send_json({
                "version": VERSION, "nodeTypes": NODE_TYPES, "templates": templates(),
                "limits": {"coordinate": MAX_COORDINATE, "nodes": MAX_NODES, "edges": MAX_EDGES},
            })
        if path == "/api/workflows":
            return self.send_json({"workflows": WORKFLOWS.list()})
        if path == "/api/workflow-runs" or path.startswith("/api/workflow-runs/"):
            return self.workflow_run_data(path, parse_qs(url.query))
        if path.startswith("/api/workflows/") and path.endswith("/schedule") and path.count("/") == 4:
            return self.workflow_schedule(path.split("/")[3])
        if path.startswith("/api/workflows/"):
            try:
                return self.send_json(WORKFLOWS.load(path.removeprefix("/api/workflows/")))
            except FileNotFoundError:
                return self.send_json({"errors": ["Workflow не найден."]}, 404)
            except (OSError, ValueError):
                return self.send_json({"errors": ["Не удалось прочитать сохранённый workflow."]}, 500)
        if path == "/api/findings":
            try:
                with REPORT_LOCK:
                    payload = contest_results()
                return self.send_json(payload)
            except (OSError, ValueError):
                return self.send_json({"error": "Не удалось прочитать конкурсный отчёт."}, 500)
        if path.startswith("/reports/"):
            name = path.rsplit("/", 1)[-1]
            allowed = {"findings.json": "application/json; charset=utf-8", "report.md": "text/markdown; charset=utf-8", "validation.md": "text/markdown; charset=utf-8"}
            if name not in allowed: return self.send_bytes(b"Not found", "text/plain", 404)
            file = REPORT / name
            if not file.exists(): return self.send_bytes(b"Report not generated yet", "text/plain", 404)
            with REPORT_LOCK:
                data = file.read_bytes()
            return self.send_bytes(data, allowed[name],
                                   extra={"Content-Disposition": f'attachment; filename="{name}"'})
        return self.send_bytes(b"Not found", "text/plain", 404)

    def do_POST(self):
        path=urlparse(self.path).path
        if path in {"/api/workflows", "/api/workflows/validate"}:
            return self.save_workflow(path)
        if path.startswith("/api/workflows/") and path.endswith("/run") and path.count("/") == 4:
            return self.start_workflow(path.split("/")[3])
        if path in {"/api/ai/explain", "/api/ai/check"}:
            return self.ai_request(path)
        if path != "/api/scan":
            return self.send_bytes(b"Not found", "text/plain", 404)
        if not REPORT_LOCK.acquire(blocking=False):
            return self.send_json({"error": "Конкурсный анализ уже выполняется."}, 409)
        try:
            findings = analyze(PROJECT, DATABASE)
            validation = evaluate(findings, json.loads(read(TRUTH)))
            write_reports(PROJECT, REPORT, findings)
            write_text(REPORT / "validation.md", validation_markdown(validation))
            payload = contest_results(validation)
        except (OSError, ValueError, KeyError):
            return self.send_json({"error": "Не удалось завершить анализ или сохранить отчёт."}, 500)
        finally:
            REPORT_LOCK.release()
        return self.send_json(payload)

    def ai_request(self, path):
        if self.headers.get_content_type() != "application/json":
            return self.send_json({"error": "Ожидается JSON."}, 415)
        if path.endswith("/check"):
            try:
                return self.send_json(bounded_integration("ai-check", {}, 12))
            except AIError as error:
                return self.send_json({**ai_settings(), "connected": False, "message": str(error)}, 503)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 20_000:
                return self.send_json({"error": "Недопустимый размер запроса AI."}, 413)
            body = json.loads(self.rfile.read(length))
            submitted = body.get("finding") if isinstance(body, dict) else None
            if not isinstance(submitted, dict):
                return self.send_json({"error": "Укажите находку из конкурсного отчёта."}, 400)
            with REPORT_LOCK:
                finding = next((row for row in contest_results()["findings"]
                                if all(row.get(key) == submitted.get(key) for key in SAFE_FIELDS)), None)
            if finding is None:
                return self.send_json({"error": "Находка отсутствует в текущем конкурсном отчёте."}, 404)
            return self.send_json(bounded_integration("ai-explain", {"finding": finding}, 25))
        except AIError as error:
            return self.send_json({"error": str(error)}, 503)
        except (OSError, ValueError, RecursionError):
            return self.send_json({"error": "Не удалось прочитать запрос или конкурсный отчёт."}, 400)

    def start_workflow(self, workflow_id):
        runtime = getattr(self.server, "workflow_runtime", None)
        if runtime is None:
            return self.send_json({"errors": ["Исполнитель workflow недоступен."]}, 503)
        if self.headers.get_content_type() != "application/json":
            return self.send_json({"errors": ["Ожидается JSON."]}, 415)
        try:
            return self.send_json(run_summary(runtime.manual(workflow_id)), 202)
        except InvalidWorkflow as error:
            return self.send_json({"errors": error.errors}, 422)
        except FileNotFoundError:
            return self.send_json({"errors": ["Workflow не найден."]}, 404)
        except QueueBusy as error:
            return self.send_json({"errors": [str(error)]}, 409)
        except RunError as error:
            return self.send_json({"errors": [str(error)]}, 422)
        except (OSError, ValueError, sqlite3.Error):
            return self.send_json({"errors": ["Не удалось создать запуск."]}, 500)

    def workflow_schedule(self, workflow_id):
        runtime = getattr(self.server, "workflow_runtime", None)
        if runtime is None:
            return self.send_json({"errors": ["Планировщик недоступен."]}, 503)
        try:
            return self.send_json({"schedules": runtime.schedules(workflow_id)})
        except FileNotFoundError:
            return self.send_json({"errors": ["Workflow не найден."]}, 404)
        except (OSError, ValueError, sqlite3.Error):
            return self.send_json({"errors": ["Не удалось прочитать расписание."]}, 500)

    def workflow_run_data(self, path, query):
        runtime = getattr(self.server, "workflow_runtime", None)
        if runtime is None:
            return self.send_json({"errors": ["История запусков недоступна."]}, 503)
        try:
            if path == "/api/workflow-runs":
                key = query.get("workflowId", [None])[0]
                return self.send_json({"runs": runtime.store.history(key)})
            _, _, _, run_id, *parts = path.split("/")
            run = runtime.store.load(run_id)
            if not parts:
                return self.send_json(run_summary(run))
            if parts == ["results"]:
                return self.send_json({"findings": run["findings"], "reports": run["reports"],
                                       "analyses": run.get("analyses", {}),
                                       "deliveries": run.get("deliveries", {})})
            if len(parts) == 3 and parts[0] == "reports" and parts[1] in run["reports"]:
                report = run["reports"][parts[1]]
                if parts[2] == "findings.json":
                    data = json.dumps(report["json"], ensure_ascii=False, indent=2) + "\n"
                    mime = "application/json; charset=utf-8"
                elif parts[2] == "report.md":
                    data, mime = report["markdown"], "text/markdown; charset=utf-8"
                else:
                    raise FileNotFoundError
                return self.send_bytes(data.encode(), mime,
                                       extra={"Content-Disposition": f'attachment; filename="{parts[2]}"'})
            raise FileNotFoundError
        except FileNotFoundError:
            return self.send_json({"errors": ["Запуск или отчёт не найден."]}, 404)
        except (OSError, ValueError, sqlite3.Error):
            return self.send_json({"errors": ["Не удалось прочитать результаты запуска."]}, 500)

    def save_workflow(self, path):
        if self.headers.get_content_type() != "application/json":
            return self.send_json({"errors": ["Ожидается JSON."]}, 415)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 256 * 1024:
                return self.send_json({"errors": ["Недопустимый размер workflow."]}, 413)
            body = json.loads(self.rfile.read(size))
            if (not isinstance(body, dict) or "graph" not in body
                    or body.keys() - {"id", "graph"}):
                return self.send_json({"errors": ["Ожидается объект с полем graph."]}, 400)
            if path.endswith("/validate"):
                errors = graph_errors(body["graph"])
                return self.send_json({"errors": errors}, 422 if errors else 200)
            record = WORKFLOWS.save(body["graph"], body.get("id"))
            return self.send_json(record, 200 if body.get("id") is not None else 201)
        except InvalidWorkflow as error:
            return self.send_json({"errors": error.errors}, 422)
        except FileNotFoundError:
            return self.send_json({"errors": ["Workflow не найден."]}, 404)
        except (ValueError, RecursionError):
            return self.send_json({"errors": ["Не удалось прочитать JSON workflow."]}, 400)
        except OSError:
            return self.send_json({"errors": ["Не удалось записать workflow на диск."]}, 500)


def load_env_file():
    env_file=ROOT/".env"
    if not env_file.exists(): return
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line=raw.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        key,value=line.split("=",1)
        key=key.strip(); value=value.strip().strip('"').strip("'")
        if key and key not in os.environ: os.environ[key]=value


def main():
    load_env_file()
    import argparse
    p = argparse.ArgumentParser(description="Cyber Garden local security dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    args = p.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Cyber Garden dashboard: http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop. Local-only server; do not expose to the public internet.")
    try:
        runtime = WorkflowRuntime(WORKFLOWS, RUN_DATABASE)
        with runtime.running():
            server.workflow_runtime = runtime
            server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    except RunError as error:
        p.exit(1, f"{error}\n")
    finally:
        server.server_close()

if __name__ == "__main__": main()
