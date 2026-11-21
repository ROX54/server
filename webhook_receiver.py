"""Local-only demonstration receiver for workflow notifications."""
import argparse
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import sys

from workflow_webhook import CATEGORIES, DEMO_PORT, RECOMMENDATIONS
from ai_assistant import SECRET_TEXT

RUN_ID = re.compile(r"[0-9a-f]{32}")
MAX_BODY = 16 * 1024


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/webhook":
            return self.respond(404, {"accepted": False})
        self.connection.settimeout(5)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_BODY:
                return self.respond(413, {"accepted": False})
            data = json.loads(self.rfile.read(size))
            safe = safe_notification(data)
        except (ValueError, TypeError, OSError, RecursionError):
            return self.respond(400, {"accepted": False})
        key = self.headers.get("Idempotency-Key", "")
        if not re.fullmatch(safe["runId"] + r"(?:\.[a-zA-Z0-9_-]{1,64})?", key):
            return self.respond(400, {"accepted": False})
        if key not in self.server.received:
            self.server.received.append(key)
            print(json.dumps(safe, ensure_ascii=False), flush=True)
        return self.respond(200, {"accepted": True, "runId": safe["runId"]})


def safe_notification(data):
    if not isinstance(data, dict) or not isinstance(data.get("runId"), str) or not RUN_ID.fullmatch(data["runId"]):
        raise ValueError
    status, counts, critical = data.get("status"), data.get("counts"), data.get("criticalCount")
    if (status not in ("running", "failed") or data.get("phase") != "notification"
            or not isinstance(counts, dict) or counts.keys() != set(CATEGORIES)
            or any(type(value) is not int or not 0 <= value <= 1000 for value in counts.values())
            or type(critical) is not int or not 0 <= critical <= sum(counts.values())):
        raise ValueError
    safe = {"runId": data["runId"], "status": status, "phase": "notification", "counts": counts,
            "findingCount": sum(counts.values()), "criticalCount": critical,
            "recommendations": [RECOMMENDATIONS[label] for label in CATEGORIES if counts[label]]}
    analyses = data.get("ai", [])
    if not isinstance(analyses, list) or len(analyses) > 8:
        raise ValueError
    for item in analyses:
        if (not isinstance(item, dict) or not isinstance(item.get("summary"), str)
                or not 1 <= len(item["summary"]) <= 1000 or SECRET_TEXT.search(item["summary"])
                or type(item.get("analyzedCount")) is not int or not 0 <= item["analyzedCount"] <= 50):
            raise ValueError
        safe.setdefault("ai", []).append({"summary": item["summary"], "analyzedCount": item["analyzedCount"]})
    return safe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=DEMO_PORT)
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    with HTTPServer(("127.0.0.1", args.port), Handler) as server:
        server.received = deque(maxlen=128)
        print(f"Demo webhook: http://127.0.0.1:{server.server_port}/webhook", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
