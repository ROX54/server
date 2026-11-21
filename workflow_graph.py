"""Versioned workflow definitions and local persistence for the Dashboard."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from threading import Lock
from uuid import uuid4

from security_workflow import write_text
from workflow_controls import SEVERITIES, condition_value, schedule_time, schedule_zone

VERSION = 1
MAX_NODES = 100
MAX_EDGES = 400
MAX_COORDINATE = 12000
ID = re.compile(r"[a-zA-Z0-9_-]{1,64}")
STORED_ID = re.compile(r"[0-9a-f]{32}")
STORE_LOCK = Lock()


def parameter(label, kind, default, **options):
    return {"label": label, "kind": kind, "default": default, **options}


def node_type(title, description, group, inputs, outputs, params):
    return {"title": title, "description": description, "group": group,
            "inputs": inputs, "outputs": outputs, "params": params}


def input_port(*kinds):
    return {"in": {"label": "Вход", "types": kinds}}


def output_port(label, kind):
    return {"out": {"label": label, "type": kind}}


NODE_TYPES = {
    "manual": node_type("Manual Trigger", "Точка входа для ручного запуска.", "trigger", {},
                        output_port("Старт", "start"), {
                            "label": parameter("Подпись запуска", "text", "Ручной запуск", maxLength=80),
                        }),
    "schedule": node_type("Schedule Trigger", "Точка входа для ежедневного или интервального запуска.", "trigger", {},
                          output_port("Старт", "start"), {
                              "enabled": parameter("Расписание включено", "boolean", False, optional=True),
                              "mode": parameter("Периодичность", "select", "daily", optional=True,
                                                choices=["daily", "interval"], labels=["Ежедневно", "По интервалу"]),
                              "time": parameter("Время запуска", "text", "09:00", maxLength=5, optional=True),
                              "timezone": parameter("Часовой пояс (UTC, UTC+03:00 или IANA)", "text", "UTC",
                                                    maxLength=64, optional=True),
                              "intervalMinutes": parameter("Интервал в минутах", "integer", 60, min=1, max=10080,
                                                           optional=True),
                          }),
    **{
        category.lower(): node_type(f"{category} Scanner", detail, "scanner", input_port("start", "findings"),
                                    output_port("Находки", "findings"), {
                                        "minSeverity": parameter("Минимальная серьёзность", "select", "LOW",
                                                                 choices=SEVERITIES),
                                    })
        for category, detail in (
            ("SECRET", "Ищет секреты собственными статическими правилами."),
            ("SAST", "Проверяет Kotlin и Spring собственными статическими правилами."),
            ("SCA", "Сверяет зависимости Gradle с локальным справочником."),
        )
    },
    "condition": node_type("Condition / If-Else", "Передаёт находки по выходу True или False.", "logic",
                           input_port("findings"), {
                               "true": {"label": "True", "type": "findings"},
                               "false": {"label": "False", "type": "findings"},
                           }, {
                               "field": parameter("Поле", "select", "criticalCount",
                                                  choices=["criticalCount", "findingCount", "hasFindings", "category", "severity"],
                                                  labels=["Критических находок", "Всего находок", "Есть находки", "Категория", "Серьёзность"]),
                               "operator": parameter("Сравнение", "select", "gt",
                                                     choices=["gt", "gte", "lt", "lte", "eq", "ne", "regex"],
                                                     labels=[">", "≥", "<", "≤", "=", "≠", "Регулярное выражение"]),
                               "value": parameter("Значение", "text", "0", maxLength=128),
                           }),
    "ai": node_type("AI Analysis", "Добавляет объяснения к находкам. Использует настроенного провайдера.", "output",
                    input_port("findings"), output_port("Находки", "findings"), {
                        "maxFindings": parameter("Максимум находок для объяснения", "integer", 10, min=1, max=50),
                        "continueOnError": parameter("Продолжить с находками при ошибке AI", "boolean",
                                                     False, optional=True),
                    }),
    "report": node_type("Report Generator", "Готовит JSON и Markdown из набора находок.", "output",
                        input_port("findings"), output_port("Отчёт", "report"), {
                            "title": parameter("Заголовок отчёта", "text", "Отчёт статического анализа", maxLength=120),
                        }),
    "webhook": node_type("HTTP Webhook Notification", "Передаёт итоговую сводку настроенному получателю.", "output",
                         input_port("findings", "report"), {}, {
                             "endpointRef": parameter("Имя профиля webhook", "reference", "demo", maxLength=64),
                         }),
}


def make_node(node_id, kind, x, y, **params):
    values = {key: field["default"] for key, field in NODE_TYPES[kind]["params"].items()}
    values.update(params)
    return {"id": node_id, "type": kind, "x": x, "y": y, "params": values}


def make_edge(source, target, source_port="out"):
    return {"source": source, "sourcePort": source_port, "target": target, "targetPort": "in"}


def template(name, nodes, edges):
    return {"version": VERSION, "name": name, "nodes": nodes, "edges": edges}


def templates():
    core = [("manual", "manual"), ("secret", "secret"), ("sast", "sast"), ("sca", "sca")]
    quick = [*core, ("report", "report")]
    full = [*core, ("ai", "ai"), ("report", "report")]
    alert = [("schedule", "schedule"), *core[1:], ("condition", "condition")]
    return [
        template(name, [make_node(key, kind, 30 + (i % 3) * 230, 60 + (i // 3) * 190)
                        for i, (key, kind) in enumerate(steps)],
                 [make_edge(a[0], b[0]) for a, b in zip(steps, steps[1:])])
        for name, steps in (("Quick Security Scan", quick), ("Full Security Audit", full))
    ] + [
        template("Critical Findings Alert",
                 [make_node(key, kind, 30 + (i % 3) * 230, 60 + (i // 3) * 190)
                  for i, (key, kind) in enumerate(alert)] + [
                     make_node("critical-report", "report", 490, 250, title="Сводка критических находок"),
                     make_node("summary", "report", 490, 425, title="Отчёт плановой проверки"),
                     make_node("notify", "webhook", 720, 250),
                 ],
                 [make_edge(a[0], b[0]) for a, b in zip(alert, alert[1:])] + [
                     make_edge("condition", "critical-report", "true"),
                     make_edge("condition", "summary", "false"),
                     make_edge("critical-report", "notify"),
                 ])
    ]


def validate_params(node, spec, stored=False):
    params = node["params"]
    fields = spec["params"]
    if params.keys() - fields.keys():
        return ["Есть неизвестные параметры."]
    errors = []
    for name, field in fields.items():
        if name not in params and field.get("optional"):
            continue
        value = params.get(name)
        kind = field["kind"]
        if kind == "integer":
            if type(value) is not int or not field["min"] <= value <= field["max"]:
                errors.append(f'{field["label"]}: укажите целое число от {field["min"]} до {field["max"]}.')
        elif kind == "boolean":
            if type(value) is not bool:
                errors.append(f'{field["label"]}: выберите да или нет.')
        elif kind == "select":
            if value not in field["choices"]:
                errors.append(f'{field["label"]}: выберите значение из списка.')
        elif not isinstance(value, str) or not value.strip() or len(value) > field["maxLength"]:
            errors.append(f'{field["label"]}: укажите текст длиной до {field["maxLength"]} символов.')
        elif kind == "reference" and not ID.fullmatch(value):
            errors.append(f'{field["label"]}: используйте латинские буквы, цифры, дефис или подчёркивание.')
    if errors:
        return errors
    try:
        if node["type"] == "condition":
            if stored and params["field"] == "category" and params["operator"] == "regex":
                try:
                    re.compile(params["value"])
                except (re.error, OverflowError, RecursionError):
                    raise ValueError("Некорректное регулярное выражение.") from None
            else:
                condition_value(params)
        if node["type"] == "schedule":
            if params.get("mode", "interval") == "daily":
                schedule_time(params.get("time", ""))
                schedule_zone(params.get("timezone", ""))
            elif "intervalMinutes" not in params:
                raise ValueError("Укажите интервал в минутах.")
    except ValueError as error:
        return [str(error)]
    return errors


def graph_errors(graph, *, stored=False):
    if not isinstance(graph, dict) or graph.keys() != {"version", "name", "nodes", "edges"}:
        return ["Граф должен содержать поля version, name, nodes и edges."]
    if type(graph["version"]) is not int or graph["version"] != VERSION:
        return ["Версия формата графа не поддерживается."]
    errors = []
    if not isinstance(graph["name"], str) or not graph["name"].strip() or len(graph["name"]) > 100:
        errors.append("Название workflow должно содержать от 1 до 100 символов.")
    if not isinstance(graph["nodes"], list) or len(graph["nodes"]) > MAX_NODES:
        return [*errors, f"Ноды должны быть массивом из не более чем {MAX_NODES} записей."]
    if not isinstance(graph["edges"], list) or len(graph["edges"]) > MAX_EDGES:
        return [*errors, f"Связи должны быть массивом из не более чем {MAX_EDGES} записей."]
    nodes = {}
    triggers = set()
    for index, node in enumerate(graph["nodes"], 1):
        if (not isinstance(node, dict) or node.keys() != {"id", "type", "x", "y", "params"}
                or not isinstance(node["id"], str) or not ID.fullmatch(node["id"])
                or not isinstance(node["type"], str) or node["type"] not in NODE_TYPES
                or not isinstance(node["params"], dict)):
            errors.append(f"Нода {index}: неизвестный тип или неверная структура.")
            continue
        node_id = node["id"]
        if node_id in nodes:
            errors.append(f"Идентификатор ноды повторяется: {node_id}.")
            continue
        nodes[node_id] = node
        spec = NODE_TYPES[node["type"]]
        if spec["group"] == "trigger":
            triggers.add(node_id)
        if any(type(node[axis]) is not int or not 0 <= node[axis] <= MAX_COORDINATE for axis in ("x", "y")):
            errors.append(f'{spec["title"]} ({node_id}): координаты вне рабочего поля.')
        errors.extend(f'{spec["title"]} ({node_id}): {error}' for error in validate_params(node, spec, stored))
    if not triggers:
        errors.append("Добавьте хотя бы один Manual Trigger или Schedule Trigger.")

    successors = {key: set() for key in nodes}
    seen = set()
    for index, edge in enumerate(graph["edges"], 1):
        if (not isinstance(edge, dict) or edge.keys() != {"source", "sourcePort", "target", "targetPort"}
                or not all(isinstance(value, str) for value in edge.values())):
            errors.append(f"Связь {index}: неверная структура.")
            continue
        source, target = edge["source"], edge["target"]
        if source not in nodes or target not in nodes:
            errors.append(f"Связь {index}: исходная или целевая нода отсутствует.")
            continue
        output = NODE_TYPES[nodes[source]["type"]]["outputs"].get(edge["sourcePort"])
        target_input = NODE_TYPES[nodes[target]["type"]]["inputs"].get(edge["targetPort"])
        if output is None or target_input is None or output["type"] not in target_input["types"]:
            errors.append(f"Связь {index}: несовместимые порты {source} → {target}.")
            continue
        key = (source, edge["sourcePort"], target, edge["targetPort"])
        if key in seen:
            errors.append(f"Связь {index}: такая связь уже существует.")
            continue
        seen.add(key)
        successors[source].add(target)

    depths = {}

    def has_cycle(node):
        if node in depths:
            return depths[node] == 1
        depths[node] = 1
        if any(has_cycle(target) for target in successors[node]):
            return True
        depths[node] = 2
        return False

    if any(has_cycle(node) for node in nodes):
        errors.append("Граф содержит цикл. Удалите обратную связь.")

    reachable = set(triggers)
    pending = list(triggers)
    while pending:
        for target in successors[pending.pop()] - reachable:
            reachable.add(target)
            pending.append(target)
    for node_id in sorted(nodes.keys() - reachable):
        errors.append(f'{NODE_TYPES[nodes[node_id]["type"]]["title"]} ({node_id}): нет пути от триггера.')
    return errors


class InvalidWorkflow(ValueError):
    def __init__(self, errors):
        super().__init__(errors[0])
        self.errors = errors


class WorkflowStore:
    def __init__(self, directory):
        self.directory = Path(directory)

    def path(self, key):
        if not isinstance(key, str) or not STORED_ID.fullmatch(key):
            raise FileNotFoundError
        return self.directory / f"{key}.json"

    def load(self, key):
        record = json.loads(self.path(key).read_text(encoding="utf-8"))
        if not isinstance(record, dict) or record.get("id") != key or not isinstance(record.get("updatedAt"), str):
            raise InvalidWorkflow(["Файл workflow повреждён."])
        if errors := graph_errors(record.get("graph"), stored=True):
            raise InvalidWorkflow(errors)
        return record

    def list(self):
        rows = []
        for path in self.directory.glob("*.json"):
            try:
                record = self.load(path.stem)
            except (OSError, ValueError):
                continue
            rows.append({"id": record["id"], "name": record["graph"]["name"], "updatedAt": record["updatedAt"]})
        return sorted(rows, key=lambda row: row["updatedAt"], reverse=True)

    def archive(self, key):
        with STORE_LOCK:
            source = self.path(key)
            if not source.is_file():
                raise FileNotFoundError
            archive = self.directory / "archive"
            archive.mkdir(exist_ok=True)
            source.rename(archive / source.name)

    def save(self, graph, key=None):
        if errors := graph_errors(graph):
            raise InvalidWorkflow(errors)
        with STORE_LOCK:
            if key is not None:
                self.load(key)
            else:
                key = uuid4().hex
            record = {"id": key, "updatedAt": datetime.now(timezone.utc).isoformat(), "graph": graph}
            self.directory.mkdir(parents=True, exist_ok=True)
            write_text(self.path(key), json.dumps(record, ensure_ascii=False, indent=2) + "\n")
        return record
