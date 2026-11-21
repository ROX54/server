"""Pure conditions and schedule calculations shared by validation and execution."""
from datetime import datetime, time, timedelta, timezone
import operator
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC = timezone.utc
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
CATEGORIES = ("SECRET", "SAST", "SCA")
COMPARE = {"eq": operator.eq, "ne": operator.ne, "gt": operator.gt,
           "gte": operator.ge, "lt": operator.lt, "lte": operator.le}
REGEX_TOKEN = re.compile(r"\(\?:|\[[A-Z0-9\-^_]{1,24}\]|[A-Z0-9_ .^$|()?*+\-]", re.I | re.ASCII)


def safe_regex(pattern):
    if not 1 <= len(pattern) <= 128:
        raise ValueError("Длина регулярного выражения должна быть от 1 до 128 символов.")
    position = 0
    previous = ""
    repeats = 0
    groups = 0
    alternatives = 0
    while position < len(pattern):
        token = REGEX_TOKEN.match(pattern, position)
        if not token:
            raise ValueError("Допустимое регулярное выражение использует буквы, цифры, простые классы и группы без повторения.")
        value = token[0]
        groups += value in {"(", "(?:"}
        alternatives += value == "|"
        if groups > 4 or alternatives > 8:
            raise ValueError("Regex допускает до четырёх групп и восьми знаков альтернативы.")
        if value in {"?", "*", "+"}:
            repeats += 1
            if not previous or previous in {"(", "(?:", ")", "|", "^", "$", "?", "*", "+"} or repeats > 2:
                raise ValueError("Regex допускает до двух повторов отдельных символов или классов.")
        previous = value
        position = token.end()
    try:
        return re.compile(pattern, re.ASCII)
    except re.error:
        raise ValueError("Некорректное регулярное выражение.") from None


def condition_value(params):
    field, operation, value = (params[key] for key in ("field", "operator", "value"))
    if operation == "regex":
        if field not in {"category", "severity"}:
            raise ValueError("Regex применяется к категории или серьёзности.")
        return safe_regex(value)
    if field == "category":
        if operation not in {"eq", "ne"} or value not in CATEGORIES:
            raise ValueError("Для категории выберите = или ≠ и укажите SECRET, SAST или SCA.")
        return value
    if field == "severity":
        if value not in SEVERITIES:
            raise ValueError("Укажите серьёзность LOW, MEDIUM, HIGH или CRITICAL.")
        return SEVERITIES.index(value)
    if field == "hasFindings":
        if operation not in {"eq", "ne"} or value.lower() not in {"true", "false"}:
            raise ValueError("Для наличия находок выберите = или ≠ и укажите true или false.")
        return value.lower() == "true"
    if not re.fullmatch(r"[0-9]{1,9}", value):
        raise ValueError("Для счётчика укажите неотрицательное целое число до 9 цифр.")
    return int(value)


def condition_matches(params, findings):
    value = condition_value(params)
    field, operation = params["field"], params["operator"]
    if field in {"category", "severity"}:
        choices = CATEGORIES if field == "category" else SEVERITIES
        present = {row.get(field) for row in findings} & set(choices)
        if operation == "regex":
            return any(value.search(item) for item in present)
        values = present if field == "category" else {SEVERITIES.index(item) for item in present}
        if operation == "ne":
            return value not in values
        return any(COMPARE[operation](item, value) for item in values)
    observed = {
        "hasFindings": lambda: bool(findings),
        "findingCount": lambda: len(findings),
        "criticalCount": lambda: sum(row.get("severity") == "CRITICAL" for row in findings),
    }[field]()
    return COMPARE[operation](observed, value)


def schedule_zone(name):
    if name == "UTC":
        return UTC
    offset = re.fullmatch(r"UTC([+-])(0[0-9]|1[0-4]):([0-5][0-9])", name)
    if offset and (offset[2] != "14" or offset[3] == "00"):
        delta = timedelta(hours=int(offset[2]), minutes=int(offset[3]))
        return timezone(delta if offset[1] == "+" else -delta)
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError("Часовой пояс недоступен. Укажите UTC или смещение в формате UTC+03:00.") from None


def schedule_time(value):
    if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value):
        raise ValueError("Время запуска указывается в формате ЧЧ:ММ.")
    return time.fromisoformat(value)


def next_slot(params, earliest):
    """Return the first UTC slot at or after earliest, or none for a disabled trigger."""
    if not params.get("enabled", False):
        return None
    if params.get("mode", "interval") == "interval":
        seconds = params["intervalMinutes"] * 60
        slot = int(earliest.timestamp()) // seconds * seconds
        result = datetime.fromtimestamp(slot, UTC)
        return result if result >= earliest else result + timedelta(seconds=seconds)
    zone = schedule_zone(params["timezone"])
    clock = schedule_time(params["time"])
    day = earliest.astimezone(zone).date()
    for offset in range(4):
        local = datetime.combine(day + timedelta(days=offset), clock, zone)
        candidate = local.astimezone(UTC)
        if candidate >= earliest and candidate.astimezone(zone).replace(tzinfo=None) == local.replace(tzinfo=None):
            return candidate
    return None
