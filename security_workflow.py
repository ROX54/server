#!/usr/bin/env python3
"""Offline SECRET, SAST and SCA analysis for local training projects."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile

ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "vulnerability-database" / "vulnerabilities.json"
EXCLUDED = {".git", ".gradle", ".idea", "build", "node_modules", "vendor"}
CONFIG = {".yml", ".yaml", ".properties", ".conf", ".json", ".toml", ".env"}
LITERAL = r"""(?:"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')"""
KOTLIN_COMMENT_OR_STRING = re.compile(
    r'"""[\s\S]*?"""|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*[\s\S]*?\*/'
)
SECRET_ASSIGNMENT = re.compile(
    rf"""(?m)(?:^[ \t]*(?:[\w-]+[ \t]+)*|(?<=[{{,])[ \t]*)["']?(?P<name>[\w.-]+)["']?[ \t]*[:=][ \t]*(?P<value>{LITERAL}|(?:Bearer[ \t]+)?[^\s,;\]]+)""",
    re.I,
)
SECRET_FALLBACK = re.compile(
    rf"""\b(?:System\.getenv|environment\.getProperty)\(\s*(?P<name>{LITERAL})\s*\)\s*\?:\s*(?P<value>{LITERAL})"""
)
BEARER = re.compile(r"\bsetBearerAuth\(\s*(\w+)\s*\)")
ASSIGN = re.compile(r"(?m)^[ \t]*(?:[\w]+[ \t]+)*\b(?:val|var)\s+(\w+)\s*(?::\s*[\w?.<>]+)?\s*=\s*([^\n;]+)")
JDBC = re.compile(r"\.\s*(?:query(?:ForList|ForObject|ForMap)?|update|execute|batchUpdate)\s*\(")
SQL = re.compile(r"(?i)^\s*(?:select|insert|update|delete|with)\b")
ROUTE_RULE = re.compile(
    r'\b(?:requestMatchers|antMatchers)\s*\(([^()]*)\)\s*\.\s*'
    r'(permitAll|authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|denyAll)\s*\('
)
METHOD_GUARD = re.compile(r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b")
REFERENCE = re.compile(r"\$(?:\{([^{}]+)\}|([A-Za-z_]\w*))")
MAVEN = re.compile(r"^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)(?::(.+))?$")
GRADLE_STRING = r'"(?:\$\{[^{}\n]*\}|\\.|[^"\\\n])*"'
GRADLE_DEPENDENCY = re.compile(
    rf'\b(?:\w*(?:[iI]mplementation|[aA]pi|[cC]ompileOnly|[rR]untimeOnly|[aA]nnotationProcessor)|kapt\w*|ksp\w*|add)\s*\(\s*'
    rf'(?:"[\w]+"[ \t\r\n]*,[ \t\r\n]*)?(?:(?:platform|enforcedPlatform)\(\s*)?(?P<coordinate>{GRADLE_STRING})'
)
GRADLE_PROPERTY = re.compile(r"""providers\.gradleProperty\(\s*["']([^"']+)["']\s*\)\.get\(\s*\)""")

RULES = {
    "password": ("HIGH", "Встроенный пароль хранится в файле проекта.", "Загружать пароль из защищённой конфигурации."),
    "api-key": ("HIGH", "Ключ API задан строковым литералом.", "Хранить ключ в защищённой конфигурации и заменить опубликованный ключ."),
    "configuration-token": ("HIGH", "В файле задан токен авторизации.", "Загружать токен из защищённого хранилища."),
    "secret-fallback": ("HIGH", "При отсутствии настройки используется встроенный секрет.", "Удалить значение по умолчанию и явно обработать отсутствие настройки."),
    "recoverable-token": ("HIGH", "Bearer-токен собирается из строковых литералов в исходниках.", "Получать токен из защищённого хранилища."),
    "sql-injection": ("CRITICAL", "SQL собирается с подстановкой динамического значения перед передачей в JDBC.", "Передавать значения отдельными параметрами JDBC."),
    "tls-verification": ("HIGH", "HTTPS-клиент допускает соединение без штатной проверки имени хоста.", "Использовать стандартную проверку имени хоста и доверенную цепочку сертификатов."),
    "credentialed-cors": ("HIGH", "Политика CORS допускает произвольный origin с учётными данными.", "Перечислить доверенные origin или отключить передачу credentials."),
    "route-authorization": ("HIGH", "Публичное правило для маршрута предшествует более строгому правилу, которое также его покрывает.", "Уточнить порядок и область правил доступа и проверить политику для маршрута."),
    "object-authorization": ("HIGH", "Объект выбирается по идентификатору запроса без видимого ограничения по владельцу.", "Ограничить выборку идентификатором текущего пользователя или проверить права на объект."),
}


def read(path):
    return path.read_text(encoding="utf-8-sig", errors="replace")


def is_link(path):
    info = path.lstat()
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def project_root(path):
    path = Path(path)
    if not path.is_dir() or is_link(path):
        raise ValueError("Укажите существующий каталог локального проекта.")
    return path.resolve()


def project_files(project):
    for parent, directories, files in os.walk(project):
        base = Path(parent)
        directories[:] = sorted(
            name for name in directories if name not in EXCLUDED and not is_link(base / name)
        )
        for name in sorted(files):
            path = base / name
            if not is_link(path) and path.is_file():
                yield path


def kotlin_source(text):
    return KOTLIN_COMMENT_OR_STRING.sub(
        lambda m: re.sub(r"[^\n]", " ", m[0]) if m[0].startswith(("//", "/*")) else m[0],
        text,
    )


def kotlin_code(text):
    return KOTLIN_COMMENT_OR_STRING.sub(lambda match: re.sub(r"[^\n]", " ", match[0]), text)


def line_number(source, offset):
    return source.count("\n", 0, offset) + 1


def finding(category, path, code, first, last=None):
    severity, description, remediation = RULES[code]
    row = dict(category=category, path=path, line=first, severity=severity,
               description=description, remediation=remediation)
    row["class"] = code
    if last is not None and last > first:
        row["endLine"] = min(last, first + 14)
    return row


def secret_kind(name):
    name = re.sub(r"[^a-z0-9]", "", name.lower())
    if "password" in name or "passwd" in name or name.endswith("pwd"):
        return "password"
    if "apikey" in name or name.endswith(("accesskey", "clientkey")):
        return "api-key"
    if name.endswith(("token", "secret", "authorization", "credential")):
        return "configuration-token"
    return None


def hardcoded(value):
    value = re.sub(r"^Bearer\s+", "", value.strip(), flags=re.I)
    if len(value) < 6 or "$" in value or value.startswith(("<", "{", "http://", "https://")):
        return False
    return not re.match(
        r"(?:your[_ -]|example(?:[_ -]|$)|placeholder|replace[_ -]?me|changeme|dummy(?:[_ -]|$)|"
        r"redacted|masked|bearer$|test(?:[_ -]?(?:token|password|api[_ -]?key|secret))?$|x{4,}$|[*-]+$)",
        value, re.I,
    )


def scan_secrets(project):
    out = []
    for file in project_files(project):
        kotlin = file.suffix in {".kt", ".kts"}
        if not kotlin and file.suffix.lower() not in CONFIG and not (
            file.name == ".env" or file.name.startswith(".env.")
        ):
            continue
        path = file.relative_to(project).as_posix()
        raw = read(file)
        text = kotlin_source(raw) if kotlin else raw
        code = kotlin_code(text) if kotlin else None
        for match in SECRET_ASSIGNMENT.finditer(text):
            if code is not None and code[match.start("name")] == " ":
                continue
            value = match["value"].strip("\"'")
            kind = secret_kind(match["name"])
            if kind and (not kotlin or re.fullmatch(LITERAL, match["value"])) and hardcoded(value):
                out.append(finding("SECRET", path, kind, line_number(text, match.start("name"))))
        if not kotlin:
            continue
        for match in SECRET_FALLBACK.finditer(text):
            if code[match.start()] != " " and secret_kind(match["name"].strip("\"'")) and hardcoded(match["value"].strip("\"'")):
                out.append(finding("SECRET", path, "secret-fallback", line_number(text, match.start())))
        assignments = [m for m in ASSIGN.finditer(text) if code[m.start(1)] != " "]
        for sink in BEARER.finditer(text):
            if code[sink.start()] == " ":
                continue
            last = line_number(text, sink.start())
            nearby = {
                m[1]: m for m in assignments
                if 0 < last - line_number(text, m.start()) <= 14 and m.start() < sink.start()
            }
            combined = nearby.get(sink[1])
            parts = re.fullmatch(r"\s*(\w+)\s*\+\s*(\w+)\s*", combined[2]) if combined else None
            if parts and all(name in nearby for name in parts.groups()):
                pieces = [nearby[name] for name in parts.groups()]
                if all(p.start() < combined.start() and re.fullmatch(LITERAL, p[2].strip()) for p in pieces):
                    value = "".join(p[2].strip()[1:-1] for p in pieces)
                    if hardcoded(value):
                        first = min(line_number(text, p.start()) for p in pieces)
                        out.append(finding("SECRET", path, "recoverable-token", first, last))
    return out


def kotlin_functions(source):
    """Find named function declarations and their approximate lexical bodies."""
    declarations = list(re.finditer(
        r"(?m)^[ \t]*(?:[\w]+[ \t]+)*fun\s+(\w+)\s*\(", kotlin_code(source)
    ))
    for index, declaration in enumerate(declarations):
        limit = declarations[index + 1].start() if index + 1 < len(declarations) else len(source)
        yield declaration, source[declaration.start():limit]


def sql_argument(body, call):
    tail = body[call.end():].lstrip()
    quoted = re.match(r'"""([\s\S]*?)"""|("(?:\\.|[^"\\\n])*")', tail)
    if quoted:
        return (quoted[1] or (quoted[2] or "")[1:-1], tail[quoted.end():])
    name = re.match(r"\w+", tail)
    if name:
        previous = [match for match in ASSIGN.finditer(body[:call.start()]) if match[1] == name[0]]
        if previous:
            expression = previous[-1][2].strip()
            return expression.strip('"'), tail[name.end():]
    return "", ""


def route_findings(path, text):
    patterns = []
    code = kotlin_code(text)
    for match in ROUTE_RULE.finditer(text):
        if code[match.start()] == " ":
            continue
        paths = [m[1] for m in re.finditer(r'"(/[^"\n]*)"', match[1])]
        method = re.search(r"^\s*(?:HttpMethod\.)?(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*,", match[1])
        for route in paths:
            patterns.append((match, route, method[1] if method else None))
    for index, (entry, route, method) in enumerate(patterns):
        if entry[2] != "permitAll" or "*" in route:
            continue
        for later, restricted, restricted_method in patterns[index + 1:]:
            if later[2] == "permitAll" or (method and restricted_method and method != restricted_method):
                continue
            prefix = restricted.removesuffix("/**")
            if route == prefix or (restricted.endswith("/**") and route.startswith(prefix + "/")):
                yield finding("SAST", path, "route-authorization", line_number(text, entry.start()))
                break


def cors_findings(path, text):
    scopes = re.finditer(
        r"\bCorsConfiguration\(\)\s*\.apply\s*\{([^{}]*)\}|"
        r"\bval\s+(\w+)\s*=\s*CorsConfiguration\(\)(?!\s*\.apply)([\s\S]*?)(?=\n\s*val\b|\Z)",
        text,
    )
    for scope in scopes:
        body = scope[1] if scope[1] is not None else scope[3]
        offset = scope.start(1) if scope[1] is not None else scope.start(3)
        receiver = "" if scope[2] is None else rf"\b{re.escape(scope[2])}\."
        origin = re.search(
            receiver + r'\b(?:allowedOriginPatterns|allowedOrigins)\s*=\s*(?:listOf|mutableListOf|arrayListOf)\(\s*"\*"\s*\)|'
            + receiver + r'\baddAllowedOrigin(?:Pattern)?\(\s*"\*"\s*\)', body
        )
        credentials = re.search(receiver + r"\b(?:allowCredentials\s*=\s*true\b|setAllowCredentials\(\s*true\s*\))", body)
        if origin and credentials:
            yield finding(
                "SAST", path, "credentialed-cors",
                line_number(text, offset + min(origin.start(), credentials.start())),
                line_number(text, offset + max(origin.start(), credentials.start())),
            )


def scan_sast(project):
    sources = {
        p.relative_to(project).as_posix(): kotlin_source(read(p))
        for p in project_files(project) if p.suffix == ".kt"
    }
    out = []
    unguarded_queries = {}
    for path, text in sources.items():
        code = kotlin_code(text)
        out.extend(route_findings(path, text))
        out.extend(cors_findings(path, text))
        for match in re.finditer(
            r"\b(?:HostnameVerifier\s*\{\s*(?:\w+\s*,\s*\w+\s*->\s*)?true\s*\}|"
            r"NoopHostnameVerifier\s*(?:\.\s*INSTANCE|\(\s*\)))", text
        ):
            if code[match.start()] != " ":
                out.append(finding("SAST", path, "tls-verification", line_number(text, match.start())))
        for declaration, body in kotlin_functions(text):
            first = line_number(text, declaration.start())
            for call in JDBC.finditer(kotlin_code(body)):
                sql, remainder = sql_argument(body, call)
                if not SQL.match(sql):
                    continue
                sql_line = line_number(text, declaration.start() + call.start())
                if REFERENCE.search(sql) or re.match(r"\s*\+\s*[\w$(]", remainder):
                    out.append(finding("SAST", path, "sql-injection", max(first, sql_line - 1), sql_line))
                # Only flag object lookups linked to a controller's path-variable input.
                if not re.search(r"\bWHERE\s+(?:\w+\.)?\w+\s*=\s*\?\s*$", sql, re.I):
                    continue
                parameters = body[declaration.end() - declaration.start():]
                identifier = re.match(r"\s*(\w+)\s*:\s*(?:Long|Int|UUID|String)\s*\)", parameters)
                if not (identifier and re.match(r"(?is)\s*select\s+(?!count\s*\().+", sql)
                        and re.search(rf",\s*{re.escape(identifier[1])}\s*[,]?\s*\)", remainder)):
                    continue
                owners = list(re.finditer(r"\bclass\s+(\w+)", text[:declaration.start()]))
                if owners and re.search(r"\b@Repository\b|\bJdbcTemplate\b", text):
                    key = (owners[-1][1], declaration[1])
                    last = min(sql_line + 1, len(text.splitlines()))
                    unguarded_queries.setdefault(key, []).append((path, first, last))
    for path, text in sources.items():
        if not re.search(r"@(?:RestController|Controller)\b", text):
            continue
        receivers = dict(re.findall(r"\b(?:val|var)\s+(\w+)\s*:\s*(\w+)", text))
        for declaration, body in kotlin_functions(text):
            argument = re.search(r"@PathVariable(?:\([^)]*\))?\s+(\w+)\s*:", body.split("=", 1)[0])
            before = text[max(0, declaration.start() - 300):declaration.start()]
            annotations = re.search(r"(?:[ \t]*@\w+[^\n]*\n)+[ \t]*$", before)
            if not argument or (annotations and METHOD_GUARD.search(annotations[0])):
                continue
            if re.search(r"\b(?:Principal|Authentication|SecurityContextHolder|hasPermission|checkAccess)\b", body):
                continue
            for receiver, method in re.findall(
                rf"\b(\w+)\s*\.\s*(\w+)\s*\(\s*{re.escape(argument[1])}\s*\)", body
            ):
                candidates = unguarded_queries.get((receivers.get(receiver), method), [])
                if len(candidates) == 1:
                    location, first, last = candidates[0]
                    out.append(finding("SAST", location, "object-authorization", first, last))
    return out


def version_tuple(value):
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
        return None
    components = tuple(map(int, value.split(".")))
    while len(components) > 1 and components[-1] == 0:
        components = components[:-1]
    return components


def in_range(version, bounds):
    value = version_tuple(version)
    if value is None:
        return False
    lower = version_tuple(bounds["lower"]) if bounds["lower"] is not None else None
    upper = version_tuple(bounds["upper"])
    return (
        (lower is None or value > lower or (value == lower and bounds["lowerInclusive"]))
        and (value < upper or (value == upper and bounds["upperInclusive"]))
    )


def adjacent_file(directory, name):
    path = directory / name
    return read(path) if path.exists() and not is_link(path) and path.is_file() else ""


def gradle_dependencies(text):
    code = kotlin_code(text)
    for block in re.finditer(r"\bdependencies\s*\{", code):
        depth = 1
        end = block.end()
        for brace in re.finditer(r"[{}]", code[end:]):
            depth += 1 if brace[0] == "{" else -1
            if depth == 0:
                end += brace.start()
                break
        for dependency in GRADLE_DEPENDENCY.finditer(text, block.end(), end):
            if code[dependency.start()] != " ":
                yield dependency["coordinate"][1:-1]


def scan_sca(project, database):
    advisories = {}
    for advisory in json.loads(read(database))["vulnerabilities"]:
        advisories.setdefault((advisory["group"], advisory["artifact"]), []).append(advisory)
    out = []
    for file in project_files(project):
        if file.name != "build.gradle.kts":
            continue
        path = file.relative_to(project).as_posix()
        text = kotlin_source(read(file))
        props = dict(re.findall(r"(?m)^\s*([\w.-]+)\s*[=:]\s*(\S+)", adjacent_file(project, "gradle.properties")))
        props.update(re.findall(r"(?m)^\s*([\w.-]+)\s*[=:]\s*(\S+)", adjacent_file(file.parent, "gradle.properties")))
        versions = dict(re.findall(r'(?m)\bval\s+(\w+)(?:\s*:\s*String)?\s*=\s*"([0-9.]+)"', text))
        versions.update(
            (match[1], props.get(match[2], ""))
            for match in re.finditer(r"\bval\s+(\w+)(?:\s*:\s*String)?\s*=\s*" + GRADLE_PROPERTY.pattern, text)
        )
        versions.update(
            (name, props.get(name, ""))
            for name in re.findall(r"\bval\s+(\w+)\s*:\s*String\s+by\s+project\b", text)
        )
        locks = {}
        for group, artifact, version in re.findall(
            r"(?m)^([\w.-]+):([\w.-]+):([^=\s]+)=",
            adjacent_file(file.parent, "gradle.lockfile"),
        ):
            locks.setdefault((group, artifact), set()).add(version)
        seen = set()
        for dependency in gradle_dependencies(text):
            declared = MAVEN.fullmatch(dependency)
            if not declared:
                continue
            group, artifact, raw_version = declared.groups()
            version = raw_version or ""
            reference = REFERENCE.fullmatch(version)
            if reference:
                expression = reference[1] or reference[2]
                prop = GRADLE_PROPERTY.fullmatch(expression.strip())
                version = props.get(prop[1], "") if prop else versions.get(expression.strip(), "")
            for resolved in sorted(locks.get((group, artifact), {version})):
                for advisory in advisories.get((group, artifact), []):
                    key = (group, artifact, resolved, advisory["id"])
                    if key in seen or not any(in_range(resolved, bounds) for bounds in advisory["ranges"]):
                        continue
                    seen.add(key)
                    advisory_id = next((a for a in advisory["aliases"] if a.startswith("CVE-")), advisory["id"])
                    out.append(dict(category="SCA", path=path, group=group, artifact=artifact,
                                    version=resolved, advisoryId=advisory_id, severity=advisory["severity"],
                                    description="Разрешённая версия входит в диапазон уязвимых версий из локального справочника.",
                                    remediation="Выбрать исправленную версию из справочника и обновить lockfile."))
    return out


def analyze(project, database=DATABASE):
    project = project_root(project)
    findings = scan_secrets(project) + scan_sast(project) + scan_sca(project, database)
    unique = {tuple(sorted(item.items())): item for item in findings}
    return sorted(unique.values(), key=lambda item: (
        item["category"], item["path"], item.get("line", 0), item.get("group", ""),
        item.get("artifact", ""), item.get("version", ""), item.get("advisoryId", ""),
    ))


def check_findings(findings, project):
    if not isinstance(findings, list):
        raise ValueError("Поле findings должно быть массивом.")
    files = {p.relative_to(project).as_posix(): p for p in project_files(project)}
    line_counts = {}
    for item in findings:
        if not isinstance(item, dict) or item.get("category") not in {"SECRET", "SAST", "SCA"}:
            raise ValueError("Недопустимая категория находки.")
        path = item.get("path")
        if not isinstance(path, str) or ":" in path:
            raise ValueError("Путь находки должен указывать на файл внутри проекта.")
        path = path.replace("\\", "/")
        if path not in files:
            raise ValueError("Путь находки должен указывать на файл внутри проекта.")
        common = {"category", "path", "severity", "description", "remediation"}
        required = {"group", "artifact", "version", "advisoryId"} if item["category"] == "SCA" else {"class"}
        lines = set() if item["category"] == "SCA" else {"line", "endLine"}
        if item.keys() - (common | required | lines):
            raise ValueError("В находке есть поля вне формата сдачи.")
        for key in required | (common & item.keys()):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ValueError(f"Поле {key} должно содержать непустую строку.")
        if lines:
            first = item.get("line")
            last = item.get("endLine", first)
            if path not in line_counts:
                line_counts[path] = len(read(files[path]).splitlines())
            if (type(first) is not int or type(last) is not int
                    or not 1 <= first <= last <= min(first + 14, line_counts[path])):
                raise ValueError("Недопустимый диапазон строк находки.")


def report_markdown(findings):
    lines = ["# Отчёт статического анализа", "", f"Всего находок: **{len(findings)}**", ""]
    if not findings:
        return "\n".join(lines + ["Находок нет.", ""])
    lines += [
        "| Категория | Серьёзность | Файл | Место / зависимость | Описание | Рекомендация |",
        "|---|---|---|---|---|---|",
    ]
    for item in findings:
        if item["category"] == "SCA":
            location = "{group}:{artifact}:{version} ({advisoryId})".format(**item)
        else:
            first, last = item["line"], item.get("endLine", item["line"])
            location = f"{item['class']}, строка {first}" + (f"–{last}" if last != first else "")
        cells = (item["category"], item.get("severity", ""), item["path"], location,
                 item.get("description", ""), item.get("remediation", ""))
        lines.append("| " + " | ".join(value.replace("|", "&#124;").replace("\n", " ") for value in cells) + " |")
    return "\n".join(lines) + "\n"


def write_text(path, content):
    handle = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, delete=False)
    try:
        with handle:
            handle.write(content)
        temporary = Path(handle.name)
        temporary.replace(path)
    finally:
        Path(handle.name).unlink(missing_ok=True)


def write_reports(project, out, findings):
    check_findings(findings, project)
    out.mkdir(parents=True, exist_ok=True)
    write_text(out / "findings.json", json.dumps({"findings": findings}, ensure_ascii=False, indent=2) + "\n")
    write_text(out / "report.md", report_markdown(findings))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", nargs="?", type=Path, default=ROOT / "training-project")
    parser.add_argument("--database", type=Path, default=DATABASE)
    parser.add_argument("--out", type=Path, default=ROOT / "security-report")
    args = parser.parse_args()
    project = project_root(args.project)
    findings = analyze(project, args.database)
    write_reports(project, args.out, findings)
    print(f"Findings: {len(findings)}")


if __name__ == "__main__":
    main()

