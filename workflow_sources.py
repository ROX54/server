"""Static snapshots of explicitly allowed public GitHub training repositories."""
from contextlib import contextmanager
import http.client
from io import BytesIO
import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

DEFAULT_REPOSITORY = "https://github.com/TBagirov/training"
DEFAULT_REVISION = "fe1fcbe212669783480666b9b60147c8a8c6eef4"
REPOSITORY_NAME = r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}"
REPOSITORY_URL = re.compile(rf"https://github\.com/({REPOSITORY_NAME})/?")
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_EXPANDED = 16 * 1024 * 1024
MAX_ENTRIES = 2000
SKIP = {".git", ".gradle", "build", "workflow-data", "node_modules", "security-report", "implementation-backups"}
WINDOWS_RESERVED = getattr(ntpath, "isreserved", lambda name: PureWindowsPath(name).is_reserved())


class SourceError(ValueError):
    """A source failure whose message can be displayed in workflow history."""


def approved_source(url):
    match = REPOSITORY_URL.fullmatch(url.removesuffix(".git")) if isinstance(url, str) else None
    if not match or len(url) > 165:
        raise SourceError("Введите HTTPS-ссылку на учебный репозиторий GitHub без параметров и подкаталогов.")
    try:
        configured = json.loads(os.environ.get("CYBERGARDEN_TRAINING_REPOS", "{}"))
    except (ValueError, RecursionError):
        raise SourceError("Неверный JSON в CYBERGARDEN_TRAINING_REPOS.") from None
    if not isinstance(configured, dict) or any(
        not re.fullmatch(REPOSITORY_NAME, key) or not isinstance(value, str)
        or not re.fullmatch(r"[a-fA-F0-9]{40}", value) for key, value in configured.items()
    ):
        raise SourceError("Список CYBERGARDEN_TRAINING_REPOS должен связывать owner/repo с SHA коммита.")
    permissions = {"tbagirov/training": ("TBagirov/training", DEFAULT_REVISION)}
    permissions.update({key.lower(): (key, value) for key, value in configured.items()})
    record = permissions.get(match[1].lower())
    if record is None:
        raise SourceError("Репозиторий отсутствует в списке разрешённых учебных источников.")
    name, revision = record
    return "https://github.com/" + name, revision


def fetch_archive(url, revision):
    name = REPOSITORY_URL.fullmatch(url)[1]
    connection = http.client.HTTPSConnection("codeload.github.com", timeout=5)
    try:
        connection.request("GET", f"/{name}/zip/{revision}", headers={"User-Agent": "CyberGarden-Training"})
        with connection.getresponse() as response:
            if response.status != 200:
                raise SourceError(f"GitHub вернул HTTP {response.status} при загрузке учебного проекта.")
            data = response.read(MAX_ARCHIVE + 1)
        if len(data) > MAX_ARCHIVE:
            raise SourceError("Архив учебного проекта слишком велик.")
        return data
    except (OSError, http.client.HTTPException):
        raise SourceError("Не удалось загрузить архив с codeload.github.com.") from None
    finally:
        connection.close()


def extract_archive(data, directory):
    root = directory / "source"
    root.mkdir()
    try:
        with ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES or sum(entry.file_size for entry in entries) > MAX_EXPANDED:
                raise SourceError("В архиве слишком много файлов или превышен лимит распаковки.")
            top = set()
            written = set()
            for entry in entries:
                parts = entry.filename.removesuffix("/").split("/")
                mode = stat.S_IFMT(entry.external_attr >> 16)
                if (any(not re.fullmatch(r"[\w. -]{1,160}", part) or part in {".", ".."}
                        or part.endswith((".", " ")) or WINDOWS_RESERVED(part) for part in parts)
                        or mode not in {0, stat.S_IFREG, stat.S_IFDIR} or "\\" in entry.filename):
                    raise SourceError("Архив содержит небезопасный путь или ссылку.")
                top.add(parts[0])
                relative = parts[1:]
                if entry.is_dir() or not relative or any(part.casefold() in SKIP for part in relative):
                    continue
                if Path(relative[-1]).suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
                    continue
                key = "/".join(relative).casefold()
                if key in written:
                    raise SourceError("Архив содержит конфликтующие пути.")
                written.add(key)
                target = root.joinpath(*relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    output.write(archive.read(entry))
            if len(top) != 1:
                raise SourceError("Архив должен содержать один корневой каталог GitHub.")
    except (BadZipFile, OSError, RuntimeError, NotImplementedError) as error:
        raise SourceError("Не удалось распаковать архив учебного проекта.") from error
    return project_in(root)


def project_in(root):
    for candidate in (root / "training-project", root):
        if (candidate / "build.gradle.kts").is_file():
            return candidate
    raise SourceError("В архиве нет корня учебного Gradle-проекта.")


@contextmanager
def imported_project(url, revision):
    with TemporaryDirectory(prefix="cybergarden-source-") as directory:
        try:
            result = subprocess.run(
                [sys.executable, "-B", str(Path(__file__).resolve()), url, revision, directory],
                capture_output=True, text=True, encoding="utf-8", timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise SourceError("Загрузка учебного проекта не завершилась за отведённое время.") from None
        if result.returncode:
            raise SourceError(result.stdout.strip() or "Не удалось подготовить учебный проект.")
        yield project_in(Path(directory) / "source")


if __name__ == "__main__":
    try:
        source, commit = approved_source(sys.argv[1])
        if commit != sys.argv[2]:
            raise SourceError("Разрешённая ревизия изменилась. Запустите workflow повторно.")
        extract_archive(fetch_archive(source, commit), Path(sys.argv[3]))
    except SourceError as error:
        sys.stdout.buffer.write(str(error).encode("utf-8"))
        raise SystemExit(1) from None
