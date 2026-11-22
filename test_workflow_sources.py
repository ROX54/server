"""Check bounded source import and detection on a reformatted local fixture."""
from collections import Counter
from io import BytesIO
import json
from pathlib import Path
import shutil
import stat
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile, ZipInfo

from security_workflow import ROOT, analyze, check_findings, report_markdown
from workflow_engine import subprocess_scanner
from workflow_sources import DEFAULT_REPOSITORY, SourceError, approved_source, extract_archive


def zipped(*files):
    buffer = BytesIO()
    with ZipFile(buffer, "w") as zipfile:
        for path, content in files:
            zipfile.writestr(path, content)
    return buffer.getvalue()


class SourcesTest(unittest.TestCase):
    def test_url_requires_exact_allowlisted_repository(self):
        self.assertEqual(approved_source(DEFAULT_REPOSITORY + ".git")[0], DEFAULT_REPOSITORY)
        for url in ("https://example.com/TBagirov/training", "http://github.com/TBagirov/training",
                    "https://github.com/TBagirov/training/tree/main", "https://github.com/other/training",
                    "https://github.com/TBagirov/training?ref=main", "https://github.com@localhost/a/b"):
            with self.subTest(url=url), self.assertRaises(SourceError):
                approved_source(url)

    def test_archive_rejects_unsafe_names_and_links(self):
        symbolic = ZipInfo("snapshot/sample")
        symbolic.create_system = 3
        symbolic.external_attr = (stat.S_IFLNK | 0o777) << 16
        for path in ("snapshot/../escaped.txt", "/absolute.txt", "snapshot/C:/x",
                     "snapshot/nul.txt", "snapshot/a\\b", symbolic):
            with self.subTest(path=path), TemporaryDirectory() as tmp, self.assertRaises(SourceError):
                extract_archive(zipped((path, "synthetic")), Path(tmp))

    def test_extracted_project_is_scanned_by_existing_worker(self):
        text = 'val demoPassword = "SyntheticFixture987!"\n'
        archive = zipped(("snapshot/training-project/build.gradle.kts", ""),
                         ("snapshot/training-project/example.kt", text),
                         ("snapshot/training-project/.env", "APP_PASSWORD=SyntheticFixture321!\n"))
        with TemporaryDirectory() as tmp:
            project = extract_archive(archive, Path(tmp))
            findings = subprocess_scanner("secret", 5, project)
            self.assertEqual({(row["category"], row["path"]) for row in findings},
                             {("SECRET", "example.kt"), ("SECRET", ".env")})
            exported = json.dumps(findings) + report_markdown(findings)
            self.assertNotIn("SyntheticFixture987!", exported)
            self.assertNotIn("SyntheticFixture321!", exported)

    def test_scanners_find_same_categories_after_moves_and_reformatting(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp) / "relocated"
            shutil.copytree(ROOT / "training-project", project)
            for index, path in enumerate(sorted(project.rglob("*.kt"))):
                # Kotlin class names are independent of file names. Change positions without changing semantics.
                text = path.read_text(encoding="utf-8")
                changed = "\n" * (index + 4) + "\n".join("  " + line.rstrip() for line in text.splitlines()) + "\n"
                new_path = project / "relocated-sources" / f"sample_{index}.kt"
                new_path.parent.mkdir(exist_ok=True)
                path.rename(new_path)
                new_path.write_text(changed, encoding="utf-8")
            findings = analyze(project)
            check_findings(findings, project)
            self.assertEqual(Counter(row["category"] for row in findings), {"SECRET": 5, "SAST": 5, "SCA": 5})
            self.assertTrue(all(row["path"].startswith("relocated-sources/") for row in findings
                                if row["category"] == "SAST"))
            rows = [line for line in report_markdown(findings).splitlines() if line.startswith("| S")]
            self.assertEqual(len(rows), len(findings))


if __name__ == "__main__":
    unittest.main()
