"""Regression tests for the contest pipeline and report contract."""
from collections import Counter
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

import security_dashboard
from security_workflow import (
    ROOT, SECRET_ASSIGNMENT, SECRET_FALLBACK, analyze, check_findings,
    hardcoded, in_range, project_root, read, secret_kind, write_reports,
)
from validate_results import TRUTH, evaluate, load_findings


class ContestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def put(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def test_training_project_and_report_contract(self):
        project = ROOT / "training-project"
        findings = analyze(project)
        self.assertEqual(Counter(row["category"] for row in findings),
                         {"SECRET": 5, "SAST": 5, "SCA": 5})
        write_reports(project, self.root, findings)
        self.assertEqual(load_findings(self.root / "findings.json", project), findings)
        markdown = read(self.root / "report.md")
        rows = [line for line in markdown.splitlines() if line.startswith(("| SECRET", "| SAST", "| SCA"))]
        self.assertEqual(len(rows), len(findings))
        for item, row in zip(findings, rows):
            self.assertIn("| " + item["path"] + " |", row)
            if item["category"] == "SCA":
                self.assertIn("{group}:{artifact}:{version} ({advisoryId})".format(**item), row)
            else:
                self.assertIn(f"{item['class']}, строка {item['line']}", row)

        reports = read(self.root / "findings.json") + markdown
        for item in findings:
            if item["category"] != "SECRET":
                continue
            source = read(project / item["path"]).splitlines()
            snippet = "\n".join(source[item["line"] - 1:item.get("endLine", item["line"])])
            for pattern in (SECRET_ASSIGNMENT, SECRET_FALLBACK):
                for match in pattern.finditer(snippet):
                    value = match["value"].strip("\"'")
                    if secret_kind(match["name"]) or item["class"] == "recoverable-token":
                        if hardcoded(value):
                            value = re.sub(r"^Bearer\s+", "", value, flags=re.I)
                            self.assertFalse(value in reports, "A literal from a secret finding was exported")

        result = evaluate(findings, json.loads(read(TRUTH)))
        self.assertEqual(result["overall"], {
            "tp": 15, "fp": 0, "fn": 0, "pending": 0, "precision": 1, "recall": 1, "f1": 1,
        })
        self.assertEqual((result["controlHits"], result["controlTotal"]), (0, 6))

    def test_secret_rules_on_renamed_files_and_references(self):
        sample = "synthetic-unit-test-value-83"
        self.put(".env", f"APP_API_KEY={sample}\n")
        self.put("config/service.yml", "authorization: Bearer ${SERVICE_TOKEN}\napi-key: replace-me\n")
        self.put("module/Transport.kt", """
class Transport {
    fun headers() {
        /* val testPassword = "illustrative-comment-value" */
        val fragmentA = "synthetic-"
        val fragmentB = "for-local-test"
        val unrelated = "this-is-not-sent"
        val credential = fragmentA + fragmentB
        headers.setBearerAuth(credential)
    }
}
""")
        findings = analyze(self.root)
        self.assertEqual([(f["path"], f["class"]) for f in findings],
                         [(".env", "api-key"), ("module/Transport.kt", "recoverable-token")])
        write_reports(self.root, self.root / "out", findings)
        for path in ("findings.json", "report.md"):
            output = read(self.root / "out" / path)
            self.assertFalse(sample in output)
            self.assertFalse("for-local-test" in output)

    def test_sast_on_changed_names_and_safe_controls(self):
        self.put("module/Policies.kt", """
class Policies {
    fun rules() {
        rules.requestMatchers(GET, "/health").permitAll()
        rules.requestMatchers(
            GET, "/teams/overview"
        ).permitAll()
        rules.requestMatchers("/teams/**").hasRole("OPERATOR")
    }
    fun cors() = CorsConfiguration().apply {
        addAllowedOriginPattern("*")
        setAllowCredentials(true)
    }
    fun client() {
        connection.hostnameVerifier = HostnameVerifier { host, session -> true }
    }
}
""")
        self.put("module/Endpoint.kt", """
@RestController
class Endpoint(private val store: RecordStore, private val jdbc: JdbcTemplate) {
    @GetMapping("/{record}")
    fun lookup(@PathVariable record: UUID) = store.load(record)

    @GetMapping("/search")
    fun search(@RequestParam tag: String): List<String> {
        val statement = "SELECT title FROM records WHERE tag = '$tag'"
        return jdbc.queryForList(statement, String::class.java)
    }

    @GetMapping("/safe")
    fun safe(@RequestParam tag: String) =
        jdbc.queryForList("SELECT title FROM records WHERE tag = ?", String::class.java, tag)
}
""")
        repository = """
@Repository
class RecordStore(private val jdbc: JdbcTemplate) {
    fun load(number: UUID): Record? = jdbc.query(
        "SELECT title FROM records WHERE record_id = ?",
        mapper,
        number,
    ).firstOrNull()
}
"""
        self.put("module/Store.kt", repository)
        classes = Counter(f["class"] for f in analyze(self.root))
        self.assertEqual(classes, dict.fromkeys((
            "route-authorization", "credentialed-cors", "tls-verification",
            "object-authorization", "sql-injection",
        ), 1))
        self.put("module/Store.kt", repository.replace("record_id = ?", "record_id = ? AND owner_id = ?"))
        self.assertNotIn("object-authorization", {f["class"] for f in analyze(self.root)})

    def test_gradle_resolution_deduplication_and_multiple_advisories(self):
        self.put("gradle.properties", "legacy=1.14.1\nmanifest=20230227\n")
        self.put("app/build.gradle.kts", """
val propertyVersion = providers.gradleProperty("legacy").get()
tasks { implementation("org.yaml:snakeyaml:1.10") }
dependencies {
    // implementation("org.yaml:snakeyaml:1.10")
    implementation("org.jsoup:jsoup:$propertyVersion")
    implementation("org.jsoup:jsoup:$propertyVersion")
    add(
        "implementation",
        "org.json:json:${providers.gradleProperty("manifest").get()}",
    )
    runtimeOnly("org.apache.pdfbox:pdfbox")
    implementation("org.apache.commons:commons-text:1.10")
}
""")
        self.put("app/gradle.lockfile", "org.apache.pdfbox:pdfbox:2.0.20=runtimeClasspath\n"
                 "org.apache.commons:commons-text:1.9=runtimeClasspath\n")
        rows = analyze(self.root)
        self.assertEqual({f["path"] for f in rows}, {"app/build.gradle.kts"})
        self.assertEqual(Counter(f["artifact"] for f in rows),
                         {"jsoup": 1, "json": 1, "pdfbox": 3, "commons-text": 1})
        self.assertEqual(next(f["version"] for f in rows if f["artifact"] == "commons-text"), "1.9")

    def test_numeric_ranges(self):
        bounds = {"lower": "1.9.0", "lowerInclusive": True, "upper": "2.0", "upperInclusive": False}
        self.assertTrue(in_range("1.9", bounds))
        self.assertFalse(in_range("2.0.0", bounds))
        self.assertFalse(in_range("1.9-RC1", bounds))
        self.assertTrue(in_range("20230618", {
            "lower": None, "lowerInclusive": False, "upper": "20230618", "upperInclusive": True,
        }))

    def test_validation_keeps_additional_advisory_pending(self):
        row = {"category": "SCA", "path": "build.gradle.kts", "group": "training", "artifact": "sample",
               "version": "1.0", "advisoryId": "example-advisory"}
        result = evaluate([row], {"findings": [], "controls": []})
        self.assertEqual((result["overall"]["fp"], result["overall"]["pending"]), (0, 1))
        control = dict(row, id="control")
        result = evaluate([row], {"findings": [], "controls": [control]})
        self.assertEqual((result["overall"]["fp"], result["overall"]["pending"]), (1, 0))
        self.assertEqual(result["controlHits"], 1)

    def test_report_rejects_escape_and_invalid_line_numbers(self):
        self.put("local.kt", "first\nsecond\n")
        base = {"category": "SECRET", "path": "local.kt", "class": "password", "line": 1}
        for values in ({"path": "../local.kt"}, {"path": "C:/local.kt"}, {"path": "./local.kt"},
                       {"line": True}, {"endLine": 3}, {"line": 0}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                check_findings([dict(base, **values)], self.root)

    def test_scanner_does_not_follow_links(self):
        self.put("ignored/build/Transient.kt", 'val password = "synthetic-unused-value"')
        outside = self.root.parent / (self.root.name + "-outside")
        outside.mkdir()
        self.addCleanup(outside.rmdir)
        target = outside / "Source.kt"
        self.addCleanup(target.unlink)
        target.write_text('val password = "synthetic-outside-value"', encoding="utf-8")
        link = self.root / "Linked.kt"
        try:
            os.symlink(target, link)
        except OSError as error:
            if os.name != "nt" or error.winerror != 1314:
                raise
            self.skipTest("Windows sandbox does not grant symbolic-link creation")
        self.assertEqual(analyze(project_root(self.root)), [])

    def test_dashboard_scan_and_export_over_http(self):
        with patch.object(security_dashboard, "REPORT", self.root):
            with security_dashboard.ThreadingHTTPServer(("127.0.0.1", 0), security_dashboard.Handler) as server:
                thread = Thread(target=server.serve_forever, daemon=True)
                thread.start()
                client = HTTPConnection("127.0.0.1", server.server_port, timeout=10)
                try:
                    for path in ("/", "/api/findings"):
                        client.request("GET", path)
                        response = client.getresponse()
                        self.assertEqual(response.status, 200)
                        response.read()
                    client.request("POST", "/api/scan")
                    response = client.getresponse()
                    self.assertEqual(response.status, 200)
                    data = json.loads(response.read())
                    self.assertEqual(data["validation"]["overall"]["tp"], 15)
                    self.assertEqual(len(data["findings"]), 15)
                    client.request("GET", "/reports/findings.json")
                    response = client.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read()), {"findings": data["findings"]})
                    client.request("GET", "/api/findings")
                    response = client.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read()), data)
                finally:
                    client.close()
                    server.shutdown()
                    thread.join()


if __name__ == "__main__":
    unittest.main()

