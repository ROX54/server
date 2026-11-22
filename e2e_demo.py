"""Run the demonstration in a clean headless Edge profile using Playwright."""
import argparse
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright

import security_dashboard as dashboard
from test_workflow_integrations import DemoReceiver, TestProvider, provider_env, receiver_env, server
from workflow_engine import WorkflowRuntime
from workflow_graph import WorkflowStore


def demo(browser, base, receiver):
    with browser.new_context(accept_downloads=True, viewport={"width": 1536, "height": 1000}) as context:
        page = context.new_page()
        page.set_default_timeout(10000)
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(base)
        expect(page.locator("#pageTitle")).to_have_text("Workflow Builder")
        page.locator("#wf-template").select_option(label="Full Security Audit")
        cards = page.locator(".wf-node")
        expect(cards).to_have_count(8)
        viewport = page.locator("#wf-viewport")
        page.locator('#wf-library [data-type="report"]').drag_to(viewport, target_position={"x": 28, "y": 380})
        expect(cards).to_have_count(9)
        extra = page.locator('.wf-node[data-type="report"]:not([data-node="report"])')
        extra_id = extra.get_attribute("data-node")
        page.locator('[data-node="condition"] [data-port="false"]').click()
        extra.locator('[data-side="in"]').click()
        expect(page.locator("#wf-count")).to_contain_text("Связи: 8")
        page.locator('[data-node="report"] .wf-node-head').click()
        page.locator('[data-param="title"]').fill("Demo validated in Edge")
        page.locator("#wf-zoom-out").click()
        expect(page.locator("#wf-zoom-reset")).to_have_text("90%")
        page.locator("#wf-zoom-reset").click()
        page.locator("#wf-save").click()
        expect(page.locator("#wf-run")).to_be_enabled()
        page.reload()
        expect(cards).to_have_count(9)
        expect(page.locator("#wf-count")).to_contain_text("Связи: 8")
        page.locator('[data-node="report"] .wf-node-head').click()
        expect(page.locator('[data-param="title"]')).to_have_value("Demo validated in Edge")
        page.locator("#wf-run").click()
        expect(page.locator("#wf-run-status")).to_contain_text("Завершено", timeout=20000)
        expect(page.locator('[data-node="condition"] .wf-run-node')).to_contain_text("True")
        expect(page.locator(f'[data-node="{extra_id}"] .wf-run-node')).to_contain_text("Пропущено")
        page.locator('[data-node="report"] .wf-node-head').click()
        expect(page.locator("#wf-node-result")).to_contain_text("SECRET 5")
        page.locator('[data-view="history"]').click()
        expect(page.locator("#wf-history-rows")).to_contain_text("Full Security Audit")
        page.locator("#wf-history-rows").get_by_role("button", name="Открыть запуск", exact=False).first.click()
        details = page.locator("#wf-history-detail")
        expect(details).to_contain_text("integration-test-double")
        expect(details).to_contain_text("HTTP 200")
        details.get_by_text("Находки запуска (15)", exact=True).click()
        expect(details.get_by_text("SECRET ·", exact=False).first).to_be_visible()
        for label in ("JSON", "Markdown"):
            with page.expect_download() as download:
                details.get_by_role("link", name=f"Скачать {label}").click()
            data = Path(download.value.path()).read_text(encoding="utf-8")
            if label == "JSON":
                assert len(json.loads(data)["findings"]) == 15
            else:
                assert data.count("\n| S") == 15
        assert len(receiver.received) == 1, "The webhook receiver did not confirm exactly one delivery"
        assert not errors, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", default="msedge")
    args = parser.parse_args()
    with TemporaryDirectory() as temp, server(TestProvider) as provider, server(DemoReceiver) as receiver:
        directory = Path(temp)
        workflows = WorkflowStore(directory)
        runtime = WorkflowRuntime(workflows, directory / "runs.sqlite3")
        configuration = {**provider_env(provider.server_port), **receiver_env(receiver.server_port)}
        with (patch.dict(os.environ, configuration), patch.object(dashboard, "WORKFLOWS", workflows),
              server(dashboard.Handler) as app, runtime.running(), sync_playwright() as playwright):
            app.workflow_runtime = runtime
            with playwright.chromium.launch(channel=args.channel, headless=True, timeout=15000) as browser:
                demo(browser, f"http://127.0.0.1:{app.server_port}", receiver)
                print("Browser demo passed:", browser.version, "(AI: local HTTP test provider)")


if __name__ == "__main__":
    main()
