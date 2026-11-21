#!/usr/bin/env python3
"""Evaluate an existing submission against the training benchmark."""
import argparse
import json
from pathlib import Path

from security_workflow import ROOT, check_findings, project_root, read, write_text

TRUTH = ROOT / "ground-truth" / "training-findings.json"
CATEGORIES = ("SECRET", "SAST", "SCA")


def same_dependency(actual, expected):
    ids = expected.get("advisoryIds") or [expected.get("advisoryId")]
    return all(actual.get(key) == expected.get(key) for key in ("group", "artifact", "version")) and (
        actual.get("advisoryId") in ids
    )


def overlaps(actual, expected):
    return (
        actual["path"] == expected["path"]
        and actual["line"] <= expected.get("endLine", expected["line"])
        and expected["line"] <= actual.get("endLine", actual["line"])
    )


def match(actual, expected, control=False):
    if actual["category"] != expected["category"]:
        return False
    if actual["category"] == "SCA":
        return actual["path"] == expected["path"] and same_dependency(actual, expected)
    classes = {expected["class"]}
    if control:
        classes.update(expected.get("classAliases", []))
    locations = [expected, *expected.get("alternateLocations", [])]
    if actual["class"] not in classes:
        return False
    if control:
        return any(overlaps(actual, location) for location in locations)
    return any(actual["path"] == location["path"] and actual["line"] == location["line"]
               for location in locations)


def metrics(tp, fp, fn, pending):
    return {
        "tp": tp, "fp": fp, "fn": fn, "pending": pending,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else None,
    }


def evaluate(findings, truth):
    remaining = set(range(len(findings)))
    missed = []
    matched = []
    for expected in truth["findings"]:
        hit = next((index for index, actual in enumerate(findings)
                    if index in remaining and match(actual, expected)), None)
        if hit is None:
            missed.append(expected)
        else:
            matched.append(expected)
            remaining.remove(hit)

    false_positives = []
    pending = []
    flagged_controls = set()
    for index in sorted(remaining):
        actual = findings[index]
        controls = [c for c in truth["controls"] if match(actual, c, control=True)]
        flagged_controls.update(c["id"] for c in controls)
        if actual["category"] == "SCA" and not controls:
            if not any(match(actual, expected) for expected in matched):
                pending.append(actual)
                continue
        false_positives.append(actual)

    def category_metrics(category):
        return metrics(*(sum(item["category"] == category for item in items)
                         for items in (matched, false_positives, missed, pending)))

    return {
        "overall": metrics(len(matched), len(false_positives), len(missed), len(pending)),
        "categories": {category: category_metrics(category) for category in CATEGORIES},
        "controlHits": len(flagged_controls),
        "controlTotal": len(truth["controls"]),
        "controlIds": sorted(flagged_controls),
        "missedIds": [item["id"] for item in missed],
        "pending": pending,
    }


def load_findings(path, project):
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.keys() != {"findings"}:
        raise ValueError("Корневой объект должен содержать только массив findings.")
    check_findings(data["findings"], project)
    return [dict(item, path=item["path"].replace("\\", "/")) for item in data["findings"]]


def validation_markdown(result):
    rows = [
        "# Проверка результатов на учебном эталоне", "",
        "| Категория | TP | FP | FN | SCA на проверке | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for label, score in [("Все категории", result["overall"]), *result["categories"].items()]:
        cells = [str(score[key]) for key in ("tp", "fp", "fn", "pending")]
        cells.extend(f"{score[key]:.2%}" if score[key] is not None else "—"
                     for key in ("precision", "recall", "f1"))
        rows.append("| " + " | ".join([label, *cells]) + " |")
    rows.extend([
        "", f"Контрольные примеры со срабатываниями: **{result['controlHits']}/{result['controlTotal']}**.",
        "",
        "Сверка использует отдельный эталон и известные контрольные примеры. "
        "Дополнительные advisory SCA без совпадения с контролем требуют отдельной проверки. "
        "До проверки они исключены из FP, Precision и F1.",
    ])
    if result["missedIds"]:
        rows.extend(["", "Пропущены: " + ", ".join(result["missedIds"]) + "."])
    if result["controlIds"]:
        rows.extend(["", "Сработали контроли: " + ", ".join(result["controlIds"]) + "."])
    if result["pending"]:
        rows.extend(["", "Дополнительные advisory для проверки:", ""])
        rows.extend(
            "- {group}:{artifact}:{version} ({advisoryId})".format(**item)
            for item in result["pending"]
        )
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, default=ROOT / "security-report" / "findings.json")
    parser.add_argument("--project", type=Path, default=ROOT / "training-project")
    parser.add_argument("--truth", type=Path, default=TRUTH)
    parser.add_argument("--out", type=Path, default=ROOT / "security-report" / "validation.md")
    args = parser.parse_args()
    findings = load_findings(args.findings, project_root(args.project))
    result = evaluate(findings, json.loads(read(args.truth)))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_text(args.out, validation_markdown(result))
    score = result["overall"]
    print(f"TP={score['tp']} FP={score['fp']} FN={score['fn']} pending={score['pending']}")


if __name__ == "__main__":
    main()

