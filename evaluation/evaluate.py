"""Results table 1: run the scanner on the 30 known-answer test files.

The correct answer for each line is written by hand in the test file itself
as a comment, e.g.   hashlib.md5(data)  # expect: MD5
(the scanner cannot see comments, so it cannot cheat). Certificates and keys
cannot hold comments, so their answers are in expected_binary.json.

A finding counts as
  correct     right algorithm (and key size / curve) on the right line
  missed      an expected item the tool did not report
  partial     tool reported the right line but could not tell the algorithm
              (e.g. "Unknown") or got the size wrong; counted as missed
  false alarm tool reported something that is not in the answer key

precision = correct / (correct + false alarms)   "how often the tool is right"
recall    = correct / (correct + missed)         "how much of the crypto it finds"

Usage:  python evaluation/evaluate.py
Writes: evaluation/results/testfile_results.csv and .md
"""

import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scan import scan  # noqa: E402

CASES = os.path.join(HERE, "testcases")
OUT = os.path.join(HERE, "results")
EXPECT = re.compile(r"#\s*expect:\s*(.+)$")


def case_of(path):
    """'tc29_requirements/requirements.txt' -> 'tc29_requirements'"""
    first = path.split("/")[0]
    return os.path.splitext(first)[0]


def load_expected():
    expected = {}
    for dirpath, _, filenames in os.walk(CASES):
        for name in filenames:
            if not name.endswith((".py", ".txt", ".toml")):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, CASES).replace("\\", "/")
            items = expected.setdefault(case_of(rel), set())
            with open(path, encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    match = EXPECT.search(line)
                    if match:
                        for alg in match.group(1).split(","):
                            items.add((rel, alg.strip(), lineno))
    with open(os.path.join(CASES, "expected_binary.json"), encoding="utf-8") as fh:
        for rel, pairs in json.load(fh).items():
            if rel.startswith("_"):
                continue
            items = expected.setdefault(case_of(rel), set())
            for alg, line in pairs:
                items.add((rel, alg, line))
    return expected


def base(name):
    """'RSA-2048' -> 'RSA', 'HMAC-SHA-1' -> 'HMAC', 'EC-P-256' -> 'EC'"""
    return name.split("-")[0]


def evaluate():
    expected = load_expected()
    findings, _ = scan(CASES)
    found = {}
    for f in findings:
        found.setdefault(case_of(f["file"]), set()).add((f["file"], f["name"], f["line"]))

    rows = []
    for case in sorted(set(expected) | set(found)):
        exp = expected.get(case, set())
        got = found.get(case, set())
        correct = exp & got
        missed = exp - got
        extra = got - exp
        partial = set()
        for item in list(extra):
            file, name, line = item
            for e in missed:
                if e[0] == file and e[2] == line and (name == "Unknown" or base(name) == base(e[1])):
                    partial.add(item)
                    break
        false_alarms = extra - partial
        rows.append({
            "test_case": case,
            "tricky": "yes" if "tricky" in case else "",
            "expected": "; ".join(f"{n}@{l}" for _, n, l in sorted(exp, key=lambda x: (x[2], x[1]))),
            "correct": len(correct),
            "missed": len(missed),
            "partial": len(partial),
            "false_alarms": len(false_alarms),
            "missed_items": "; ".join(f"{n}@{l}" for _, n, l in sorted(missed, key=lambda x: x[2])),
            "false_alarm_items": "; ".join(f"{n}@{l}" for _, n, l in sorted(false_alarms, key=lambda x: x[2] or 0)),
            "result": "PASS" if not missed and not false_alarms else "FAIL",
        })
    return rows


def metrics(rows):
    tp = sum(r["correct"] for r in rows)
    fn = sum(r["missed"] for r in rows)
    fp = sum(r["false_alarms"] for r in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"files": len(rows), "expected": tp + fn, "correct": tp, "missed": fn,
            "false_alarms": fp, "precision": precision, "recall": recall, "f1": f1}


def main():
    rows = evaluate()
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "testfile_results.csv"), "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    groups = {
        "Standard cases": [r for r in rows if not r["tricky"]],
        "Tricky cases": [r for r in rows if r["tricky"]],
        "All 30 files": rows,
    }
    lines = ["# Results table 1: known-answer test files", "",
             "| Test file | Expected | Correct | Missed | Partial | False alarms | Result |",
             "|---|---|---|---|---|---|---|"]
    for r in rows:
        exp = r["expected"].replace(";", ",") or "(nothing)"
        lines.append(f"| {r['test_case']} | {exp} | {r['correct']} | {r['missed']} | "
                     f"{r['partial']} | {r['false_alarms']} | {r['result']} |")
    lines += ["", "| Group | Files | Expected items | Correct | Missed | False alarms | "
              "Precision | Recall | F1 |", "|---|---|---|---|---|---|---|---|---|"]
    for name, group in groups.items():
        m = metrics(group)
        lines.append(f"| {name} | {m['files']} | {m['expected']} | {m['correct']} | {m['missed']} | "
                     f"{m['false_alarms']} | {m['precision']:.1%} | {m['recall']:.1%} | {m['f1']:.1%} |")
    misses = [r for r in rows if r["missed_items"] or r["false_alarm_items"]]
    if misses:
        lines += ["", "## What the tool got wrong", ""]
        for r in misses:
            if r["missed_items"]:
                lines.append(f"- **{r['test_case']}** missed: {r['missed_items']}")
            if r["false_alarm_items"]:
                lines.append(f"- **{r['test_case']}** false alarm: {r['false_alarm_items']}")
    text = "\n".join(lines) + "\n"
    with open(os.path.join(OUT, "testfile_results.md"), "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)


if __name__ == "__main__":
    main()
