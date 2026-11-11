"""Results table 2: scan 5 real open-source Python projects.

Downloads each project at a fixed version (git clone --depth 1 --branch <tag>),
scans it, and writes:
  results/real_projects.md / .csv    one row per project
  results/spot_check.csv             20 random findings (fixed seed) with an
                                     empty "correct?" column for you to fill
                                     in by opening each file and line by hand
  results/real/<project>/            the CBOM, report and findings per project

Usage:  python evaluation/real_projects.py
"""

import csv
import json
import os
import random
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from cbom_scanner.cbom_writer import build_cbom, validate_cbom, write_cbom  # noqa: E402
from cbom_scanner.finding import summarize  # noqa: E402
from cbom_scanner.report import write_html  # noqa: E402
from scan import scan  # noqa: E402

# name, git URL, tag, why it was chosen
PROJECTS = [
    ("itsdangerous", "https://github.com/pallets/itsdangerous", "2.2.0",
     "Signed tokens used by Flask sessions (HMAC)"),
    ("pyjwt", "https://github.com/jpadilla/pyjwt", "2.9.0",
     "JSON Web Token library (HMAC, RSA, ECDSA)"),
    ("python-rsa", "https://github.com/sybrenstuvel/python-rsa", "version-4.9",
     "Pure-Python RSA implementation"),
    ("fabric", "https://github.com/fabric/fabric", "3.2.2",
     "SSH deployment tool built on paramiko"),
    ("flask-security", "https://github.com/pallets-eco/flask-security", "5.5.2",
     "Flask login/authentication extension"),
]

CLONES = os.path.join(HERE, "real-projects")
OUT = os.path.join(HERE, "results")


def clone(name, url, tag):
    dest = os.path.join(CLONES, name)
    if not os.path.isdir(dest):
        os.makedirs(CLONES, exist_ok=True)
        subprocess.run(["git", "clone", "--quiet", "--depth", "1", "--branch", tag, url, dest],
                       check=True)
    commit = subprocess.run(["git", "-C", dest, "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    return dest, commit


def is_test(path):
    """Findings in test suites are reported separately from the main code."""
    parts = path.lower().split("/")
    return any(p in ("tests", "test", "testing", "integration") for p in parts[:-1])         or parts[-1].startswith("test_") or parts[-1].endswith("_test.py")         or parts[-1] == "conftest.py"


def count_py(path):
    return sum(1 for _, _, files in os.walk(path) for f in files if f.endswith(".py"))


def main():
    rows, all_findings = [], []
    for name, url, tag, why in PROJECTS:
        print(f"== {name} {tag}")
        try:
            path, commit = clone(name, url, tag)
        except subprocess.CalledProcessError as exc:
            print(f"   clone failed: {exc}")
            continue
        findings, _ = scan(path)
        for f in findings:
            f["project"] = name
        all_findings += findings

        out = os.path.join(OUT, "real", name)
        os.makedirs(out, exist_ok=True)
        bom = build_cbom(findings, name)
        write_cbom(bom, os.path.join(out, "cbom.json"))
        write_html(findings, os.path.join(out, "report.html"), f"{name} {tag}")
        with open(os.path.join(out, "findings.json"), "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        valid, _ = validate_cbom(bom)

        main_code = [f for f in findings if not is_test(f["file"])]
        s = summarize(main_code)
        algos = Counter(f["name"] for f in main_code if f["label"] != "info")
        rows.append({
            "project": name, "version": tag, "commit": commit, "about": why,
            "py_files": count_py(path),
            "findings": len(main_code),
            "test_findings": len(findings) - len(main_code),
            "red": s["counts"]["red"], "yellow": s["counts"]["yellow"],
            "green": s["counts"]["green"], "libraries": s["counts"]["info"],
            "readiness_%": s["readiness_score"],
            "top_algorithms": ", ".join(f"{a} ({n})" for a, n in algos.most_common(5)),
            "cbom_valid": valid,
        })
        print(f"   {len(main_code)} findings in main code (+{len(findings) - len(main_code)} "
              f"in tests), readiness {s['readiness_score']}%")

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "real_projects.csv"), "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    lines = ["# Results table 2: real open-source projects", "",
             "Main code only; findings inside test suites are counted separately.", "",
             "| Project | Version | .py files | Findings | (in tests) | Red | Yellow | Green | "
             "Libraries | Readiness | Most common algorithms |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['project']} | {r['version']} | {r['py_files']} | {r['findings']} | "
                     f"{r['test_findings']} | "
                     f"{r['red']} | {r['yellow']} | {r['green']} | {r['libraries']} | "
                     f"{r['readiness_%']}% | {r['top_algorithms']} |")
    text = "\n".join(lines) + "\n"
    with open(os.path.join(OUT, "real_projects.md"), "w", encoding="utf-8") as fh:
        fh.write(text)
    print()
    print(text)

    # 20 random findings for the manual spot check (seed fixed => same sample every run)
    pool = [f for f in all_findings if f["source"] == "code" and not is_test(f["file"])]
    sample = random.Random(2026).sample(pool, min(20, len(pool)))
    with open(os.path.join(OUT, "spot_check.csv"), "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["project", "file", "line", "tool_says", "label", "evidence",
                         "correct? (yes/no)", "comment"])
        for f in sample:
            writer.writerow([f["project"], f["file"], f["line"], f["name"], f["label"],
                             f["evidence"], "", ""])
    print(f"Spot-check sheet: {os.path.join(OUT, 'spot_check.csv')}")


if __name__ == "__main__":
    main()
