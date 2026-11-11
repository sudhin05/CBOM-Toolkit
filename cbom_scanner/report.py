"""HTML report (jinja2) and console summary."""

import os
from collections import Counter
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .finding import summarize

LABEL_ORDER = {"red": 0, "yellow": 1, "green": 2, "info": 3}


def sort_findings(findings):
    return sorted(findings, key=lambda f: (LABEL_ORDER.get(f["label"], 9), f["source"],
                                           f["file"], f["line"] or 0))


def write_html(findings, path, project, tls_summaries=None):
    env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")),
        autoescape=select_autoescape(["html", "j2"]))
    html = env.get_template("report.html.j2").render(
        project=project,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"),
        version=__version__,
        summary=summarize(findings),
        by_source=dict(Counter(f["source"] for f in findings)),
        findings=sort_findings(findings),
        tls=tls_summaries or [],
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


COLORS = {"red": "\033[31m", "yellow": "\033[33m", "green": "\033[32m", "info": "\033[90m"}
RESET = "\033[0m"


def print_console(findings, use_color=True):
    for f in sort_findings(findings):
        where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        tag = f"{f['label'].upper():6}"
        if use_color:
            tag = COLORS[f["label"]] + tag + RESET
        print(f"  {tag} {f['name']:<22} {f['source']:<11} {where}")
    s = summarize(findings)
    c = s["counts"]
    print()
    print(f"  {s['total_assets']} crypto assets: {c['red']} red, {c['yellow']} yellow, "
          f"{c['green']} green  (+{c['info']} crypto libraries)")
    if s["readiness_score"] is not None:
        print(f"  Quantum readiness score: {s['readiness_score']}%")
