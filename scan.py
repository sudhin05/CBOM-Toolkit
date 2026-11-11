"""One command that runs all four scanners and writes the CBOM and report.

Examples:
    python scan.py ./sample-project
    python scan.py ./sample-project --url example.com
    python scan.py --url example.com --url localhost:8443
    python scan.py ./myproj --out results --no-color
"""

import argparse
import json
import os
import sys

from cbom_scanner import cert_scanner, code_scanner, dependency_scanner, tls_scanner
from cbom_scanner.cbom_writer import build_cbom, validate_cbom, write_cbom
from cbom_scanner.report import print_console, write_html


def scan(path=None, urls=(), skip=()):
    """Run the scanners and return (findings, tls_summaries)."""
    findings, tls_summaries = [], []
    if path:
        if "code" not in skip:
            findings += code_scanner.scan_directory(path)
        if "deps" not in skip:
            findings += dependency_scanner.scan_directory(path)
        if "certs" not in skip:
            findings += cert_scanner.scan_directory(path)
    if urls:
        tls_findings, tls_summaries = tls_scanner.scan_targets(urls)
        findings += tls_findings
    return findings, tls_summaries


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build a quantum-readiness CBOM for a "
                                                 "Python project and/or websites.")
    parser.add_argument("path", nargs="?", help="project folder (or single file) to scan")
    parser.add_argument("--url", action="append", default=[],
                        help="website to check, e.g. example.com or host:port (repeatable)")
    parser.add_argument("--out", default="cbom-output", help="output folder (default: cbom-output)")
    parser.add_argument("--name", help="project name used in the CBOM and report")
    parser.add_argument("--skip", action="append", default=[], choices=["code", "deps", "certs"],
                        help="skip a scanner (repeatable)")
    parser.add_argument("--no-color", action="store_true", help="plain console output")
    args = parser.parse_args(argv)

    if not args.path and not args.url:
        parser.error("give a project folder, a --url, or both")
    if args.path and not os.path.exists(args.path):
        parser.error(f"path not found: {args.path}")

    name = args.name or (os.path.basename(os.path.abspath(args.path)) if args.path
                         else args.url[0])
    print(f"Scanning {name} ...")
    findings, tls_summaries = scan(args.path, args.url, set(args.skip))

    os.makedirs(args.out, exist_ok=True)
    bom = build_cbom(findings, name, tls_summaries)
    cbom_path = os.path.join(args.out, "cbom.json")
    report_path = os.path.join(args.out, "report.html")
    findings_path = os.path.join(args.out, "findings.json")
    write_cbom(bom, cbom_path)
    write_html(findings, report_path, name, tls_summaries)
    with open(findings_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)

    print_console(findings, use_color=not args.no_color and sys.stdout.isatty())
    ok, error = validate_cbom(bom)
    status = {True: "valid CycloneDX 1.6", False: "SCHEMA ERRORS", None: "not validated"}[ok]
    print(f"\n  CBOM:     {cbom_path}  ({status})")
    if ok is False:
        print(f"            {error[:500]}")
    print(f"  Report:   {report_path}")
    print(f"  Findings: {findings_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
