"""Results table 3: TLS checker vs. sslyze on a local test server and public sites.

Starts the local Python TLS test server (TLS 1.2 only, RSA-2048) on port 8444,
then runs our TLS checker and sslyze on every target and compares:
  * which TLS versions the server accepts
  * the certificate's key (e.g. RSA-2048)
  * the certificate's signature algorithm
  * the key-exchange group (ours = negotiated; sslyze = list of supported groups)

Usage:  python evaluation/tls_checks.py [extra targets ...]
        (default targets: localhost:8444, example.com, wikipedia.org)
Writes: evaluation/results/tls_checks.md / .csv
If sslyze is not installed, only our results are written; compare them by
hand with https://www.ssllabs.com/ssltest/ instead.
"""

import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, os.path.join(HERE, "tls-testserver"))

from cbom_scanner.cert_scanner import describe_key, describe_signature  # noqa: E402
from cbom_scanner.finding import display_name  # noqa: E402
from cbom_scanner.tls_scanner import parse_target, scan_target  # noqa: E402

OUT = os.path.join(HERE, "results")
DEFAULT_TARGETS = ["localhost:8444", "example.com", "wikipedia.org"]


def ours(target):
    findings, summary = scan_target(target)
    if summary.get("error"):
        return {"error": summary["error"]}
    key = next(f for f in findings if f["function"] == "certificate-key")
    sig = next(f for f in findings if f["function"] == "certificate-signature")
    kex = next(f for f in findings if f["function"] == "keyexchange")
    return {"versions": summary["versions"], "cert_key": key["name"],
            "cert_sig": f"{sig['name']} ({sig['note'].replace('Signature hash: ', '')})",
            "group": kex["name"], "labels": [f["label"] for f in findings]}


def sslyze_result(target):
    try:
        from sslyze import (ScanCommand, ScanCommandAttemptStatusEnum, Scanner,
                            ServerNetworkLocation, ServerScanRequest, ServerScanStatusEnum)
    except ImportError:
        return None
    host, port = parse_target(target)
    commands = {ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO, ScanCommand.ELLIPTIC_CURVES}
    scanner = Scanner()
    scanner.queue_scans([ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=host, port=port),
        scan_commands=commands)])
    for res in scanner.get_results():
        if res.scan_status != ServerScanStatusEnum.COMPLETED:
            return {"error": str(res.connectivity_error_trace or res.scan_status)}
        r = res.scan_result
        versions = []
        for name, attr in [("TLS 1.0", "tls_1_0_cipher_suites"), ("TLS 1.1", "tls_1_1_cipher_suites"),
                           ("TLS 1.2", "tls_1_2_cipher_suites"), ("TLS 1.3", "tls_1_3_cipher_suites")]:
            attempt = getattr(r, attr)
            if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and \
                    attempt.result.accepted_cipher_suites:
                versions.append(name)
        out = {"versions": versions}
        if r.certificate_info.status == ScanCommandAttemptStatusEnum.COMPLETED:
            leaf = r.certificate_info.result.certificate_deployments[0].received_certificate_chain[0]
            alg, param, _ = describe_key(leaf.public_key())
            sig_alg, sig_hash, _ = describe_signature(leaf)
            out["cert_key"] = display_name(alg, param)
            out["cert_sig"] = f"{sig_alg} ({sig_hash})"
        if r.elliptic_curves.status == ScanCommandAttemptStatusEnum.COMPLETED and \
                r.elliptic_curves.result.supported_curves:
            out["groups"] = [c.name for c in r.elliptic_curves.result.supported_curves]
        return out
    return None


def main():
    from python_server import start_in_background
    start_in_background(8444)
    targets = DEFAULT_TARGETS + sys.argv[1:]

    rows = []
    for target in targets:
        print(f"== {target}")
        a = ours(target)
        b = sslyze_result(target)
        if "error" in a:
            rows.append({"target": target, "check": "connect", "ours": a["error"],
                         "sslyze": "", "agree": ""})
            continue
        b = b or {}
        groups = b.get("groups")
        group_ok = "" if groups is None else \
            ("yes" if a["group"].replace("ECDHE-", "").lower() in
             [g.lower().replace("secp256r1", "p-256").replace("secp384r1", "p-384")
              .replace("prime256v1", "p-256") for g in groups] else "check")
        checks = [
            ("TLS versions accepted", ", ".join(a["versions"]), ", ".join(b.get("versions", [])),
             "" if not b else ("yes" if a["versions"] == b.get("versions") else "NO")),
            ("Certificate key", a["cert_key"], b.get("cert_key", ""),
             "" if not b else ("yes" if a["cert_key"] == b.get("cert_key") else "NO")),
            ("Certificate signature", a["cert_sig"], b.get("cert_sig", ""),
             "" if not b else ("yes" if a["cert_sig"] == b.get("cert_sig") else "NO")),
            ("Key exchange group", a["group"],
             "supported: " + ", ".join(groups) if groups else "", group_ok),
        ]
        for check, x, y, agree in checks:
            rows.append({"target": target, "check": check, "ours": x, "sslyze": y, "agree": agree})
            print(f"   {check:<24} ours: {x:<32} sslyze: {y[:50]:<50} {agree}")

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "tls_checks.csv"), "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["target", "check", "ours", "sslyze", "agree"])
        writer.writeheader()
        writer.writerows(rows)
    lines = ["# Results table 3: TLS checks (our checker vs. sslyze)", "",
             "| Target | Check | Our TLS checker | sslyze | Agree |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['target']} | {r['check']} | {r['ours']} | {r['sslyze']} | {r['agree']} |")
    with open(os.path.join(OUT, "tls_checks.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"\nWrote {os.path.join(OUT, 'tls_checks.md')}")


if __name__ == "__main__":
    main()
