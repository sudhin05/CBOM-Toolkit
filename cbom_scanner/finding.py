"""The shared finding format that every scanner returns.

Every scanner returns a list of plain Python dictionaries built with
make_finding(), so the scanners, the CBOM writer and the HTML report can be
developed separately and still plug together.

Example:
    {"source": "code", "file": "app/auth.py", "line": 12,
     "algorithm": "RSA", "param": 2048, "name": "RSA-2048",
     "primitive": "pke", "function": "keygen",
     "evidence": "rsa.generate_private_key(...)",
     "label": "red", "quantum_safe": False,
     "reason": "Broken by Shor's algorithm on a quantum computer"}
"""

from .rules import classify


def display_name(algorithm, param=None):
    """'RSA' + 2048 -> 'RSA-2048';  'EC' + 'P-256' -> 'EC-P-256';  'MD5' -> 'MD5'."""
    if param in (None, ""):
        return algorithm
    return f"{algorithm}-{param}"


def make_finding(source, file, line, algorithm, primitive, param=None,
                 function=None, evidence="", note="", extra=None):
    """Build one finding and attach its red/yellow/green label.

    source     -- which scanner: "code", "dependency", "certificate" or "tls"
    file       -- file path (relative to the scanned folder) or host:port
    line       -- line number in the file (None when it does not apply)
    algorithm  -- canonical algorithm name, e.g. "RSA", "AES", "SHA-256"
    primitive  -- CycloneDX primitive: hash, mac, block-cipher, pke, signature,
                  key-agree, kem, kdf, ae, stream-cipher, protocol, library ...
    param      -- key size in bits (int) or curve name (str), if known
    function   -- what the code does with it: keygen, sign, encrypt, digest ...
    evidence   -- the source code or text that triggered the finding
    note       -- extra explanation shown in the report
    extra      -- dict of scanner-specific details (certificate subject, ...)
    """
    label, reason = classify(algorithm, param, primitive)
    return {
        "source": source,
        "file": file,
        "line": line,
        "algorithm": algorithm,
        "param": param,
        "name": display_name(algorithm, param),
        "primitive": primitive,
        "function": function,
        "evidence": evidence,
        "label": label,
        "quantum_safe": label == "green",
        "reason": reason,
        "note": note,
        "extra": extra or {},
    }


def readiness_score(findings):
    """Share of labelled crypto assets that are quantum-safe (green), in %.

    Dependency findings are labelled "info" (a library is not an algorithm)
    and are left out of the score. Returns None when there is nothing to score.
    """
    scored = [f for f in findings if f["label"] in ("red", "yellow", "green")]
    if not scored:
        return None
    green = sum(1 for f in scored if f["label"] == "green")
    return round(100 * green / len(scored), 1)


def summarize(findings):
    counts = {"red": 0, "yellow": 0, "green": 0, "info": 0}
    for f in findings:
        counts[f["label"]] = counts.get(f["label"], 0) + 1
    return {
        "counts": counts,
        "total_assets": counts["red"] + counts["yellow"] + counts["green"],
        "readiness_score": readiness_score(findings),
    }
