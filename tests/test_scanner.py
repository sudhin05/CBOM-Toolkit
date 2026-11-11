"""Unit tests. Run with:  python -m pytest -q"""

import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cbom_scanner import cert_scanner, dependency_scanner  # noqa: E402
from cbom_scanner.cbom_writer import build_cbom, validate_cbom  # noqa: E402
from cbom_scanner.code_scanner import FileScanner  # noqa: E402
from cbom_scanner.finding import readiness_score  # noqa: E402
from cbom_scanner.rules import classify  # noqa: E402
from cbom_scanner.tls_scanner import describe_cipher, parse_target  # noqa: E402
from scan import scan  # noqa: E402

CASES = os.path.join(ROOT, "evaluation", "testcases")


def scan_code(source):
    return [(f["name"], f["line"]) for f in FileScanner(source, "x.py").scan(ast.parse(source))]


# ---- labelling rules ----------------------------------------------------------
def test_labels_follow_the_plan():
    assert classify("RSA", 2048)[0] == "red"
    assert classify("ECDSA", "P-256")[0] == "red"
    assert classify("Ed25519")[0] == "red"
    assert classify("MD5")[0] == "yellow"
    assert classify("SHA-1")[0] == "yellow"
    assert classify("AES", 128)[0] == "yellow"
    assert classify("AES", 256)[0] == "green"
    assert classify("SHA-256")[0] == "green"
    assert classify("ML-KEM", 768)[0] == "green"
    assert classify("ML-DSA", 65)[0] == "green"
    assert classify("HMAC-SHA-256")[0] == "green"
    assert classify("HMAC-MD5")[0] == "yellow"
    assert classify("cryptography", None, "library")[0] == "info"


def test_readiness_score_ignores_libraries():
    findings = [{"label": "green"}, {"label": "red"}, {"label": "info"}, {"label": "green"},
                {"label": "yellow"}]
    assert readiness_score(findings) == 50.0
    assert readiness_score([{"label": "info"}]) is None


# ---- code scanner -----------------------------------------------------------
def test_import_aliases():
    src = "import hashlib as h\nfrom hashlib import md5 as m\nh.sha1()\nm()\n"
    assert scan_code(src) == [("SHA-1", 3), ("MD5", 4)]


def test_comments_and_strings_are_ignored():
    assert scan_code("import hashlib\n# hashlib.md5()\nx = 'hashlib.md5()'\n") == []


def test_local_object_is_not_a_module():
    assert scan_code("rsa = Thing()\nrsa.newkeys(2048)\n") == []


def test_key_size_from_variable():
    src = ("import os\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
           "k = os.urandom(16)\nAESGCM(k)\n")
    assert scan_code(src) == [("AES-128", 4)]


def test_hmac_consumes_its_hash():
    src = ("from cryptography.hazmat.primitives import hashes, hmac\n"
           "hmac.HMAC(b'k', hashes.SHA256())\n")
    assert scan_code(src) == [("HMAC-SHA-256", 2)]


def test_runtime_name_is_reported_as_unknown():
    src = "import hashlib\nn = 'sha' + '1'\nhashlib.new(n)\n"
    assert scan_code(src) == [("Unknown", 3)]


# ---- certificates, dependencies, TLS helpers -----------------------------------
def test_certificate_key_and_signature():
    names = [f["name"] for f in cert_scanner.scan_file(os.path.join(CASES, "tc26_rsa3072_cert.crt"))]
    assert names == ["RSA-3072", "RSA"]


def test_requirements_and_pyproject():
    found = {f["name"] for f in dependency_scanner.scan_directory(CASES)}
    assert found == {"cryptography", "pycryptodome", "pyjwt", "paramiko", "rsa", "python-jose"}


def test_cipher_suite_parsing():
    assert describe_cipher("ECDHE-RSA-AES128-GCM-SHA256") == ("ECDHE", "AES", 128)
    assert describe_cipher("TLS_AES_256_GCM_SHA384") == (None, "AES", 256)
    assert describe_cipher("AES256-SHA") == ("RSA", "AES", 256)
    assert parse_target("https://example.com:8443/x") == ("example.com", 8443)
    assert parse_target("example.com") == ("example.com", 443)


# ---- end to end -------------------------------------------------------------
def test_sample_project_cbom_is_valid_cyclonedx():
    findings, _ = scan(os.path.join(ROOT, "sample-project"))
    bom = build_cbom(findings, "sample-project")
    ok, error = validate_cbom(bom)
    assert ok is not False, error
    assert any(c["name"] == "RSA-2048" for c in bom["components"])


def test_standard_test_files_all_pass():
    sys.path.insert(0, os.path.join(ROOT, "evaluation"))
    from evaluate import evaluate
    rows = [r for r in evaluate() if not r["tricky"]]
    assert all(r["result"] == "PASS" for r in rows), [r for r in rows if r["result"] != "PASS"]
