"""Writes findings as a CycloneDX 1.6 CBOM (JSON) and validates it.

CycloneDX 1.6 added the "cryptographic-asset" component type. We use:
  * one "algorithm" asset per distinct algorithm (e.g. RSA-2048), listing
    every place it was found under evidence.occurrences
  * one "certificate" asset per certificate, pointing at its key and
    signature algorithm assets
  * one "protocol" asset per scanned website (TLS versions + cipher suite)
  * one "library" component per crypto dependency
Our red/yellow/green label is stored as a component property so other tools
can read it, and the NIST quantum security level goes in the standard field.
"""

import json
import uuid
from datetime import datetime, timezone

from . import __version__
from .rules import nist_quantum_level

PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
              "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"}
FUNCTIONS = {"keygen": "keygen", "encrypt": "encrypt", "decrypt": "decrypt",
             "digest": "digest", "tag": "tag", "keyderive": "keyderive",
             "sign": "sign", "verify": "verify", "certificate-signature": "sign"}
TOOL = "cbom-scanner"


def algorithm_ref(f):
    return f"crypto/algorithm/{f['name']}"


def label_properties(f):
    return [{"name": f"{TOOL}:quantum-label", "value": f["label"]},
            {"name": f"{TOOL}:quantum-safe", "value": str(f["quantum_safe"]).lower()},
            {"name": f"{TOOL}:reason", "value": f["reason"]}]


def occurrence(f):
    occ = {"location": f["file"]}
    if f.get("line"):
        occ["line"] = f["line"]
    context = f.get("evidence") or ""
    if f.get("note"):
        context = f"{context} ({f['note']})" if context else f["note"]
    if context:
        occ["additionalContext"] = context
    return occ


def build_cbom(findings, project_name="scanned-project", tls_summaries=None):
    components = {}
    order = []

    def add(ref, component):
        if ref not in components:
            components[ref] = component
            order.append(ref)
        return components[ref]

    # 1. algorithms (everything that is not a library, protocol or certificate)
    for f in findings:
        if f["primitive"] in ("library", "protocol"):
            continue
        ref = algorithm_ref(f)
        props = {"primitive": f["primitive"] if f["primitive"] in PRIMITIVES else "other"}
        if isinstance(f["param"], int):
            props["parameterSetIdentifier"] = str(f["param"])
        elif f["param"]:
            if f["algorithm"] in ("EC", "ECDSA", "ECDH", "ECDHE"):
                props["curve"] = f["param"]
            else:
                props["parameterSetIdentifier"] = str(f["param"])
        level = nist_quantum_level(f["algorithm"], f["param"])
        if level is not None:
            props["nistQuantumSecurityLevel"] = level
        comp = add(ref, {
            "type": "cryptographic-asset", "bom-ref": ref, "name": f["name"],
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props},
            "properties": label_properties(f),
            "evidence": {"occurrences": []},
        })
        fn = FUNCTIONS.get(f.get("function") or "", None)
        if fn:
            funcs = comp["cryptoProperties"]["algorithmProperties"].setdefault("cryptoFunctions", [])
            if fn not in funcs:
                funcs.append(fn)
        comp["evidence"]["occurrences"].append(occurrence(f))

    # 2. certificates: pair the "certificate-key" and "certificate-signature" findings
    certs = {}
    for f in findings:
        if f.get("function") in ("certificate-key", "certificate-signature"):
            key = (f["file"], f["line"], f["extra"].get("serial"))
            certs.setdefault(key, {})[f["function"]] = f
    for i, ((file, line, serial), pair) in enumerate(certs.items(), 1):
        any_f = next(iter(pair.values()))
        info = any_f["extra"]
        ref = f"crypto/certificate/{serial or i}"
        cert_props = {
            "subjectName": info.get("subject", ""),
            "issuerName": info.get("issuer", ""),
            "notValidBefore": info.get("not_before"),
            "notValidAfter": info.get("not_after"),
            "certificateFormat": "X.509",
        }
        if "certificate-key" in pair:
            cert_props["subjectPublicKeyRef"] = algorithm_ref(pair["certificate-key"])
        if "certificate-signature" in pair:
            cert_props["signatureAlgorithmRef"] = algorithm_ref(pair["certificate-signature"])
        add(ref, {
            "type": "cryptographic-asset", "bom-ref": ref,
            "name": info.get("subject") or f"certificate {i}",
            "cryptoProperties": {"assetType": "certificate",
                                 "certificateProperties": {k: v for k, v in cert_props.items() if v}},
            "evidence": {"occurrences": [occurrence(any_f)]},
        })

    # 3. protocols: TLS versions found in code or on websites
    for f in findings:
        if f["primitive"] != "protocol":
            continue
        version = f["algorithm"].replace("TLS ", "").replace("TLS", "").replace("SSH", "")
        if f["source"] == "tls":
            ref = f"crypto/protocol/tls/{f['file']}/{f['algorithm']}"
        else:
            ref = f"crypto/protocol/{f['name']}"
        proto = {"type": "tls" if f["algorithm"].startswith("TLS")
                 else "ssh" if f["algorithm"] == "SSH" else "other"}
        if version:
            proto["version"] = version
        comp = add(ref, {
            "type": "cryptographic-asset", "bom-ref": ref,
            "name": f["name"] if f["source"] != "tls" else f"{f['name']} @ {f['file']}",
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": proto},
            "properties": label_properties(f),
            "evidence": {"occurrences": []},
        })
        comp["evidence"]["occurrences"].append(occurrence(f))

    # attach the negotiated cipher suite to each website's default protocol version
    for s in tls_summaries or []:
        if s.get("error"):
            continue
        ref = f"crypto/protocol/tls/{s['target']}/{s['default_version']}"
        if ref in components:
            algs = [algorithm_ref(f) for f in findings
                    if f["source"] == "tls" and f["file"] == s["target"]
                    and f.get("function") in ("keyexchange", "encrypt")]
            components[ref]["cryptoProperties"]["protocolProperties"]["cipherSuites"] = [
                {"name": s["cipher"], "algorithms": sorted(set(algs))}]

    # 4. libraries
    lib_refs = []
    for f in findings:
        if f["primitive"] != "library":
            continue
        pkg, version = f["extra"]["package"], f["extra"].get("version")
        exact = version[2:].strip() if version and version.startswith("==") else None
        ref = f"pkg:pypi/{pkg}" + (f"@{exact}" if exact else "")
        comp = {"type": "library", "bom-ref": ref, "name": pkg, "purl": ref,
                "description": f["note"],
                "evidence": {"occurrences": [occurrence(f)]}}
        if exact:
            comp["version"] = exact
        if ref not in components:
            lib_refs.append(ref)
        else:
            components[ref]["evidence"]["occurrences"].append(occurrence(f))
            continue
        add(ref, comp)

    root_ref = f"app/{project_name}"
    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": TOOL,
                                      "version": __version__}]},
            "component": {"type": "application", "bom-ref": root_ref, "name": project_name},
        },
        "components": [components[r] for r in order],
        "dependencies": [{"ref": root_ref, "dependsOn": lib_refs}] + [
            {"ref": r} for r in lib_refs],
    }
    return bom


def write_cbom(bom, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)


def validate_cbom(bom):
    """Validate against the official CycloneDX 1.6 JSON schema.
    Returns (True, None), (False, error text) or (None, reason it was skipped)."""
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        return None, "cyclonedx-python-lib not installed; schema check skipped"
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    return (True, None) if error is None else (False, str(error))
