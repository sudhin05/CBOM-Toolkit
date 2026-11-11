"""Code scanner: finds cryptography calls in .py files using Python's ast module.

How it works, in four steps:
  1. Parse the file into a syntax tree with ast.parse (comments and strings
     are ignored automatically, so "# hashlib.md5()" is not a finding).
  2. Read the import lines to learn what each local name means
     ("from hashlib import md5 as m" means m -> hashlib.md5).
  3. Visit every function call, turn it into a fully qualified name such as
     "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key"
     and look it up in the rules file (code_rules.py).
  4. Read the arguments to find key sizes, curves and algorithm names,
     following simple variables (algo = "sha1"; hashlib.new(algo)).

Known limits (documented in the report): names built at runtime
("sha" + "1"), getattr(), values read from config files or environment
variables, dynamic imports, and crypto done outside Python.
"""

import ast
import os

from .code_rules import (CURVES, HASH_NAMES, JWT_ALGS, RANDOM_BYTES, RULES,
                         SSL_PROTOCOLS)
from .finding import make_finding

SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", "node_modules",
             ".tox", ".mypy_cache", ".pytest_cache", "site-packages", "build", "dist"}


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------
def scan_directory(root):
    findings = []
    for path in iter_files(root, (".py",)):
        findings.extend(scan_file(path, root))
    return findings


def iter_files(root, extensions):
    if os.path.isfile(root):
        if root.lower().endswith(extensions):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.lower().endswith(extensions):
                yield os.path.join(dirpath, name)


def scan_file(path, root=None):
    rel = relpath(path, root)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError):
        return []  # Python 2 files or broken files are skipped
    return FileScanner(source, rel).scan(tree)


def relpath(path, root):
    if not root or os.path.isfile(root):
        return os.path.basename(path)
    return os.path.relpath(path, root).replace("\\", "/")


# ---------------------------------------------------------------------------
# The scanner for one file
# ---------------------------------------------------------------------------
class FileScanner:
    def __init__(self, source, rel_path):
        self.source = source
        self.file = rel_path
        self.imports = {}      # local name -> fully qualified name
        self.assigns = {}      # variable name -> [(line, value node), ...]
        self.consumed = set()  # call nodes already reported inside another finding
        self.findings = []

    # -- step 2: imports and simple variable assignments -------------------
    def collect_names(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.imports[a.asname] = a.name
                    else:  # "import os.path" makes the name "os" available
                        top = a.name.split(".")[0]
                        self.imports[top] = top
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for a in node.names:
                    if a.name != "*":
                        self.imports[a.asname or a.name] = f"{node.module}.{a.name}"
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if node.value is None:
                    continue
                for t in targets:
                    if isinstance(t, ast.Name):
                        self.assigns.setdefault(t.id, []).append((node.lineno, node.value))
        for values in self.assigns.values():
            values.sort(key=lambda item: item[0])

    def lookup_var(self, name, line):
        """Value of the last assignment to `name` at or before `line`."""
        best = None
        for lineno, value in self.assigns.get(name, []):
            if lineno <= line:
                best = value
        return best

    # -- step 3: turn a call into a qualified name --------------------------
    def qualified_name(self, node, line, depth=0):
        if depth > 5:
            return None
        if isinstance(node, ast.Name):
            if node.id in self.imports:
                return self.imports[node.id]
            value = self.lookup_var(node.id, line)  # h = hashlib.md5 ; h()
            if isinstance(value, (ast.Attribute, ast.Name)):
                return self.qualified_name(value, line, depth + 1)
            if value is not None:
                return None  # a local object, not a module: never a rule match
            return node.id
        if isinstance(node, ast.Attribute):
            base = self.qualified_name(node.value, line, depth + 1)
            return f"{base}.{node.attr}" if base else None
        return None

    @staticmethod
    def normalize(name):
        if name and name.startswith("Cryptodome."):
            return "Crypto." + name[len("Cryptodome."):]
        return name

    def find_rule(self, name):
        name = self.normalize(name)
        return (name, RULES[name]) if name in RULES else (name, None)

    # -- step 4: read arguments --------------------------------------------
    @staticmethod
    def get_arg(call, position, keyword):
        if keyword:
            for kw in call.keywords:
                if kw.arg == keyword:
                    return kw.value
        if position is not None and position < len(call.args):
            arg = call.args[position]
            if not isinstance(arg, ast.Starred):
                return arg
        return None

    def constant(self, node, line, depth=0):
        """Value of a literal, or of a variable that holds a literal."""
        if node is None or depth > 5:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self.constant(self.lookup_var(node.id, line), line, depth + 1)
        return None

    def key_bits(self, node, line, depth=0):
        """Key size in bits from a key expression such as os.urandom(32)."""
        if node is None or depth > 5:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)):
            return len(node.value) * 8
        if isinstance(node, ast.Name):
            return self.key_bits(self.lookup_var(node.id, line), line, depth + 1)
        if isinstance(node, ast.Call):
            name = self.normalize(self.qualified_name(node.func, line))
            if name in RANDOM_BYTES and node.args:
                n = self.constant(node.args[0], line)
                return n * 8 if isinstance(n, int) else None
            if name and name.endswith(".generate_key"):
                bits = self.constant(self.get_arg(node, 0, "bit_length"), line)
                if isinstance(bits, int):
                    return bits
                if "ChaCha20Poly1305" in name:
                    return 256
        return None

    def curve_name(self, node, line):
        if node is None:
            return None
        raw = None
        if isinstance(node, ast.Call):  # ec.SECP256R1()
            raw = (self.qualified_name(node.func, line) or "").split(".")[-1]
        elif isinstance(node, (ast.Attribute, ast.Name)):  # ecdsa.NIST256p
            value = self.constant(node, line)
            raw = value if isinstance(value, str) else \
                (self.qualified_name(node, line) or "").split(".")[-1]
        else:
            value = self.constant(node, line)
            raw = value if isinstance(value, str) else None
        if not raw:
            return None
        key = raw.lower().replace("-", "").replace("_", "").replace(" ", "")
        return CURVES.get(key, raw)

    def hash_from(self, node, line):
        """Hash name from 'sha256', hashlib.sha256, hashes.SHA256() or SHA256."""
        if node is None:
            return None
        value = self.constant(node, line)
        if isinstance(value, str):
            return canonical_hash(value)
        target = node.func if isinstance(node, ast.Call) else node
        name = self.qualified_name(target, line)
        if not name:
            return None
        if isinstance(node, ast.Call):
            self.consumed.add(id(node))
        last = self.normalize(name).split(".")
        # Crypto.Hash.SHA256 (module passed as digestmod) -> "SHA256"
        return canonical_hash(last[-1] if last[-1] != "new" else last[-2])

    # -- reporting -----------------------------------------------------------
    def evidence(self, node):
        text = ast.get_source_segment(self.source, node) or ""
        text = " ".join(text.split())
        return text if len(text) <= 120 else text[:117] + "..."

    def add(self, node, algorithm, primitive, param=None, function=None, note=""):
        self.findings.append(make_finding(
            "code", self.file, node.lineno, algorithm, primitive, param=param,
            function=function, evidence=self.evidence(node), note=note))

    # -- main loop -----------------------------------------------------------
    def scan(self, tree):
        self.collect_names(tree)
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        calls.sort(key=lambda n: (n.lineno, n.col_offset))  # outer call first
        for call in calls:
            if id(call) in self.consumed:
                continue
            name, spec = self.find_rule(self.qualified_name(call.func, call.lineno))
            if spec is None:
                continue
            handler = spec.get("handler")
            if handler:
                getattr(self, "handle_" + handler)(call, spec)
            else:
                self.handle_simple(call, spec)
        return self.findings

    # -- handlers --------------------------------------------------------------
    def handle_simple(self, call, spec):
        line = call.lineno
        param = spec.get("param")
        if "size" in spec:
            value = self.constant(self.get_arg(call, *spec["size"]), line)
            param = value if isinstance(value, int) else None
        elif "keybytes" in spec:
            param = self.key_bits(self.get_arg(call, *spec["keybytes"]), line)
        elif "curve" in spec:
            param = self.curve_name(self.get_arg(call, *spec["curve"]), line)
        note = spec.get("note", "")
        if spec["prim"] == "hash" and self.not_for_security(call):
            note = "Marked usedforsecurity=False (non-security use, still worth replacing)"
        self.add(call, spec["alg"], spec["prim"], param, spec.get("fn"), note)
        if "hash_arg" in spec:
            alg = self.hash_from(self.get_arg(call, *spec["hash_arg"]), line)
            if alg:
                self.add(call, alg, "hash", function="digest")

    @staticmethod
    def not_for_security(call):
        return any(kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant)
                   and kw.value.value is False for kw in call.keywords)

    def handle_hash_by_name(self, call, spec):
        alg = self.hash_from(self.get_arg(call, *spec["arg"]), call.lineno)
        if alg:
            self.add(call, alg, "hash", function="digest")
        else:
            self.add(call, "Unknown", "hash", function="digest",
                     note="Hash name is computed at runtime; check by hand")

    def handle_pbkdf2_by_name(self, call, spec):
        alg = self.hash_from(self.get_arg(call, *spec["arg"]), call.lineno)
        self.add(call, "PBKDF2", "kdf", alg, "keyderive")

    def handle_kdf_with_hash(self, call, spec):
        alg = self.hash_from(self.get_arg(call, *spec["arg"]), call.lineno)
        self.add(call, spec["alg"], "kdf", alg, "keyderive")

    def handle_hmac(self, call, spec):
        node = self.get_arg(call, *spec["arg"])
        alg = self.hash_from(node, call.lineno) if node is not None else None
        if node is None and self.normalize(self.qualified_name(call.func, call.lineno)) \
                == "Crypto.Hash.HMAC.new":
            alg = "MD5"  # pycryptodome default digestmod
        if alg:
            self.add(call, f"HMAC-{alg}", "mac", function="tag")
        else:
            self.add(call, "Unknown", "mac", function="tag",
                     note="HMAC hash is not given or computed at runtime")

    def _jwt(self, call, names):
        for value in names:
            alg, param, prim = JWT_ALGS.get(value, (value, None, "signature"))
            self.add(call, alg, prim, param, "sign", note=f"JWT algorithm {value}")

    def handle_jwt_encode(self, call, spec):
        node = self.get_arg(call, 2, "algorithm")
        value = self.constant(node, call.lineno) if node is not None else "HS256"
        if isinstance(value, str):
            self._jwt(call, [value])
        elif node is not None:
            self.add(call, "Unknown", "signature", function="sign",
                     note="JWT algorithm is computed at runtime")

    def handle_jwt_decode(self, call, spec):
        node = self.get_arg(call, 2, "algorithms")
        if node is None:
            return
        if isinstance(node, ast.Name):
            node = self.lookup_var(node.id, call.lineno) or node
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = [self.constant(e, call.lineno) for e in node.elts]
            self._jwt(call, [v for v in values if isinstance(v, str)])
        else:
            value = self.constant(node, call.lineno)
            if isinstance(value, str):
                self._jwt(call, [value])

    def handle_paramiko_ecdsa(self, call, spec):
        bits = self.constant(self.get_arg(call, 1, "bits"), call.lineno) or 256
        curve = {256: "P-256", 384: "P-384", 521: "P-521"}.get(bits, bits)
        self.add(call, "ECDSA", "signature", curve, "keygen")

    def handle_ssl_context(self, call, spec):
        node = self.get_arg(call, *spec["arg"])
        proto = None
        if isinstance(node, (ast.Attribute, ast.Name)):
            proto = (self.qualified_name(node, call.lineno) or "").split(".")[-1]
        version = SSL_PROTOCOLS.get(proto)
        if version:
            self.add(call, version, "protocol", function="connect",
                     note=f"Context pinned to {version}")
        else:
            self.add(call, "TLS", "protocol", function="connect",
                     note="Negotiated TLS version and key exchange decide quantum safety; "
                          "run the TLS checker on the server")

    def handle_pqc_by_name(self, call, spec):
        value = self.constant(self.get_arg(call, *spec["arg"]), call.lineno)
        if not isinstance(value, str):
            self.add(call, "Unknown", spec["prim"], function="keygen")
            return
        alg, _, param = value.rpartition("-")
        if alg and param.isdigit():
            self.add(call, alg, spec["prim"], int(param), "keygen")
        else:
            self.add(call, value, spec["prim"], function="keygen")


def canonical_hash(text):
    key = text.lower().replace("-", "").replace("_", "").replace("/", "")
    return HASH_NAMES.get(key)
