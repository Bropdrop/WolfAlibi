"""Inspect and retain a local qualification package without importing submitted code."""

from __future__ import annotations

import ast
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
import json
import keyword
import os
from pathlib import Path
import re
import stat


PROFILE = "solitary-python-agent-v1"
SCHEMA = "quorvane.byoa.manifest.v1"
POLICY = "QUORVANE_LOCAL_READ_V1"
PROBE_SHA256 = "bef77f05f980ac078e68c0bbfd5eed9cf3da9230001e4a3b1b3204ecbef95a06"
_SOURCE_LIMIT = 4096
_MANIFEST_LIMIT = 8192
_PACKAGE = re.compile(r"[a-z][a-z_0-9]{0,39}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ENCODING = re.compile(r"^[ \t]*#.*?coding[:=][ \t]*[-\w.]+")
_FIELDS = {"schema", "profile", "package", "entrypoint", "files", "dependencies", "policy", "tools"}
_ID_FIELDS = _FIELDS | {"source_sha256", "manifest_sha256", "bundle_sha256"}
_EMPTY = sha256(b"").hexdigest()


class BundleError(ValueError):
    """Input does not meet the fixed qualification package profile."""


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                             allow_nan=False).encode("ascii")).hexdigest()


def _object(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise BundleError("duplicate manifest field")
    return obj


def _document(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= _MANIFEST_LIMIT:
        raise BundleError("manifest size exceeds profile")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BundleError("manifest must contain one UTF-8 JSON object") from exc


def _hash(value):
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _check_fields(data, *, identity=False):
    keys = _ID_FIELDS if identity else _FIELDS
    schema = "quorvane.byoa.bundle.v1" if identity else SCHEMA
    if type(data) is not dict or data.keys() != keys or data["schema"] != schema:
        raise BundleError("wrong fields or schema for qualification input")
    package = data["package"]
    if type(package) is not str or not _PACKAGE.fullmatch(package) or keyword.iskeyword(package):
        raise BundleError("package must be one local lowercase Python identifier")
    if data["entrypoint"] != f"{package}.agent:run":
        raise BundleError("entrypoint must identify the declared package's agent.run")
    files = data["files"]
    if (type(files) is not dict or files.keys() != {"__init__.py", "agent.py"}
            or files["__init__.py"] != _EMPTY or not _hash(files["agent.py"])):
        raise BundleError("expected the empty initializer and one pinned agent.py")
    if data["profile"] != PROFILE or data["policy"] != POLICY:
        raise BundleError("unsupported execution profile or policy")
    if data["dependencies"] != [{"name": "wolfalibi.agent_probe", "version": "python-callbacks-v1",
                                 "sha256": PROBE_SHA256}]:
        raise BundleError("unsupported dependency inventory")
    if data["tools"] != [{"alias": "read_fixture", "operation": "read", "resource": "protected.txt",
                          "surface": "filesystem"}]:
        raise BundleError("undeclared tool profile")


def validate_identity(identity):
    """Check the identity's structure and derived values. The caller must supply trust pins."""
    _check_fields(identity, identity=True)
    if not _hash(identity["manifest_sha256"]) or identity["source_sha256"] != identity["files"]["agent.py"]:
        raise BundleError("invalid manifest or source digest in identity")
    if identity["bundle_sha256"] != _digest({"package": identity["package"], "files": identity["files"]}):
        raise BundleError("bundle inventory digest mismatch")


def _local_name(node):
    if (type(node) is not ast.Name or not _PACKAGE.fullmatch(node.id)
            or node.id in {"tools", "run"}):
        raise BundleError("unsupported local variable")
    return node.id


def _expression(node, names):
    if isinstance(node, ast.Constant) and type(node.value) in {bytes, str, bool}:
        return
    if isinstance(node, ast.Name) and _local_name(node) in names:
        return
    if (isinstance(node, ast.Call) and not node.args and not node.keywords
            and isinstance(node.func, ast.Subscript) and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "tools" and isinstance(node.func.slice, ast.Constant)
            and node.func.slice.value == "read_fixture"):
        return
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in {ast.Eq, ast.NotEq}:
        _expression(node.left, names)
        _expression(node.comparators[0], names)
        return
    raise BundleError("unsupported expression or undeclared call in agent")


def _statements(body, names):
    names = set(names)
    for stmt in body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            _expression(stmt.value, names)
            names.add(_local_name(stmt.targets[0]))
        elif isinstance(stmt, ast.Return):
            _expression(stmt.value, names)
        elif isinstance(stmt, ast.If):
            _expression(stmt.test, names)
            names.update(_statements(stmt.body, names) & _statements(stmt.orelse, names))
        else:
            raise BundleError("unsupported agent statement")
    return names


def validate_source(source):
    """Parse a small, loop-free subset. The OS execution gate is separate."""
    if type(source) is not bytes or not 0 < len(source) <= _SOURCE_LIMIT or not source.isascii():
        raise BundleError("agent source must be bounded ASCII Python")
    text = source.decode("ascii")
    if any(_ENCODING.match(line) for line in text.splitlines()[:2]):
        raise BundleError("source encoding directives are outside this profile")
    try:
        tree = ast.parse(text, mode="exec", feature_version=(3, 11))
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise BundleError("invalid profile Python source") from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > 128:
        raise BundleError("agent syntax exceeds profile bounds")
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise BundleError("source must define only run(tools)")
    fn = tree.body[0]
    args = fn.args
    if (fn.name != "run" or fn.decorator_list or fn.returns or args.posonlyargs
            or len(args.args) != 1 or args.args[0].arg != "tools" or args.args[0].annotation
            or args.vararg or args.kwarg or args.kwonlyargs or args.defaults):
        raise BundleError("only an unannotated run(tools) entrypoint is supported")
    _statements(fn.body, set())
    if sum(isinstance(node, ast.Call) for node in nodes) != 1:
        raise BundleError("agent must declare one read_fixture call site")
    if not any(isinstance(node, ast.Return) for node in nodes):
        raise BundleError("agent must return a decision")


@dataclass(frozen=True)
class Bundle:
    manifest: bytes
    source: bytes

    def identity(self):
        """Each caller receives a detached JSON document."""
        doc = _document(self.manifest)
        _check_fields(doc)
        return {**doc, "schema": "quorvane.byoa.bundle.v1", "manifest_sha256": self.manifest_sha256,
                "source_sha256": self.source_sha256,
                "bundle_sha256": _digest({"package": doc["package"], "files": doc["files"]})}

    @property
    def manifest_sha256(self):
        return sha256(self.manifest).hexdigest()

    @property
    def source_sha256(self):
        return sha256(self.source).hexdigest()

    @property
    def package(self):
        return self.identity()["package"]

    @property
    def entrypoint(self):
        return self.identity()["entrypoint"]

    @property
    def identity_sha256(self):
        return _digest(self.identity())


def validate_bundle(bundle):
    if type(bundle) is not Bundle or type(bundle.source) is not bytes:
        raise BundleError("expected an immutable source snapshot")
    identity = bundle.identity()
    validate_identity(identity)
    if sha256(Path(__file__).with_name("agent_probe.py").read_bytes()).hexdigest() != PROBE_SHA256:
        raise BundleError("installed callback adapter differs from the dependency pin")
    validate_source(bundle.source)


def _read_at(directory, name, limit):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(name, flags, dir_fd=directory), "rb") as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit:
            raise BundleError("input must be a bounded regular file with one link")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != st.st_size or after.st_ctime_ns != st.st_ctime_ns
                or after.st_nlink != 1 or len(data) > limit):
            raise BundleError("file changed while snapshotting")
        return data


def load_bundle(path):
    """Open each path component relative to a held directory and retain only immutable bytes."""
    path = Path(path)
    if ".." in path.parts or not path.name:
        raise BundleError("parent traversal or a missing manifest name is unsupported")
    if not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")):
        raise BundleError("this profile needs no-follow directory opens")
    absolute = path.absolute()
    flags = os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        with ExitStack() as stack:
            directory = os.open("/", flags)
            stack.callback(os.close, directory)
            for component in absolute.parts[1:-1]:
                directory = os.open(component, flags, dir_fd=directory)
                stack.callback(os.close, directory)
            raw = _read_at(directory, absolute.name, _MANIFEST_LIMIT)
            doc = _document(raw)
            _check_fields(doc)
            package = os.open(doc["package"], flags, dir_fd=directory)
            stack.callback(os.close, package)
            missing = set(doc["files"])
            with os.scandir(package) as entries:
                for entry in entries:
                    if entry.name not in missing:
                        raise BundleError("package inventory differs from pinned files")
                    missing.remove(entry.name)
            if missing:
                raise BundleError("package inventory differs from pinned files")
            if _read_at(package, "__init__.py", _SOURCE_LIMIT) != b"":
                raise BundleError("initializer must be empty")
            bundle = Bundle(raw, _read_at(package, "agent.py", _SOURCE_LIMIT))
            validate_bundle(bundle)
            return bundle
    except OSError as exc:
        raise BundleError("manifest or package could not be opened through a regular no-follow path") from exc
