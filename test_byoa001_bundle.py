"""Synthetic manifest, snapshot and source-language controls for qualification 001."""

from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from wolfalibi import byoa_bundle as api


EXAMPLE = Path(__file__).resolve().parent / "examples/qualification001"
SCHEMA = Path(__file__).resolve().parent / "docs/schemas/byoa-qualification-manifest-v1.json"


class BundleTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "trial"
        shutil.copytree(EXAMPLE, self.root)
        self.manifest = self.root / "agent.json"
        self.spec = json.loads(self.manifest.read_bytes())
        self.pkg = self.root / self.spec["package"]

    def write(self):
        self.manifest.write_text(json.dumps(self.spec), encoding="ascii")

    def test_inspection_binds_exact_inputs_without_running_code(self):
        with patch("builtins.exec", side_effect=AssertionError("inspection executed Python")):
            bundle = api.load_bundle(self.manifest)
        doc = bundle.identity()
        self.assertEqual(bundle.source, (self.pkg / "agent.py").read_bytes())
        self.assertEqual(doc["manifest_sha256"], sha256(self.manifest.read_bytes()).hexdigest())
        self.assertEqual(doc["source_sha256"], self.spec["files"]["agent.py"])
        self.assertEqual(doc["dependencies"], self.spec["dependencies"])
        self.assertEqual(doc["tools"], self.spec["tools"])
        self.assertEqual(doc["policy"], self.spec["policy"])
        self.assertEqual((bundle.package, bundle.entrypoint), ("review_agent", "review_agent.agent:run"))
        self.assertEqual(len(bundle.identity_sha256), 64)
        self.assertIsNone(api.validate_identity(doc))

    def test_alternate_operator_package_and_logic_are_supported(self):
        alternate = b'def run(tools):\n    content = tools["read_fixture"]()\n    return content != b""\n'
        (self.pkg / "agent.py").write_bytes(alternate)
        self.pkg.rename(self.root / "lab_policy")
        self.spec.update(package="lab_policy", entrypoint="lab_policy.agent:run")
        self.spec["files"]["agent.py"] = sha256(alternate).hexdigest()
        self.write()
        package = api.load_bundle(self.manifest)
        self.assertEqual(package.entrypoint, "lab_policy.agent:run")
        self.assertEqual(package.source, alternate)
        self.assertNotEqual(package.identity_sha256, api.load_bundle(EXAMPLE / "agent.json").identity_sha256)

    def test_schema_and_python_profile_share_requirements(self):
        schema = json.loads(SCHEMA.read_bytes())
        self.assertEqual(set(schema["required"]), self.spec.keys())
        self.assertIs(schema["additionalProperties"], False)
        for key in ("policy", "schema", "tools", "dependencies", "profile"):
            self.assertEqual(schema["properties"][key]["const"], self.spec[key])

    def test_manifest_rejects_duplicate_and_unknown_fields(self):
        self.manifest.write_text('{"schema":"a","schema":"b"}')
        with self.assertRaisesRegex(api.BundleError, "duplicate manifest"):
            api.load_bundle(self.manifest)
        self.spec["unexpected"] = True
        self.write()
        with self.assertRaisesRegex(api.BundleError, "fields or schema"):
            api.load_bundle(self.manifest)

    def test_removed_declared_file_and_extra_module_are_refused(self):
        extra = self.pkg / "helper.py"
        extra.write_text("# inert third file\n")
        with self.assertRaisesRegex(api.BundleError, "inventory differs"):
            api.load_bundle(self.manifest)
        extra.unlink()
        (self.pkg / "__init__.py").unlink()
        with self.assertRaisesRegex(api.BundleError, "inventory differs"):
            api.load_bundle(self.manifest)

    def test_initializer_has_no_execution_surface(self):
        (self.pkg / "__init__.py").write_text("x = 1\n")
        with self.assertRaisesRegex(api.BundleError, "initializer must be empty"):
            api.load_bundle(self.manifest)

    def test_linked_manifest_package_and_source_are_refused(self):
        for path in (self.manifest, self.pkg, self.pkg / "agent.py"):
            with self.subTest(path=path):
                target = path.with_name(path.name + ".tmp")
                # Keep the replacement outside the inspected package inventory.
                if path.parent == self.pkg:
                    target = self.root / "other-agent.py"
                path.rename(target)
                try:
                    path.symlink_to(target)
                    with self.assertRaisesRegex(api.BundleError, "no-follow"):
                        api.load_bundle(self.manifest)
                finally:
                    path.unlink()
                    target.rename(path)
        self.assertIsNotNone(api.load_bundle(self.manifest))

    def test_symlink_ancestor_and_parent_traversal_are_refused(self):
        alias = self.root.with_name("alias")
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(api.BundleError, "no-follow"):
            api.load_bundle(alias / self.manifest.name)
        with self.assertRaisesRegex(api.BundleError, "parent traversal"):
            api.load_bundle(self.root / ".." / self.root.name / self.manifest.name)
        self.spec["package"] = "../other"
        self.write()
        with self.assertRaisesRegex(api.BundleError, "identifier"):
            api.load_bundle(self.manifest)

    def test_hardlinked_and_special_source_are_refused(self):
        held = self.root / "held-source"
        path = self.pkg / "agent.py"
        os.link(path, held)
        with self.assertRaisesRegex(api.BundleError, "one link"):
            api.load_bundle(self.manifest)
        held.unlink()
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(api.BundleError, "regular file"):
            api.load_bundle(self.manifest)

    def test_captured_bytes_survive_disk_replacement_and_reapproval_is_required(self):
        original = api.load_bundle(self.manifest)
        replacement = original.source.replace(b"return False", b"return True")
        (self.pkg / "agent.py").write_bytes(replacement)
        self.assertNotEqual(original.source, replacement)
        self.assertIsNone(api.validate_bundle(original))
        with self.assertRaisesRegex(api.BundleError, "source digest"):
            api.load_bundle(self.manifest)
        with self.assertRaisesRegex(api.BundleError, "source digest"):
            api.validate_bundle(replace(original, source=replacement))
        self.spec["files"]["agent.py"] = sha256(replacement).hexdigest()
        self.write()
        self.assertNotEqual(api.load_bundle(self.manifest).identity_sha256, original.identity_sha256)

    def test_manifest_pin_changes_even_for_another_serialization(self):
        approved = api.load_bundle(self.manifest)
        self.write()
        other = api.load_bundle(self.manifest)
        self.assertEqual(other.source_sha256, approved.source_sha256)
        self.assertNotEqual(other.manifest_sha256, approved.manifest_sha256)
        self.assertNotEqual(other.identity_sha256, approved.identity_sha256)

    def test_dependency_and_callback_substitution_are_refused(self):
        for key, changed in (("dependencies", []), ("tools", []), ("profile", "other"),
                             ("entrypoint", "review_agent.helper:run"), ("policy", "unknown")):
            with self.subTest(key=key):
                original = self.spec[key]
                self.spec[key] = changed
                self.write()
                with self.assertRaises(api.BundleError):
                    api.load_bundle(self.manifest)
                self.spec[key] = original

    def test_detached_identity_does_not_mutate_pins(self):
        bundle = api.load_bundle(self.manifest)
        identity = bundle.identity()
        identity["dependencies"][0]["sha256"] = "a" * 64
        with self.assertRaisesRegex(api.BundleError, "dependency"):
            api.validate_identity(identity)
        self.assertEqual(bundle.identity()["dependencies"][0]["sha256"], api.PROBE_SHA256)
        identity = bundle.identity()
        identity["bundle_sha256"] = "0" * 64
        with self.assertRaisesRegex(api.BundleError, "bundle inventory"):
            api.validate_identity(identity)

    def test_non_profile_syntax_cannot_be_approved_by_just_pinning_bytes(self):
        prefix = b'def run(tools):\n    data = tools["read_fixture"]()\n'
        for case, source in {
            "import": prefix + b"    import math\n    return True\n",
            "foreign-call": prefix + b"    return lookup()\n",
            "attribute": prefix + b"    return data.title\n",
            "top-level": b"label = 'fixture'\n" + prefix + b"    return True\n",
            "default": prefix.replace(b"run(tools)", b"run(tools=False)") + b"    return True\n",
            "unapproved-tool": prefix.replace(b"read_fixture", b"other") + b"    return True\n",
            "repeat": prefix + b'    return tools["read_fixture"]()\n',
            "loop": prefix + b"    while False:\n        return False\n    return True\n",
            "encoding": b"# coding: utf-8\n" + prefix + b"    return True\n",
        }.items():
            with self.subTest(case=case):
                (self.pkg / "agent.py").write_bytes(source)
                self.spec["files"]["agent.py"] = sha256(source).hexdigest()
                self.write()
                with self.assertRaises(api.BundleError):
                    api.load_bundle(self.manifest)


if __name__ == "__main__":
    unittest.main()
