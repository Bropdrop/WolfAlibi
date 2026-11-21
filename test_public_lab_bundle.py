"""Check the standalone browser document and extracted offline verifier bundle."""

from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parent
CASE_IDS = {"education", "finance", "history"}
ASSET_ATTRIBUTES = {
    "audio": {"src"}, "image": {"href", "xlink:href"}, "img": {"src", "srcset"},
    "input": {"src"}, "link": {"href"}, "script": {"src"}, "source": {"src", "srcset"},
    "track": {"src"}, "use": {"href", "xlink:href"}, "video": {"src", "poster"},
}


class StandaloneMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.scripts = []
        self.current_script = None

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        self.tags.append((tag, attributes))
        if tag == "script":
            self.current_script = []
            self.scripts.append((attributes, self.current_script))

    def handle_data(self, text):
        if self.current_script is not None:
            self.current_script.append(text)

    def handle_endtag(self, tag):
        if tag == "script":
            self.current_script = None


class PublicLabBundleTests(unittest.TestCase):
    def test_standalone_html_has_no_external_assets_and_embeds_inert_json(self):
        document = StandaloneMarkup()
        document.feed((ROOT / "public_lab" / "index.html").read_text(encoding="utf-8"))
        document.close()
        policy = []
        for tag, attributes in document.tags:
            with self.subTest(tag=tag, attributes=sorted(attributes)):
                self.assertNotIn(tag, {"base", "embed", "iframe", "object"})
                self.assertFalse(any(name.startswith("on") for name in attributes))
                for name in ASSET_ATTRIBUTES.get(tag, set()) & attributes.keys():
                    self.assertTrue(attributes[name].startswith(("data:", "#")), (tag, name))
                if tag == "meta":
                    directive = attributes.get("http-equiv", "").lower()
                    self.assertNotEqual(directive, "refresh")
                    if directive == "content-security-policy":
                        policy.append(attributes["content"])
        self.assertEqual(len(policy), 1)
        directives = {tuple(clause.strip().split()) for clause in policy[0].split(";") if clause.strip()}
        self.assertIn(("default-src", "'none'"), directives)
        self.assertIn(("connect-src", "'none'"), directives)
        inert = ["".join(parts) for attrs, parts in document.scripts if attrs.get("type") == "application/json"]
        self.assertEqual(len(inert), 1)
        self.assertNotIn("<", inert[0])
        data = json.loads(inert[0])
        self.assertEqual(set(data["cases"]), CASE_IDS)
        for case in CASE_IDS:
            files = data["cases"][case]["raw"]
            self.assertEqual(set(files), {"challenge.txt", "genuine.json", "pins.json", "tampered.json"})
            for filename, embedded in files.items():
                with self.subTest(case=case, filename=filename):
                    self.assertEqual(embedded.encode("utf-8"),
                                     (ROOT / "public_lab" / "vectors" / case / filename).read_bytes())
        self.assertEqual(len(document.scripts), 2)

    def _run(self, script, *arguments, cwd, expected_exit=0):
        result = subprocess.run([sys.executable, "-I", str(script), *map(str, arguments)], cwd=cwd,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, expected_exit, result.stdout + result.stderr)
        return result.stdout

    def test_archive_is_reproducible_and_verifies_without_the_project_checkout(self):
        with TemporaryDirectory(prefix="quorvane-bundle-test-") as temporary:
            root = Path(temporary)
            builder = ROOT / "scripts" / "build_public_lab.py"
            first = root / "package-a.zip"
            second = root / "package-b.zip"
            first_report = json.loads(self._run(builder, "--archive", first, cwd=root))
            second_report = json.loads(self._run(builder, "--archive", second, cwd=root))
            self.assertEqual(first_report["outcome"], "PASS")
            self.assertEqual(first_report, second_report)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_report["artifacts"]["public_lab/quorvane-public-lab-001.zip"],
                             sha256(first.read_bytes()).hexdigest())
            package = root / "extracted"
            with ZipFile(first) as archive:
                members = archive.infolist()
                names = {entry.filename for entry in members}
                self.assertEqual(len(names), len(members))
                for entry in members:
                    path = PurePosixPath(entry.filename)
                    self.assertFalse(path.is_absolute() or ".." in path.parts or ".git" in path.parts)
                    self.assertNotIn("\\", entry.filename)
                    self.assertTrue(stat.S_ISREG(entry.external_attr >> 16))
                self.assertTrue({"public_lab/index.html", "public_lab/manifest.json", "scripts/public_lab.py",
                                 "wolfalibi/history_verify.py", "wolfalibi/education_verify.py",
                                 "wolfalibi/finance_verify.py"} <= names)
                archive.extractall(package)
            verifier = package / "scripts" / "public_lab.py"
            self.assertEqual((package / "public_lab" / "index.html").read_bytes(),
                             (ROOT / "public_lab" / "index.html").read_bytes())
            result = json.loads(self._run(verifier, "verify", cwd=root))
            self.assertEqual(result["outcome"], "PASS")
            self.assertEqual({item["id"] for item in result["cases"]}, CASE_IDS)
            for case in result["cases"]:
                self.assertEqual(case["genuine"]["outcome"], "VERIFIED")
                self.assertEqual(case["tampered"]["outcome"], "REJECTED")
            copied_artifact = package / "public_lab" / "vectors" / "education" / "genuine.json"
            copied_artifact.write_bytes(copied_artifact.read_bytes() + b"\n")
            rejected = json.loads(self._run(verifier, "verify", "--case", "education", cwd=root, expected_exit=2))
            self.assertEqual(rejected["outcome"], "BLOCKED")
            self.assertIn("SHA-256 mismatch", rejected["cases"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
