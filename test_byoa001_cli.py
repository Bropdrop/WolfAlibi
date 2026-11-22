"""Exercise preparation, target administration and fail-stop CLI publication boundaries."""

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import wolfalibi_cli
from wolfalibi import byoa_qualification_cli as cli


SAMPLE = Path(__file__).parent / "examples/qualification001/agent.json"


class QualificationCliTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix="byoa-ops-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.trial, self.owner, self.review, self.output = (self.root / k for k in ("trial", "owner", "review", "out"))
        self.grant = self.root / "grant.json"
        self.expect = self.review / "expected.json"

    def command(self, verb, *args):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = wolfalibi_cli.main(["byoa", verb, *map(str, args)])
        report = json.loads(buffer.getvalue())
        self.assertEqual(code == 0, report["outcome"] not in {"REJECTED", "BLOCKED", "UNSUPPORTED"})
        return report

    def setup_roles(self):
        for name, path in (("trial", self.trial), ("owner", self.owner)):
            self.assertEqual(self.command("provision", "--role", name, "--output", path)["outcome"], "PROVISIONED")
        admin = self.command("enroll-owner", "--trial", self.trial, "--owner-pin", self.owner / "public.json",
                             "--approve-owner")
        self.assertEqual(admin["outcome"], "ENROLLED")
        args = ("--manifest", SAMPLE, "--trial-pins", self.trial / "public.json", "--owner-pin",
                self.owner / "public.json", "--output", self.review)
        self.assertEqual(self.command("prepare", *args)["outcome"], "PREPARED")

    def approve(self):
        args = ("--owner", self.owner, "--expect", self.expect, "--output", self.grant)
        self.assertEqual(self.command("grant-read", *args, "--approve-read")["outcome"], "GRANTED")

    def launch_args(self, output=None):
        return ("--manifest", SAMPLE, "--trial", self.trial, "--review", self.review, "--grant", self.grant,
                "--output", output or self.output)

    def target(self, action):
        return self.command(action, "--trial", self.trial, "--expect", self.expect, "--grant", self.grant)

    def crash_at(self, point):
        pid = os.fork()
        if pid == 0:
            with patch(point, side_effect=lambda *_, **kw: os._exit(73)):
                self.command("qualify", *self.launch_args(), "--consent")
            os._exit(74)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 73)
        self.assertFalse((self.output / "report.json").exists())

    def test_consent_and_separate_owner_grant_required(self):
        self.setup_roles()
        self.assertEqual(self.command("grant-read", "--owner", self.owner, "--expect", self.expect,
                                     "--output", self.grant)["outcome"], "BLOCKED")
        self.assertFalse(self.grant.exists())
        self.approve()
        self.assertEqual(self.command("qualify", *self.launch_args())["outcome"], "BLOCKED")
        self.assertFalse(self.output.exists())
        self.assertFalse((self.review / "attempt.json").exists())
        self.assertEqual(self.target("recover-read")["outcome"], "BLOCKED")

    def test_revoked_permission_fails_before_launch(self):
        self.setup_roles()
        self.approve()
        self.assertEqual(self.target("revoke-read")["outcome"], "REVOKED")
        with patch("wolfalibi.byoa_cell.run_cell") as launch:
            result = self.command("qualify", *self.launch_args(), "--consent")
        launch.assert_not_called()
        self.assertIn("revoked", result["reason"].lower())
        self.assertFalse((self.output / "report.json").exists())

    def test_replaced_verifier_expectations_cannot_launch(self):
        self.setup_roles()
        self.approve()
        expected = json.loads(self.expect.read_bytes())
        expected["contract"]["run_id"] += "-other"
        self.expect.write_text(json.dumps(expected))
        result = self.command("qualify", *self.launch_args(), "--consent")
        self.assertIn("retained issuance", result["reason"])
        self.assertFalse((self.trial / "attempt.json").exists())

    def test_interruption_after_reservation_burns_attempt_without_read(self):
        self.setup_roles()
        self.approve()
        self.crash_at("wolfalibi.byoa_cell.run_cell")
        self.assertTrue((self.trial / "attempt.json").is_file() and (self.review / "attempt.json").is_file())
        with patch("wolfalibi.byoa_cell.run_cell") as launch:
            self.assertEqual(self.command("qualify", *self.launch_args(self.root / "retry"), "--consent")["outcome"],
                             "BLOCKED")
        launch.assert_not_called()
        self.assertEqual(self.target("recover-read")["outcome"], "BLOCKED")

    def test_interruption_after_fresh_acceptance_recovers_only_admission(self):
        self.setup_roles()
        self.approve()
        self.crash_at("wolfalibi.byoa_qualification_cli._publish_report")
        first = self.target("recover-read")
        self.assertEqual(first["outcome"], "RECONCILED")
        self.assertFalse(first["redispatched"])
        self.assertEqual(first, self.target("recover-read"))
        retry = self.command("qualify", *self.launch_args(self.root / "retry"), "--consent")
        self.assertEqual(retry["outcome"], "BLOCKED")
        self.assertFalse((self.root / "retry/report.json").is_file())

    def test_partial_and_non_object_documents_fail_closed(self):
        for payload in ("[]", "{", '{"pin":0,"pin":1}'):
            path = self.root / "doc.json"
            path.write_text(payload)
            self.assertEqual(self.command("verify-qualification", "--report", path, "--expect", path)["outcome"], "BLOCKED")

    def test_private_files_never_overwritten_by_provision_or_publication(self):
        self.assertEqual(self.command("provision", "--role", "owner", "--output", self.owner)["outcome"], "PROVISIONED")
        original = (self.owner / "public.json").read_bytes()
        self.assertEqual(self.command("provision", "--role", "owner", "--output", self.owner)["outcome"], "BLOCKED")
        self.assertEqual((self.owner / "public.json").read_bytes(), original)
        self.assertEqual((self.owner / "owner.seed").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            cli._publish_report(self.owner / "public.json", {"unexpected": True})
        self.assertEqual((self.owner / "public.json").read_bytes(), original)
