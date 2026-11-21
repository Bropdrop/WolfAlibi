"""Focused direct-API regressions for the fictional Education admission gate.

These cases intentionally use synthetic keys and the in-process target API.
The separate service suite owns sockets, peer-credential transport and process
delivery demonstrations.
"""

from copy import deepcopy
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from alibi import Signer, canon
from wolfalibi.education_records import digest, dispatch, owner_grant, qualify, verify_receipt
from wolfalibi.education_target import (
    CONFIG_FILE,
    LEDGER_FILE,
    EducationTarget,
    EducationTargetError,
    init_key,
)
from wolfalibi.voidcell002_anchor import AnchorError


def _write_new(path, data):
    """Create one private synthetic fixture file without replacing it."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        if stream.write(data) != len(data):
            raise OSError("short synthetic fixture write")
        stream.flush()
        os.fsync(stream.fileno())


class EducationAdmissionTests(unittest.TestCase):
    """Cryptographic, temporal and durable-state controls without a socket."""

    def setUp(self):
        temporary = TemporaryDirectory(prefix="wolfalibi-education-admission-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "target"
        self.anchor = self.root / "anchor"
        self.control = self.root / "control"
        for directory in (self.state, self.anchor, self.control):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)

        self.now = 1_700_000_000
        self.clock = patch("wolfalibi.education_target._clock_time", side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)

        self.owner, self.supervisor, self.witness, self.caller = (Signer() for _ in range(4))
        self.target_pub = init_key(self.state)
        self.peer = {
            "pid": 7171, "uid": 1000, "gid": 1000, "start_ticks": 123_456,
            "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
            "exe_sha256": "ab" * 32, "argv_sha256": "bc" * 32, "source_sha256": "cd" * 32,
        }
        self.scope = {
            "tenant": "fictional-school", "student": "fictional-aster",
            "purpose": "approved-support", "operation": "edu.student_record.read",
            "target_pub": self.target_pub, "policy_version": "edu-gate-002.v1",
            "run_id": "admission-run", "challenge": "ef" * 32,
            "caller_pub": self.caller.pub.hex(), "request_id": "read-once",
        }
        self.grant_id = "fictional-school-grant"
        self.qualification = self._qualification()
        self.witness_path = self.control / "witness-head"
        _write_new(self.witness_path, digest(self.qualification).encode("ascii"))
        config = {
            "scope": self.scope, "owner_pub": self.owner.pub.hex(),
            "supervisor_pub": self.supervisor.pub.hex(), "witness_pub": self.witness.pub.hex(),
            "peer": self.peer, "witness_head_path": str(self.witness_path),
        }
        _write_new(self.state / CONFIG_FILE, canon(config))
        with EducationTarget(self.state, self.anchor, create=True) as target:
            self.assertEqual(target.status()["outcome"], "READY")
            self.assertEqual(target.target_pub.hex(), self.target_pub)

    def _target(self):
        return EducationTarget(self.state, self.anchor)

    def _grant(self, *, signer=None, scope=None, grant_id=None, start=None, end=None):
        return owner_grant(
            self.owner if signer is None else signer,
            self.scope if scope is None else scope,
            self.grant_id if grant_id is None else grant_id,
            self.now if start is None else start,
            self.now + 90 if end is None else end,
        )

    def _qualification(self, *, supervisor=None, witness=None, scope=None, peer=None, start=None, end=None):
        return qualify(
            self.supervisor if supervisor is None else supervisor,
            self.witness if witness is None else witness,
            self.scope if scope is None else scope,
            self.peer if peer is None else peer,
            self.now if start is None else start,
            self.now + 60 if end is None else end,
        )

    def _packet(self, *, caller=None, scope=None, grant=None, qualification=None):
        scope = self.scope if scope is None else scope
        return dispatch(
            self.caller if caller is None else caller, scope,
            self._grant(scope=scope) if grant is None else grant,
            self.qualification if qualification is None else qualification,
        )

    def _denied(self, result, reason=None):
        self.assertIn(result["outcome"], {"DENIED", "BLOCKED"}, result)
        if reason is not None:
            self.assertEqual(result.get("reason"), reason, result)
        self.assertNotIn("response", result, result)
        self.assertNotIn("receipt", result, result)

    def _released(self, target, packet):
        result = target.handle("read", packet, target.peer)
        self.assertEqual(result["outcome"], "RELEASED", result)
        self.assertEqual(result["response"], {
            "student_ref": "fictional-aster", "support_level": "scheduled-check-in",
        })
        verified = verify_receipt(
            result["receipt"], target_pub=target.target_pub, scope=target.scope,
            packet=packet, response=result["response"],
        )
        self.assertEqual(verified["authorized_at"], self.now)
        return result

    def _replace_witness_head(self, qualification):
        data = digest(qualification).encode("ascii")
        flags = os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
        with os.fdopen(os.open(self.witness_path, flags), "wb") as stream:
            if stream.write(data) != len(data):
                raise OSError("short synthetic witness update")
            stream.flush()
            os.fsync(stream.fileno())

    def test_valid_read_has_exact_target_receipt_and_restart_reconciliation(self):
        packet = self._packet()
        with self._target() as target:
            result = self._released(target, packet)
            self.assertEqual(target.status()["release_count"], 1)
        with self._target() as reopened:
            reconciled = reopened.handle("reconcile", packet, reopened.peer)
            self.assertEqual(reconciled["outcome"], "RECONCILED", reconciled)
            self.assertEqual(reconciled["receipt"], result["receipt"])
            self.assertNotIn("response", reconciled)

    def test_forged_owner_grants_are_denied_without_response_or_receipt(self):
        altered = self._grant()
        altered["signature"] = "00" * 64
        foreign = self._grant(signer=Signer())
        with self._target() as target:
            for grant in (altered, foreign):
                with self.subTest(foreign=grant is foreign):
                    self._denied(target.handle("read", self._packet(grant=grant), target.peer),
                                 "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
                    self.assertEqual(target.status()["release_count"], 0)

    def test_scope_substitution_cannot_reuse_authority(self):
        fields = {
            "tenant": "fictional-other-school", "student": "fictional-birch",
            "run_id": "other-run", "challenge": "01" * 32, "request_id": "other-read",
            "target_pub": Signer().pub.hex(), "caller_pub": Signer().pub.hex(),
            "purpose": "other-purpose", "operation": "edu.student_record.write",
            "policy_version": "other-policy",
        }
        packet = self._packet()
        with self._target() as target:
            for field, value in fields.items():
                with self.subTest(field=field):
                    substituted = deepcopy(packet)
                    substituted["scope"][field] = value
                    self._denied(target.handle("read", substituted, target.peer))
                    self.assertEqual(target.status()["release_count"], 0)
            alternate = dict(self.scope, request_id="other-read")
            for changed in (self._packet(grant=self._grant(scope=alternate)),
                            self._packet(qualification=self._qualification(scope=alternate))):
                self._denied(target.handle("read", changed, target.peer),
                             "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
                self.assertEqual(target.status()["release_count"], 0)

    def test_forged_or_replayed_qualification_is_denied(self):
        forged = deepcopy(self.qualification)
        forged["supervisor_signature"] = "00" * 64
        prior = self._qualification(start=self.now - 120, end=self.now - 1)
        foreign = self._qualification(supervisor=Signer())
        with self._target() as target:
            for qualification in (forged, prior, foreign):
                with self.subTest(foreign=qualification is foreign):
                    # Give every hostile record the retained digest it claims;
                    # rejection must still depend on its time/signatures.
                    self._replace_witness_head(qualification)
                    self._denied(target.handle("read", self._packet(qualification=qualification), target.peer),
                                 "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
                    self.assertEqual(target.status()["release_count"], 0)

    def test_tampered_measured_executable_argv_or_source_is_denied(self):
        packet = self._packet()
        with self._target() as target:
            for field in ("exe_sha256", "argv_sha256", "source_sha256"):
                with self.subTest(field=field):
                    peer = dict(target.peer, **{field: "00" * 32})
                    self._denied(target.handle("read", packet, peer), "PEER_MISMATCH")
                    self.assertEqual(target.status()["release_count"], 0)
                    # Even a newly signed qualification cannot substitute a
                    # different measured executable, argv or source digest.
                    qualification = self._qualification(peer=peer)
                    self._replace_witness_head(qualification)
                    self._denied(target.handle("read", self._packet(qualification=qualification), target.peer),
                                 "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
                    self.assertEqual(target.status()["release_count"], 0)

    def test_distinct_caller_and_issuer_roles_are_required(self):
        with self.assertRaises(ValueError):
            self._grant(signer=self.caller)
        with self.assertRaises(ValueError):
            self._qualification(supervisor=self.owner, witness=self.owner)
        with self.assertRaises(ValueError):
            self._qualification(supervisor=self.caller)

    def test_target_refuses_collapsed_configured_issuer_roles_before_ledger_creation(self):
        state = self.root / "duplicate-state"
        anchor = self.root / "duplicate-anchor"
        control = self.root / "duplicate-control"
        for directory in (state, anchor, control):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        target_pub = init_key(state)
        scope = dict(self.scope, target_pub=target_pub, request_id="duplicate-role-read")
        qualification = self._qualification(scope=scope)
        witness = control / "witness-head"
        _write_new(witness, digest(qualification).encode("ascii"))
        config = {
            "scope": scope, "owner_pub": self.owner.pub.hex(),
            "supervisor_pub": self.owner.pub.hex(), "witness_pub": self.witness.pub.hex(),
            "peer": self.peer, "witness_head_path": str(witness),
        }
        _write_new(state / CONFIG_FILE, canon(config))
        with self.assertRaises(EducationTargetError):
            EducationTarget(state, anchor, create=True)
        self.assertFalse((state / LEDGER_FILE).exists())

    def test_receipt_rejects_wrong_signer_body_or_operation(self):
        packet = self._packet()
        with self._target() as target:
            result = self._released(target, packet)
        with self.assertRaises(ValueError):
            verify_receipt(result["receipt"], target_pub=Signer().pub, scope=self.scope,
                           packet=packet, response=result["response"])
        with self.assertRaises(ValueError):
            verify_receipt(result["receipt"], target_pub=bytes.fromhex(self.target_pub), scope=self.scope,
                           packet=packet, response=dict(result["response"], support_level="changed"))
        damaged = deepcopy(result["receipt"])
        damaged["payload"]["request_id"] = "other-read"
        with self.assertRaises(ValueError):
            verify_receipt(damaged, target_pub=bytes.fromhex(self.target_pub), scope=self.scope,
                           packet=packet, response=result["response"])
        with self.assertRaises(ValueError):
            verify_receipt(result["receipt"], target_pub=bytes.fromhex(self.target_pub),
                           scope=dict(self.scope, operation="edu.student_record.write"),
                           packet=packet, response=result["response"])

    def test_target_clock_and_current_windows_control_admission(self):
        future, deadline = self.now + 5, self.now + 10
        grant = self._grant(start=future, end=deadline)
        qualification = self._qualification(start=future, end=deadline)
        self._replace_witness_head(qualification)
        packet = self._packet(grant=grant, qualification=qualification)
        with self._target() as target:
            injected = deepcopy(packet)
            injected["checked_at"] = 0
            self._denied(target.handle("read", injected, target.peer), "INVALID_TARGET_REQUEST")
            self.now = future - 1
            self._denied(target.handle("read", packet, target.peer),
                         "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
            self.now = future
            self._released(target, packet)
            self.assertEqual(target.status()["release_count"], 1)

    def test_precommit_expiry_creates_no_release(self):
        deadline = self.now + 1
        grant = self._grant(end=deadline)
        qualification = self._qualification(end=deadline)
        self._replace_witness_head(qualification)
        packet = self._packet(grant=grant, qualification=qualification)
        with self._target() as target:
            with patch("wolfalibi.education_target._clock_time", side_effect=[self.now, deadline]):
                result = target.handle("read", packet, target.peer)
            self._denied(result, "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
            self.assertEqual(target.status()["release_count"], 0)

    def test_post_checkpoint_expiry_never_hands_off_data(self):
        deadline = self.now + 1
        grant = self._grant(end=deadline)
        qualification = self._qualification(end=deadline)
        self._replace_witness_head(qualification)
        packet = self._packet(grant=grant, qualification=qualification)
        with self._target() as target:
            with patch("wolfalibi.education_target._clock_time", side_effect=[self.now, self.now, deadline]):
                result = target.handle("read", packet, target.peer)
            self._denied(result, "AUTHORIZATION_EXPIRED_BEFORE_HANDOFF")
            self.assertEqual(target.status()["release_count"], 1)

    def test_later_handoff_sample_is_durable_across_restart(self):
        packet = self._packet()
        later = self.now + 1
        with self._target() as target:
            with patch("wolfalibi.education_target._clock_time",
                       side_effect=[self.now, self.now, later, later]):
                self._released(target, packet)
            self.assertEqual(target.status()["release_count"], 1)
        with self._target() as reopened:
            self.now -= 1
            self._denied(reopened.handle("read", packet, reopened.peer), "TARGET_CLOCK_REGRESSION")
            self._denied(reopened.handle("reconcile", packet, reopened.peer), "TARGET_CLOCK_REGRESSION")

    def test_durable_clock_highwater_blocks_backdating_after_restart(self):
        packet = self._packet()
        future = self.now + 100
        with self._target() as target:
            self.now = future
            self._denied(target.handle("read", packet, target.peer),
                         "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
        with self._target() as reopened:
            self.now = future - 1
            self._denied(reopened.handle("read", packet, reopened.peer), "TARGET_CLOCK_REGRESSION")
            self.assertEqual(reopened.status()["release_count"], 0)

    def test_revocation_survives_restart_and_blocks_ambiguous_reconciliation(self):
        packet = self._packet()
        with self._target() as target:
            released = self._released(target, packet)
        with self._target() as reopened:
            self.assertEqual(reopened.revoke(self.grant_id), {"outcome": "REVOKED"})
            self._denied(reopened.handle("reconcile", packet, reopened.peer), "OWNER_GRANT_REVOKED")
            self._denied(reopened.handle("read", packet, reopened.peer), "OWNER_GRANT_REVOKED")
            self.assertEqual(reopened.status()["release_count"], 1)
        self.assertIn("receipt", released)

    def test_older_ledger_snapshot_cannot_replace_retained_checkpoint(self):
        ledger = self.state / LEDGER_FILE
        before = ledger.read_bytes()
        with self._target() as target:
            self._released(target, self._packet())
        retained = (self.anchor / "ledger-anchor.json").read_bytes()
        ledger.write_bytes(before)
        with self.assertRaises(EducationTargetError):
            self._target()
        self.assertEqual((self.anchor / "ledger-anchor.json").read_bytes(), retained)

    def test_commit_before_checkpoint_fault_has_no_outward_release_and_fails_stop(self):
        packet = self._packet()
        with self._target() as target:
            with patch.object(target._anchor, "advance", side_effect=AnchorError("synthetic interruption")):
                result = target.handle("read", packet, target.peer)
            self._denied(result, "TARGET_STATE_UNAVAILABLE")
            self._denied(target.status(), "TARGET_STATE_UNAVAILABLE")
        with self.assertRaises(EducationTargetError):
            self._target()

    def test_revocation_checkpoint_fault_is_ambiguous_but_fails_stop(self):
        with self._target() as target:
            with patch.object(target._anchor, "advance", side_effect=AnchorError("synthetic interruption")):
                result = target.revoke(self.grant_id)
            self._denied(result, "TARGET_STATE_UNAVAILABLE")
            self._denied(target.status(), "TARGET_STATE_UNAVAILABLE")
        with self.assertRaises(EducationTargetError):
            self._target()


if __name__ == "__main__":
    unittest.main()
