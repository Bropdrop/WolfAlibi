"""Public-handoff checks for VOIDCELL 003 without simulating a second UID.

The tests deliberately do not claim that a same-UID temporary directory is
cross-account custody.  The real owner-init path returns UNSUPPORTED before a
fixed Stage 5 trial when the declared gateway UID is the current target UID.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

from alibi import Signer, canon
from wolfalibi.agent_solitary import agent_solitary_contract
from wolfalibi.voidcell_records import grant, make_scope
from wolfalibi import voidcell003_fixture as fixture


class GatewayReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wolfalibi-voidcell003-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.gateway = self.root / "gateway"
        self.exchange = self.root / "exchange"
        self.gateway.mkdir(mode=0o700)
        self.exchange.mkdir(mode=0o755)
        self.gateway.chmod(0o700)
        self.exchange.chmod(0o755)
        self.reference = self.exchange / "gateway-public.json"

    def test_gateway_init_writes_only_private_seed_and_signed_public_reference(self):
        result = fixture.gateway_init(self.gateway, self.reference)
        self.assertEqual(result["outcome"], "PROVISIONED")
        key = self.gateway / fixture.GATEWAY_KEY_FILE
        self.assertEqual(key.read_bytes().__len__(), 32)
        self.assertEqual(stat.S_IMODE(key.lstat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.reference.lstat().st_mode), 0o644)
        signer = fixture.load_gateway_signer(self.gateway)
        self.assertEqual(signer.pub.hex(), result["gateway_pub"])
        record = json.loads(self.reference.read_bytes())
        payload = fixture.verify_gateway_reference(
            record, expected_gateway_uid=os.geteuid(), expected_gateway_gid=os.getegid(),
            expected_gateway_pub=signer.pub,
        )
        self.assertEqual(payload["gateway_pub"], signer.pub.hex())
        self.assertEqual(fixture.handoff_sha256(record), result["public_ref_sha256"])

    def test_gateway_reference_requires_the_independently_pinned_key_and_identity(self):
        fixture.gateway_init(self.gateway, self.reference)
        signer = fixture.load_gateway_signer(self.gateway)
        record = json.loads(self.reference.read_bytes())
        with self.assertRaisesRegex(fixture.FixtureError, "independently supplied"):
            fixture.verify_gateway_reference(
                record, expected_gateway_uid=os.geteuid(), expected_gateway_gid=os.getegid(),
                expected_gateway_pub=Signer().pub,
            )
        tampered = deepcopy(record)
        tampered["payload"]["gateway_gid"] += 1
        self.reference.write_bytes(canon(tampered))
        with self.assertRaisesRegex(fixture.FixtureError, "differs|signature"):
            fixture.verify_gateway_reference(
                tampered, expected_gateway_uid=os.geteuid(), expected_gateway_gid=os.getegid(),
                expected_gateway_pub=signer.pub,
            )


class OwnerHandoffTests(unittest.TestCase):
    def _material(self):
        now = int(time.time())
        owner, gateway, target, broker, witness, supervisor = (Signer() for _ in range(6))
        expected, terminal = bytes(range(32)), bytes(range(32, 64))
        contract = agent_solitary_contract("fixture-owner-handoff", bytes(reversed(range(32))), now + 60)
        scope = make_scope(
            contract, gateway_pub=gateway.pub, target_pub=target.pub,
            operation_id="fixture-counter", expected_witness_state_digest=expected,
        )
        owner_grant = grant(owner, scope=scope, grant_id="fixture-grant",
                            not_before=now, expires_at=contract["expires_at"])
        target_state = {
            "authority_config_sha256": "ab" * 32,
            "state_device": "11", "state_inode": "12", "state_mode": 0o700,
            "anchor_device": "13", "anchor_inode": "14", "anchor_mode": 0o700,
            "key_mode": 0o600, "ledger_mode": 0o600,
        }
        source = {"commit": "a" * 40, "tree": "b" * 40}
        return {
            "owner": owner, "gateway": gateway, "target": target, "broker": broker,
            "witness": witness, "supervisor": supervisor, "expected": expected,
            "terminal": terminal, "contract": contract, "scope": scope,
            "owner_grant": owner_grant, "target_state": target_state,
            "source": source, "now": now,
        }

    def _record(self, material):
        return fixture.make_owner_handoff(
            material["owner"], source=material["source"], created_at=material["now"],
            gateway_reference_sha256="cd" * 32, gateway_uid=2001, gateway_gid=2001,
            gateway_pub=material["gateway"].pub, target_uid=2002, target_gid=2001,
            target_pub=material["target"].pub, socket_path="/run/user/2002/voidcell003.sock",
            target_state=material["target_state"], contract=material["contract"],
            qualification={"synthetic": "envelope"}, broker_pub=material["broker"].pub,
            witness_pub=material["witness"].pub, supervisor_pub=material["supervisor"].pub,
            expected_witness_state_digest=material["expected"],
            terminal_witness_state_digest=material["terminal"], operation_id="fixture-counter",
            owner_grant=material["owner_grant"],
        )

    def test_signed_handoff_binds_exact_scope_and_historical_issuance_time(self):
        material = self._material()
        verification = {"outcome": "VERIFIED", "witness_state_digest": material["terminal"].hex()}
        with patch.object(fixture, "verify_solitary", return_value=verification):
            record = self._record(material)
            payload = fixture.verify_owner_handoff(
                record, owner_pub=material["owner"].pub,
                expected_sha256=fixture.handoff_sha256(record),
                expected_source_revision=material["source"],
            )
        self.assertEqual(payload["scope"], material["scope"])
        self.assertEqual(payload["initial_witness_head"], material["terminal"].hex())
        self.assertEqual(payload["target_uid"], 2002)
        self.assertEqual(payload["target_gid"], 2001, "shared ordinary GID remains representable")

    def test_even_an_owner_signed_scope_substitution_is_rejected(self):
        material = self._material()
        verification = {"outcome": "VERIFIED", "witness_state_digest": material["terminal"].hex()}
        with patch.object(fixture, "verify_solitary", return_value=verification):
            record = self._record(material)
            substituted = deepcopy(record)
            substituted["payload"]["scope"]["operation_id"] = "other-operation"
            substituted["signature"] = material["owner"].sign(
                fixture.OWNER_HANDOFF_DOMAIN,
                canon({"schema": fixture.OWNER_HANDOFF_SCHEMA, "payload": substituted["payload"]}),
            ).hex()
            with self.assertRaisesRegex(fixture.FixtureError, "scope"):
                fixture.verify_owner_handoff(substituted, owner_pub=material["owner"].pub)

    def test_wrong_external_owner_pin_is_rejected(self):
        material = self._material()
        verification = {"outcome": "VERIFIED", "witness_state_digest": material["terminal"].hex()}
        with patch.object(fixture, "verify_solitary", return_value=verification):
            record = self._record(material)
            with self.assertRaisesRegex(fixture.FixtureError, "signature|pinned"):
                fixture.verify_owner_handoff(record, owner_pub=Signer().pub)


class RolePreflightTests(unittest.TestCase):
    def test_same_uid_is_explicitly_unsupported_not_a_custody_candidate(self):
        result = fixture.split_role_preflight(os.geteuid(), os.getegid())
        self.assertEqual(result["outcome"], "UNSUPPORTED")
        self.assertEqual(result["custody"], "UNSUPPORTED")

    def test_owner_init_stops_before_source_or_stage5_work_when_roles_are_same(self):
        with tempfile.TemporaryDirectory(prefix="wolfalibi-voidcell003-owner-") as root_text:
            root = Path(root_text)
            target, anchor, qualification = (root / name for name in ("target", "anchor", "qualification"))
            exchange, endpoint = root / "exchange", root / "endpoint"
            for path, mode in ((target, 0o700), (anchor, 0o700), (qualification, 0o700),
                               (exchange, 0o755), (endpoint, 0o755)):
                path.mkdir(mode=mode)
                path.chmod(mode)
            gateway = Signer()
            reference = fixture.make_gateway_reference(
                gateway, gateway_uid=os.geteuid(), gateway_gid=os.getegid(),
            )
            reference_path = exchange / "gateway.json"
            reference_path.write_bytes(canon(reference))
            reference_path.chmod(0o644)
            with patch.object(fixture, "source_revision", side_effect=AssertionError("must not be called")):
                result = fixture.owner_init(
                    target_state_dir=target, anchor_dir=anchor, qualification_dir=qualification,
                    gateway_ref=reference_path, handoff=exchange / "owner.json",
                    socket_path=endpoint / "target.sock", consent=True,
                    expected_gateway_uid=os.geteuid(), expected_gateway_gid=os.getegid(),
                    expected_gateway_pub=gateway.pub,
                )
            self.assertEqual(result["outcome"], "UNSUPPORTED")
            self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
