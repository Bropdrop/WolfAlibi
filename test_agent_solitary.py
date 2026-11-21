"""Qualify the fixed Stage 5 adapter using only local synthetic fixtures."""

from copy import deepcopy
import json
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import Mock, patch

from alibi import Broker, DurableWitness, H, Signer, canon
from wolfalibi import agent_solitary, stage3, stage35_measure
from wolfalibi.agent_probe import AgentProbe, SCHEMA as OBSERVATION_SCHEMA
from wolfalibi.agent_solitary import agent_solitary_contract, run_agent_solitary
from wolfalibi.agent_solitary_observation import parse_observation
from wolfalibi.agent_solitary_worker import OBSERVATION_PREFIX, agent_worker_profile
from wolfalibi.clearance import ClearanceGateway
from wolfalibi.clearance_records import grant, identity_pins, revoke, sign_request, verify_decision
from wolfalibi.solitary import solitary_contract
from wolfalibi.solitary_evidence import verify_solitary
from wolfalibi.stage35_verifier import VerifierStore
from wolfalibi.stage3_worker import UnsupportedWorker


class AgentSolitaryObservationTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(socket, "SO_PASSCRED"), "requires Linux packet markers")
    def test_closed_seqpacket_distinguishes_an_empty_record_from_eof(self):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with receiver, sender:
            sender.send(b"")
            sender.close()
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            deadline = time.monotonic() + 1
            with self.assertRaisesRegex(stage3.TrialBlocked, "empty packet"):
                stage3._receive_closed(receiver, deadline)
            self.assertEqual(stage3._receive_closed(receiver, deadline), b"")

    def test_parser_rejects_incomplete_or_nonaggregate_observations(self):
        with AgentProbe(consent=True) as probe:
            probe.wrap(lambda: None, surface="filesystem", operation="read")()
        summary = probe.summary()
        def packet(aggregate):
            return {"type": "agent-observation", "summary": aggregate}

        self.assertEqual(parse_observation(canon(packet(summary)))["outcome"], "OBSERVED")
        self.assertEqual(parse_observation(b"")["outcome"], "UNAVAILABLE")
        for label, changed in (
            ("missing", {k: v for k, v in summary.items() if k != "counts"}),
            ("incomplete", dict(summary, complete_wrapped_calls=False, inflight=1)),
            ("forged coverage", dict(summary, assurance="BROKER_ONLY")),
            ("forged counter", dict(summary, counts={"filesystem.read.success": 2})),
            ("raw value", dict(summary, prompt="synthetic input not approved for export")),
        ):
            with self.subTest(label=label):
                rejected = parse_observation(canon(packet(changed)))
                self.assertEqual(rejected["outcome"], "REJECTED")
                self.assertNotIn("summary", rejected)
        noncanonical = parse_observation(json.dumps(packet(summary), sort_keys=True).encode())
        self.assertEqual(noncanonical["outcome"], "REJECTED")


class AgentSolitaryTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory(prefix="wolfalibi-agent-solitary-")
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.now = int(time.time())
        self.broker = Signer()
        self.supervisor = Signer()
        self.witness = DurableWitness(self.state / "witness.json", Signer())
        self.addCleanup(self.witness.close)
        self.initial = self.witness.state_digest
        try:
            self.contract = agent_solitary_contract(
                "synthetic-agent-solitary", bytes(range(32)), self.now + 120,
            )
        except UnsupportedWorker as exc:
            # Dynamic launch and measurement failures remain test failures.
            self.skipTest(f"UNSUPPORTED static Stage 5 prerequisite: {exc}")

    def _run(self, *, contract=None):
        return run_agent_solitary(
            self.state, contract=self.contract if contract is None else contract,
            signer=self.broker, witness=self.witness, supervisor=self.supervisor,
            expected_witness_state_digest=self.initial,
        )

    def _accept(self, result):
        self.assertEqual(result["outcome"], "COMPLETED", result)
        observation = result["observation"]
        self.assertEqual(observation["outcome"], "OBSERVED")
        self.assertEqual(observation["assurance"], "OBSERVATIONAL_ONLY")
        summary = observation["summary"]
        self.assertEqual(summary["schema"], OBSERVATION_SCHEMA)
        self.assertEqual(summary["assurance"], "OBSERVATIONAL_ONLY")
        self.assertEqual(summary["coverage"], "EXPLICITLY_WRAPPED_CALLS_ONLY")
        self.assertTrue(summary["complete_wrapped_calls"])
        self.assertEqual(summary["events"], 1)
        self.assertEqual(summary["inflight"], 0)
        self.assertEqual(summary["manual_events"], 0)
        self.assertEqual(summary["counts"], {"filesystem.read.success": 1})
        self.assertFalse(summary["nonaccess_proof"])
        self.assertFalse(summary["network_upload"])
        self.assertNotIn(stage3.FIXTURE_KEY, json.dumps(observation))
        self.assertNotIn(stage3.FIXTURE_BYTES.decode().strip(), json.dumps(observation))
        self.assertNotIn(self.contract["challenge"], json.dumps(observation))
        return result["envelope"]

    def _verify(self, envelope, *, contract=None):
        return verify_solitary(
            envelope, contract=self.contract if contract is None else contract,
            broker_pub=self.broker.pub, witness_pub=self.witness.signer.pub,
            supervisor_pub=self.supervisor.pub, expected_witness_state_digest=self.initial,
            now=self.now,
        )

    def test_live_agent_probe_is_separate_from_witnessed_solitary_evidence(self):
        with VerifierStore(
                self.state / "verifier.sqlite",
                bootstrap_heads={self.witness.signer.pub: self.initial}) as verifier:
            issued = verifier.issue(
                contract=self.contract, broker_pub=self.broker.pub,
                witness_pub=self.witness.signer.pub, supervisor_pub=self.supervisor.pub, now=self.now,
            )
            self.assertEqual(issued["outcome"], "ISSUED", issued)
            result = self._run()
            envelope = self._accept(result)
            verified = self._verify(envelope)
            self.assertEqual(verified["outcome"], "VERIFIED", verified)
            self.assertEqual(verified["assurance"], "BROKER_ONLY")
            self.assertEqual(verified["confinement"], "BLOCKED")
            self.assertEqual(verified["witness_state_digest"], self.witness.state_digest.hex())
            self.assertEqual(verified["closure"], {
                "launcher_reaped": True, "worker_pidfd_exited": True,
                "peer_hangup": True, "broker_drained": True,
            })
            self.assertEqual(envelope["evidence"]["payload"]["observations"]["response_sha256"],
                             H(stage3.FIXTURE_BYTES).hex())
            self.assertEqual(set(envelope), {"evidence", "supervisor_record"})
            self.assertEqual(verified["worker_self_report"], {
                "ambient_canary_absent": True,
                "scratch_roundtrip": True,
                "file_size_cap_enforced": True,
                "new_socket_denied": True,
                "fork_denied": True,
                "protected_write_denied": True,
                "exec_denied": True,
                "address_space_cap_enforced": True,
                "descriptor_cap_enforced": True,
            })
            accepted = verifier.accept(
                envelope["evidence"], challenge=self.contract["challenge"],
                supervisor_record=envelope["supervisor_record"], now=self.now,
            )
            self.assertEqual(accepted["outcome"], "VERIFIED", accepted)
            self.assertEqual(verifier.head(self.witness.signer.pub), self.witness.state_digest)
            replay = verifier.accept(
                envelope["evidence"], challenge=self.contract["challenge"],
                supervisor_record=envelope["supervisor_record"], now=self.now,
            )
            self.assertEqual(replay["outcome"], "REJECTED", replay)

    def test_wrong_profile_does_not_qualify_and_legacy_expectations_refuse_stage5(self):
        altered = deepcopy(self.contract)
        altered["profile"]["agent_adapter"]["probe_sha256"] = "ff" * 32
        refused = self._run(contract=altered)
        self.assertIn(refused["outcome"], ("BLOCKED", "REJECTED"), refused)
        self.assertNotIn("envelope", refused)
        self.assertEqual(self.witness.state_digest, self.initial)

        legacy = solitary_contract(self.contract["run_id"], bytes.fromhex(self.contract["challenge"]),
                                   self.contract["expires_at"])
        refused = self._run(contract=legacy)
        self.assertIn(refused["outcome"], ("BLOCKED", "REJECTED"), refused)
        self.assertNotIn("envelope", refused)
        self.assertNotIn("observation", refused)
        result = self._run()
        envelope = self._accept(result)
        self.assertIn(self._verify(envelope, contract=legacy)["outcome"], ("REJECTED", "BLOCKED"))
        self.assertIn(self._verify(envelope, contract=altered)["outcome"], ("REJECTED", "BLOCKED"))

    def test_observation_parse_failure_keeps_independent_broker_evidence(self):
        def omit_required_counter(raw):
            if raw:
                packet = json.loads(raw)
                del packet["summary"]["counts"]
                raw = canon(packet)
            return parse_observation(raw)

        with patch.object(agent_solitary, "parse_observation", side_effect=omit_required_counter) as parse:
            result = self._run()
        self.assertEqual([bool(call.args[0]) for call in parse.call_args_list], [False, True])
        self.assertEqual(result["outcome"], "COMPLETED", result)
        self.assertEqual(result["observation"]["outcome"], "REJECTED")
        self.assertNotIn("summary", result["observation"])
        self.assertEqual(result["observation"]["assurance"], "OBSERVATIONAL_ONLY")
        verified = self._verify(result["envelope"])
        self.assertEqual(verified["outcome"], "VERIFIED", verified)
        self.assertEqual(verified["assurance"], "BROKER_ONLY")
        self.assertEqual(self.witness.state_anchor()["anchor"]["generation"], 3)

    def _replace_observation_frame(self, replacement):
        receive = stage3._receive_closed
        replacement_count = 0

        def receive_fault(channel, deadline):
            nonlocal replacement_count
            packet = receive(channel, deadline)
            if packet.startswith(OBSERVATION_PREFIX):
                replacement_count += 1
                return replacement
            return packet

        with patch.object(stage3, "_receive_closed", side_effect=receive_fault):
            result = self._run()
        self.assertEqual(replacement_count, 1)
        return result

    def test_missing_optional_observation_leaves_terminal_broker_evidence(self):
        result = self._replace_observation_frame(b"")
        self.assertEqual(result["outcome"], "COMPLETED", result)
        observation = result["observation"]
        self.assertEqual(observation["outcome"], "UNAVAILABLE")
        self.assertEqual(observation["assurance"], "OBSERVATIONAL_ONLY")
        self.assertNotIn("summary", observation)
        self.assertEqual(self._verify(result["envelope"])["outcome"], "VERIFIED")

    def test_wrong_observation_frame_blocks_entire_trial(self):
        result = self._replace_observation_frame(b"synthetic malformed transport record")
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertNotIn("observation", result)
        self.assertNotIn("envelope", result)
        self.assertEqual(self.witness.state_anchor()["anchor"]["generation"], 1)

    def test_measured_executable_mismatch_blocks_before_protected_read(self):
        read_executable = stage35_measure._proc_executable

        def mismatched_executable(*args, **kwargs):
            executable, invocation = read_executable(*args, **kwargs)
            return {**executable, "sha256": "ff" * 32}, invocation

        with patch.object(stage35_measure, "_proc_executable", side_effect=mismatched_executable), \
                patch.object(stage3, "_send", wraps=stage3._send) as send:
            result = self._run()
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertIn("observed executable or command line", result["reason"])
        self.assertNotIn("envelope", result)
        send.assert_not_called()
        self.assertEqual(self.witness.state_anchor()["anchor"]["generation"], 1)

    def test_interrupted_wal_before_release_yields_neither_terminal_artifact(self):
        jwrite = Broker._jwrite

        def interrupt(broker, record):
            if record.get("t") == "e" and record.get("seq") == 2:
                raise OSError("synthetic Stage 5 read WAL interruption")
            return jwrite(broker, record)

        with patch.object(Broker, "_jwrite", interrupt), \
                patch.object(stage3, "_send", wraps=stage3._send) as send:
            result = self._run()
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertIn("synthetic Stage 5 read WAL interruption", result["reason"])
        self.assertNotIn("envelope", result)
        self.assertNotIn("observation", result)
        send.assert_not_called()
        self.assertEqual(self.witness.state_anchor()["anchor"]["generation"], 1)

    def test_interrupted_reply_preserves_unsealed_read_and_cannot_replay(self):
        with patch.object(stage3, "_send", side_effect=BrokenPipeError(
                "synthetic Stage 5 worker disconnect")) as send:
            result = self._run()
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertNotIn("envelope", result)
        self.assertNotIn("observation", result)
        send.assert_called_once()
        self.assertEqual(self.witness.state_anchor()["anchor"]["generation"], 1)
        run_dir = Path(result["run_dir"])
        with Broker(run_dir / "resources", self.broker, self.witness,
                    journal=run_dir / "broker.wal") as recovered:
            self.assertEqual(recovered.seq, 2)
            self.assertEqual(list(recovered.sealed), [0])
            self.assertIn(stage3.FIXTURE_KEY.encode(), recovered.cur)
        replay = self._run()
        self.assertEqual(replay["outcome"], "BLOCKED", replay)
        self.assertNotIn("envelope", replay)

    def _clearance_fixture(self):
        gateway_root = self.state / "gateway"
        gateway_root.mkdir(mode=0o700)
        self.gateway_signer, self.owner, self.agent = Signer(), Signer(), Signer()
        identity = identity_pins(agent_worker_profile())
        self.credential = b"synthetic credential held by gateway only"
        self.upstream_result = b"synthetic protected clearance result"
        self.upstream = Mock(return_value=self.upstream_result)
        return ClearanceGateway(
            gateway_root, signer=self.gateway_signer, owner_pub=self.owner.pub,
            broker_pub=self.broker.pub, witness_pub=self.witness.signer.pub,
            supervisor_pub=self.supervisor.pub, expected_witness_state_digest=self.initial,
            observe_witness_head=lambda: self.witness.state_digest,
            observe_identity=lambda _: identity, upstream=self.upstream,
            upstream_credential=self.credential, clock=lambda: self.now,
        )

    def _clearance_admit(self, gateway):
        issued = gateway.prepare("synthetic-agent-clearance", agent_pub=self.agent.pub,
                                 profile="solitary-python-callback")
        self.assertEqual(issued["outcome"], "ISSUED", issued)
        contract = issued["contract"]
        self.contract = contract
        completed = self._run()
        envelope = self._accept(completed)
        challenge = contract["challenge"]
        owner_grant = grant(
            self.owner, scope=issued["scope"], not_before=self.now,
            expires_at=self.now + 60, grant_id="synthetic-stage5-grant",
        )
        for qualification, approval in ((completed["observation"], owner_grant), (envelope, None)):
            denied = gateway.admit(challenge=challenge, envelope=qualification, grant=approval)
            self.assertIn(denied["outcome"], ("DENIED", "BLOCKED"), denied)
            self.assertFalse(denied.get("capability"))
            self.upstream.assert_not_called()
        admitted = gateway.admit(challenge=challenge, envelope=envelope, grant=owner_grant)
        self.assertEqual(admitted["outcome"], "ADMITTED", admitted)
        self.assertEqual(verify_decision(admitted["decision"], self.gateway_signer.pub)["outcome"],
                         "ADMITTED")
        self.upstream.assert_not_called()
        return admitted["capability"]

    def _protected_read(self, gateway, capability):
        return gateway.perform(capability=capability, request=sign_request(
            self.agent, capability=capability, request_id="synthetic-one-read",
        ))

    def test_matching_clearance_qualification_and_grant_release_only_one_stub_read(self):
        with self._clearance_fixture() as gateway:
            capability = self._clearance_admit(gateway)
            allowed = self._protected_read(gateway, capability)
            self.assertEqual(allowed["outcome"], "ALLOWED", allowed)
            self.assertEqual(allowed["data"], self.upstream_result)
            verified = verify_decision(allowed["decision"], self.gateway_signer.pub)
            self.assertEqual(verified["qualification"], "SYNTHETIC_CURRENT")
            self.assertEqual(verified["owner_authorization"], "CURRENT")
            self.assertEqual(verified["effect"], "OBSERVED")
            self.assertEqual(verified["broker_assurance"], "BROKER_ONLY")
            self.assertEqual(verified["production"], "BLOCKED")
            self.upstream.assert_called_once_with(self.credential)
            replay = self._protected_read(gateway, capability)
            self.assertIn(replay["outcome"], ("BLOCKED", "DENIED"), replay)
            self.upstream.assert_called_once_with(self.credential)

    def test_stage5_owner_revocation_fences_admitted_clearance(self):
        with self._clearance_fixture() as gateway:
            capability = self._clearance_admit(gateway)
            revoked = gateway.revoke(revoke(
                self.owner, grant_id="synthetic-stage5-grant", gateway_pub=self.gateway_signer.pub,
            ))
            self.assertEqual(revoked["outcome"], "REVOKED", revoked)
            denied = self._protected_read(gateway, capability)
            self.assertIn(denied["outcome"], ("BLOCKED", "DENIED"), denied)
            self.assertNotIn("data", denied)
            self.upstream.assert_not_called()


if __name__ == "__main__":
    unittest.main()
