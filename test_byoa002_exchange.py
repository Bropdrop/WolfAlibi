"""Check witness exchanges against target/verifier pins without issuing a protected effect."""
from unittest import TestCase
from unittest.mock import Mock, patch

from alibi import Signer
from wolfalibi import byoa002_exchange as wire
from wolfalibi.byoa002_enrollment import digest


class ExchangeTests(TestCase):
    def setUp(self):
        self.verifier = Signer()
        self.target = Signer()
        self.enrollment = {"target_pub": self.target.pub.hex(), "verifier_pub": self.verifier.pub.hex()}
        self.store = Mock()
        self.store.check_pending.return_value = {"state": "pending"}
        self.payload = {"action": "pending", "nonce": "ab" * 32, "enrollment_sha256": digest(self.enrollment),
                        "expected": {}, "challenge": {}, "receipt": None}

    def test_pinned_query_and_reply_bind_the_request(self):
        query = wire._signed(self.payload, self.target, wire.QUERY)
        answer = wire.answer_query(query, self.store, self.enrollment, self.verifier)
        verified = wire._verified(answer, self.enrollment["verifier_pub"], wire.ANSWER)
        self.assertEqual(verified, {"query_sha256": digest(query),
                                   "result": {"accepted": True, "value": {"state": "pending"}}})
        self.store.check_pending.assert_called_once_with({}, {})

    def test_wrong_target_or_enrollment_never_reaches_store(self):
        for signer, reference in ((Signer(), digest(self.enrollment)), (self.target, "00" * 32)):
            query = wire._signed(dict(self.payload, enrollment_sha256=reference), signer, wire.QUERY)
            with self.assertRaises(ValueError):
                wire.answer_query(query, self.store, self.enrollment, self.verifier)
        self.assertEqual(self.store.mock_calls, [])

    def test_replayed_signed_witness_reply_cannot_approve_new_query(self):
        old = wire._signed(self.payload, self.target, wire.QUERY)
        reply = wire.answer_query(old, self.store, self.enrollment, self.verifier)
        with patch.object(wire, "validate_enrollment", return_value=self.enrollment):
            client = wire.WitnessConnection("/unused", self.enrollment, self.target)
        with patch.object(wire.socket, "socket"), patch.object(wire, "_send"), patch.object(wire, "_receive", return_value=reply):
            with self.assertRaisesRegex(ValueError, "wrong witness response binding"):
                client.check_pending({}, {})

    def test_unavailable_store_cannot_supply_positive_response(self):
        self.store.check_pending.side_effect = ValueError("prior head disagreement")
        query = wire._signed(self.payload, self.target, wire.QUERY)
        answer = wire.answer_query(query, self.store, self.enrollment, self.verifier)
        self.assertEqual(wire._verified(answer, self.enrollment["verifier_pub"], wire.ANSWER)["result"], {"accepted": False})
