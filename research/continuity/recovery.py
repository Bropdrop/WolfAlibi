"""Read-only recovery of a frozen operation through an authenticated TLS session."""

import hashlib
import json
import ssl
import time
from research.blackout.reader import DENIAL
from research.schism.storage import guard
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import sign_record
from research.continuity.history import verify


class FrozenRecovery:
    def __init__(self, roots, package, signing_key):
        self.history = verify(roots, package)
        self.roots = roots
        self.acl = package["journal"]["recovery"]
        self.revocations = package["journal"]["revocations"]
        self.key = signing_key

    def response(self, tls, query, con, paths, pins):
        if (
            not isinstance(tls, ssl.SSLSocket)
            or not tls.server_side
            or tls.context.verify_mode != ssl.CERT_REQUIRED
        ):
            return DENIAL
        principal = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
        if time.time() >= ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"]):
            return DENIAL
        if not isinstance(query, dict) or not isinstance(
            query.get("request_sha256"), str
        ):
            return DENIAL
        binding = self.acl.get(query["request_sha256"])
        if (
            binding is None
            or principal != binding["principal"]
            or query != {k: v for k, v in binding.items() if k != "grant_id"}
        ):
            return DENIAL
        try:
            con.execute("BEGIN")
            guard(con, paths, pins)
            marker = con.execute("SELECT checkpoint FROM control.imported").fetchone()
            if marker[0] != self.roots["checkpoint_sha256"]:
                raise ValueError("checkpoint changed")
            historical = self.history.get(query["operation_id"])
            receipt = None
            if historical and historical["request"] == query["request_sha256"]:
                receipt = json.loads(historical["receipt"])
                outcome = "COMMITTED"
            elif not historical and binding["grant_id"] in self.revocations:
                outcome = "NOT_COMMITTED"
            else:
                outcome = "UNRESOLVED"
        except Exception:
            outcome, receipt = "UNRESOLVED", None
        finally:
            con.rollback()
        return dict(
            receipt=receipt,
            proof=sign_record(
                self.key,
                dict(
                    query,
                    outcome=outcome,
                    schema="wolfalibi.continuity.historical-recovery.v1",
                    authority="READ_ONLY",
                    checkpoint=self.roots["checkpoint_sha256"],
                    receipt_sha256=digest(receipt) if receipt else None,
                ),
            ),
        )
