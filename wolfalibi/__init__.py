"""Experimental WolfAlibi extension interfaces.

The original ``alibi.py`` API remains the compatibility surface.  This package
contains optional receipt, isolation, and adapter layers; none silently turns
broker-scoped evidence into a universal nonaccess claim.
"""

from .receipts import (EvidenceRun, RECEIPT_TYPE, ReceiptError,
                       policy_digest, sha256_file, verify_negative_access_receipt)

__all__ = [
    "EvidenceRun", "RECEIPT_TYPE", "ReceiptError", "policy_digest",
    "sha256_file", "verify_negative_access_receipt",
]
