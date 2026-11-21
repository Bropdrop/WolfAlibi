"""Experimental WolfAlibi extension interfaces.

The original ``alibi.py`` API remains the compatibility surface.  This package
contains optional receipt, isolation, and adapter layers; none silently turns
broker-scoped evidence into a universal nonaccess claim.
"""

from .receipts import (EvidenceRun, RECEIPT_TYPE, RECEIPT_TYPE_V1,
                       RECEIPT_TYPE_V2, RECEIPT_VERSION_V1,
                       RECEIPT_VERSION_V2, ReceiptError, policy_digest,
                       sha256_file, verify_negative_access_receipt)

__all__ = [
    "EvidenceRun", "RECEIPT_TYPE", "RECEIPT_TYPE_V1", "RECEIPT_TYPE_V2",
    "RECEIPT_VERSION_V1", "RECEIPT_VERSION_V2", "ReceiptError",
    "policy_digest", "sha256_file", "verify_negative_access_receipt",
]
