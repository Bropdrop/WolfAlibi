"""Qualify the offline Gate 003 payment-intent service and its historical receipt."""

from qualify_resource_gate import Gate, main


FINANCE = Gate("finance", "003", "6b4eda2f2e80cc02d8e6639e1a093f49e6de6e35", 32,
               322, 35, "intent_count", "HISTORICAL_SYNTHETIC_PAYMENT_INTENT", "PENDING_EXTERNAL_SETTLEMENT")


if __name__ == "__main__":
    raise SystemExit(main(FINANCE, __doc__))
