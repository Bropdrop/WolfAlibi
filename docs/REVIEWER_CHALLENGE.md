# WolfAlibi: an open engineering challenge

**Can you prove a negative without trusting the system that tells you it happened?**

WolfAlibi explores a privacy-conscious way to verify that a software agent **did not access certain resources within a specified mediated environment**.

A broker emits an event commitment; a witness cosigns; a short nonmembership proof can be verified without revealing the full event log. That part is promising. But a perfectly signed incomplete event set is still an incomplete event set.

We invite systems engineers, cryptographers, formal-methods researchers, Linux security specialists, and testing practitioners to challenge the *missing assumptions*, not simply admire the signatures.

### Challenge A — Prove event completeness

Can a live process bypass the declared broker via subprocesses, shared memory, descriptors, race conditions or other unintended routes? Present a local synthetic reproducer against the **declared** confinement model and an analysis of its actual coverage. No third-party systems.

### Challenge B — Define the time interval

What exactly counts as "during the run"? Define a linearization point for mediated reads and effects; show a design that remains sound when an operation begins before sealing and finishes afterward. Show how you establish quiescence.

### Challenge C — Make the journal honest after a crash

Explore short writes, torn headers, disk-full errors, fsync failures, process crashes, resource exhaustion and restoration. A released read must not disappear from later claimed history.

### Challenge D — Challenge witness independence

A witness can verify a supplied tree but cannot necessarily know which events were omitted. Propose evidence or threat assumptions that make a witness genuinely informative. Address state loss, rollback, key reuse, collusion and recovery.

### Challenge E — Review the negative proof

Is Merkle nonmembership sound when keys are binary, the trie ordering is malformed, duplicate leaves are injected, or the verifier accepts oddly encoded indices? Try property testing, mutation tests and alternative independent implementations.

### Challenge F — Protect the absence proof's privacy

Neighbor leaves, event counts, file names and stable public keys may reveal information. Measure the leakage and propose a practical improvement, but don't trade away simple verifiability without evidence.

### Challenge G — Bind the claim to the job

Prove that a valid receipt for an earlier safe run, different policy, different directory, or unrelated sandbox cannot be replayed as the result of the verifier's fresh task. Specify an offline-verifiable challenge/response schema.

## Submission protocol

Provide an exact git SHA, a minimum executable synthetic fixture, expected vs observed behavior, and a corrected claim or implementation. A useful review can conclude that a proof is **BLOCKED**—that is a successful finding.

Reviewers should first read [CONTRIBUTING](../CONTRIBUTING.md), [THREAT_MODEL](THREAT_MODEL.md), [CLAIMS_AND_EVIDENCE](CLAIMS_AND_EVIDENCE.md) and [TEST_MATRIX](TEST_MATRIX.md).

**We are not recruiting researchers to test real companies, banks, health systems or government infrastructure.** Only local authorized environments and synthetic data are in scope.

## The north star

A powerful AI should not merely *assert* that it respected a boundary. A verifier should be able to check the scope, witnesses, time coverage, authorization and the limits of what is actually demonstrated.

Build the counterexample that forces us to make the claim more truthful.
