# GitHub Repository Security Operations — Operator Checklist

This file is an **operator checklist**, not proof that GitHub settings have been activated. No enforcement is established by documentation or CODEOWNERS alone. Apply settings through the repository Settings UI, then verify each rule and a disposable negative-control attempt. Preserve all existing PR heads, commits and evidence hashes.

## Priorities

### P0 — Secure the default branch and published research refs

1. In **Settings → Rules → Rulesets**, create an **active branch ruleset** for the default branch \`main\`: block force pushes, restrict deletions, require a pull request before updates/merge, and require conversation resolution when available. Configure administrator bypass explicitly; avoid weakening an accidental protective gate silently.
2. A single-owner repository generally cannot approve its own PR. Do not set required external approvals or code-owner approval until an independent trusted reviewer exists. Until then use an auditable PR gate with zero required approvals, and do not merge without a human review of the exact tree. Later use at least one independent reviewer and enable code-owner reviews.
3. Add an **active branch ruleset targeting all existing and future branches** to block non-fast-forward (force) pushes and branch deletion. Do not require a PR for each *feature branch*: Codex and the owner's ordinary fast-forward commits must keep working. When a published research head is formally frozen, a separately targeted restrict-updates rule can pin that ref, with only controlled bypasses. A SHA alone is an immutable content identifier, but a moving/deleted branch changes discoverability.
4. Verify via GitHub branch metadata and rulesets API that \`main\` and protected published refs report protections active. Save dated screenshots or JSON of the actual settings, not merely a policy declaration. Do not rewrite or delete existing PR refs to test this.
5. Leave merge, release, deploy and paid workflow activation disabled until explicitly approved.

### P0 — Credentials and contributor ingress

1. Review the repo's **Settings → Collaborators / Manage access** and remove any account or GitHub App with unnecessary write/admin access. Record who has access through a private channel; avoid publishing personally identifying account lists.
2. Under **Settings → Security and analysis / Advanced Security**, verify and enable available secret-scanning alerts and push protection. Review reported leaks privately. Revoke/rotate any real exposed secret; removing a commit or adding \`.gitignore\` alone does not invalidate a leaked credential.
3. Review all accessible **branches and Git history**, not just \`main\`, for credentials, private keys, pasted bearer tokens, hidden configuration, PR attachments and executable dependency/installation changes. Do not paste secrets into public reports or logs.
4. Require strong authentication (passkey/security key + 2FA) for maintainers, review personal access tokens and SSH keys, and restrict tokens/apps to the least permission needed. These account-level settings cannot be verified by a repository file.
5. Enable GitHub **private vulnerability reporting** before requesting confidential external security disclosures. Keep public issue submissions strictly synthetic and redacted.

### P1 — Budget-aware automation and supply chain

1. Under **Settings → Actions → General**, prefer GitHub Actions **disabled** if paid CI is not authorized. If needed later, choose explicitly allowed actions, minimum \`GITHUB_TOKEN\` read permissions, no secret access in fork PRs, and required review for outside-contributor workflows. Do not blindly trust \`pull_request_target\` checkouts or execute contributed PR code with credentials.
2. Inspect changes to \`.github/workflows/**\`, \`AGENTS.md\`, \`CODEX_MISSION.md\`, build scripts, Python dependencies, distribution archives and signature-verification code as high-risk, untrusted modifications. Issue comments and PR descriptions can contain prompt injection. Do not grant such text authority over agent/tool behavior.
3. Do not add CI workflows or paid scan automation to satisfy this checklist. Run local qualification offline on a disposable, unprivileged environment and record exact SHA/tree.
4. Export verified external checksums for release candidate archives. Avoid self-authenticating a ZIP exclusively with a checksum inside that same ZIP.

### P1 — Monitoring and response

- Observe **GitHub API events that are actually available**: changed branch tips, new/updated PRs, actor names associated with GitHub events, unexpected workflow files, releases, new third-party contributions, and changed artifact digests. Keep time/URL/commit hashes and observations without unsupported guesses about intent.
- A public repository's viewer/clone traffic is aggregate; there is no dependable identity feed for anonymous readers or anonymous cloners. Never claim an IP or agent identity based on a visit.
- A failed or surprising synthetic test is not proof of an intruder. Classify signals as \`OBSERVED\`, \`SUSPICIOUS_UNCONFIRMED\`, \`VERIFIED_POLICY_VIOLATION\`, or \`UNSUPPORTED\`. Require evidence and independent review.
- Keep monitoring reports private by default, avoid logging raw tokens or private record contents, minimize retention and redact before sharing. Only instrument systems you control with consent; never add covert tracking pixels or network beacons to an offline public lab.

## Recheck after settings changes

- Branch endpoint reports \`protected: true\` for \`main\` and the intended rule-covered branches, and the rulesets endpoint displays active matching rules.
- A controlled, authorized **disposable** branch demonstrates that forbidden force push/deletion is blocked. Do not risk a production or published branch.
- PRs from outside contributors cannot run secrets-bearing workflows; code and instructions are reviewed before running.
- Existing exact review artifacts remain byte-for-byte unchanged, including the PR #35 and PR #36 archive digests.
- Security report intake and evidence handling have an approved private channel.

**Current research assurance does not change by enabling GitHub settings:** \`SIMULATED_POLICY_ONLY\`; cross-UID custody \`UNSUPPORTED\`; production/confinement \`BLOCKED\`; certification \`NOT_ISSUED\`.
