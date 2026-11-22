# BYOA 002 · control and evidence matrix

Start with a positive control for each layer. The consented local run executes the installed LangChain driver, its selected decision package, a first witnessed broker read, a second owner-target operation and a detached historical check. A verifier that refuses everything cannot pass. Match the refusal, authoritative state and expected branch for each negative test. A setup failure, timeout or exception by itself provides no evidence of an enforced denial. [Exact-tree qualification runner](../scripts/qualify_byoa002.py)

```sh
python -m unittest discover -v
python -m unittest -v test_byoa002_package test_byoa002_transport
python -u mutation_test.py
```

## Signed evidence and runtime identity

| Condition | Named control and authoritative oracle |
| --- | --- |
| Successful historical review and absent current authority | `test_byoa002_package.test_original_verifies_offline_twice_without_dispatch` checks the same historical package twice with detached expectations. No dispatching process is needed. The result concerns the signed commitment and gives no present capability. |
| Replacement of trust inputs or selected agent | `test_package_has_no_source_of_trust_for_itself`, `test_all_external_role_pins_must_match`, `test_source_revision_is_bound_to_the_enrolled_challenge` and `test_replacing_measured_trial_fails_even_with_authentic_002_records` compare independently supplied pins, exact source revision and original signed 001 evidence. |
| Unsigned claims, missing or altered record, stale reference | `test_each_signed_component_is_mandatory`, `test_added_unsigned_claim_in_any_component_is_refused`, `test_signed_event_must_match_externally_retained_history` and `test_external_generation_is_an_exact_integer` exercise the offline verifier. Success requires the owner-target commitment and verifier acknowledgment against the exact retained head. |
| Operator-provided observations | `test_operator_observations_remain_attributed_statements`, `test_unsigned_observations_cannot_be_inserted_into_the_verified_package` and `test_observation_signature_cannot_be_detached_from_its_operator_or_package` check the detached operator statement. A valid evidence package does not independently attest the truth of operator counters. |
| Live gateway identity, process substitution, source or target pin mismatch | `test_byoa002_transport.test_kernel_enrolled_gateway_and_true_restart_on_ambiguous_delivery` and `test_wrong_live_source_and_target_pin_are_refused_before_effect` use real Unix peers. The transport test target counts arrivals at its protected methods. Its counter measures transport admission to a recording fixture. Actual target ledger and receipt evidence comes from the end-to-end run. |
| Actual gateway exclusion from owner credentials and ledger | `test_same_uid_is_unsupported_for_owned_files_without_open_attempts` records the absence of a valid cross-UID test on this host. Independent positives require an owner-signed inventory pinned to the actual target and gateway and four kernel open results for the protected files. Access through unauthorized UIDs must leave the owner's commitment count unchanged. No such cross-UID result was established here. |

## Inherited cell controls reproduced on the exact revision

| Boundary | Named test and authoritative oracle |
| --- | --- |
| Source mutation after approval, missing supervision or missing callback | `test_byoa001_cell.test_changed_source_approval_is_refused_before_launcher`, `test_missing_required_measurement_blocks_before_admission_and_read` and `test_missing_observation_prevents_seal_even_when_worker_exited` inspect the actual launch/read boundary and absence of a terminal report. `test_real_selected_python_callback_runs_in_measured_cell` provides the authorized control. |
| Direct protected-file access, attempted network, fork/exec, descriptors and mounts | `test_byoa_solitary.test_live_worker_admission_and_signed_observations_are_distinct` checks required worker-reported controls and supervisor measurements. `test_stage35_measurement.test_two_declared_paths_with_kernel_observations_and_pinned_signatures` and `test_extra_alias_and_single_path_permissions_block_layout` add the separate two-path fixture. Record the kernel-sampled device/inode and process facts separately from worker-supplied errno. The positive broker read and scratch access show this fixture can make permitted progress. |
| Runtime witness omitted, signed aggregate or supervisor claims inflated | `test_byoa001_attestation.test_missing_inner_supervisor_or_target_cannot_be_replaced_by_outer_signature`, `test_unsigned_replacement_of_aggregate_fails` and `test_incomplete_record_or_claim_inflation_is_refused_even_with_supervisor_endorsement` compare distinct signing domains, expected profile and required terminal evidence. |
| Worker/CLI interruption and publication | `test_byoa001_cell.test_worker_death_after_read_wal_before_data_has_no_terminal_receipt`, `test_byoa001_cli.test_interruption_after_reservation_burns_attempt_without_read` and `test_interruption_after_fresh_acceptance_recovers_only_admission` distinguish a durable first admission, broker WAL, challenge reservation, acceptance and terminal publication. |


## Owner decisions, fresh verifier state and recovery

The target tests use a measured 001 report and synthetic peer records to isolate owner policy, the authoritative SQL ledger and verifier callbacks. The transport suite tests kernel peers independently. The demonstration combines these paths under the one authorized account.

| Boundary | Named control and authoritative oracle |
| --- | --- |
| Independent challenge choice, consumed nonce and stale head | `test_byoa002_verifier.test_verifier_rejects_an_unreserved_pair`, `test_issue_persists_unique_run_and_nonce_across_restart`, `test_competing_submissions_are_serialized_across_connections` and `test_stale_issued_head_cannot_advance_and_fresh_successor_can` inspect verifier state and original acknowledgment. A fresh successor supplies the positive control. |
| Owner-key substitution, wrong operator/epoch, wrong gateway or missing trial | `test_byoa002_target.test_positive_commits_one_retained_target_record`, `test_owner_signature_alternative_key_is_refused`, `test_missing_trial_or_different_operator_and_policy_are_denied` and `test_unenrolled_gateway_and_nonlive_sender_cannot_commit` compare release bodies and target effect count. |
| Grant expiry, revocation and time | `test_revoked_before_dispatch_and_after_restart_stays_denied`, `test_revocation_while_verifier_retains_withholds_body`, `test_narrower_owner_expiration_while_qualification_current` and `test_expiration_then_target_clock_rollback_stays_blocked` exercise grant authority at different decision boundaries. The in-process revocation control checks the committed ledger and withheld response. `test_target_future_commitment_and_early_verifier_signature_are_refused` checks conflicting signed timestamps. |
| Duplicate, simultaneous and replacement requests | `test_duplicate_dispatch_withholds_record`, `test_simultaneous_dispatch_has_one_commit_and_one_handoff` and `test_lost_reply_restart_recovers_only_original_receipt` inspect receipt/ack, stable target count and response body. |
| Authenticated verifier link | In `test_byoa002_exchange`, `test_pinned_query_and_reply_bind_the_request`, `test_wrong_target_or_enrollment_never_reaches_store`, `test_replayed_signed_witness_reply_cannot_approve_new_query` and `test_unavailable_store_cannot_supply_positive_response` check use of the pinned target, fresh signed query and matching signed answer. |
| Missing witness and false acknowledgment | `test_missing_witness_before_dispatch_refuses_commit`, `test_target_commit_before_retention_withholds_body`, `test_corrupt_verifier_ack_cannot_release` and `test_ack_requires_exact_retained_receipt` distinguish an absent commitment from an unacknowledged decision whose SQL row survives. |
| Process death before or after commit | `test_process_death_before_sql_commit_rolls_back_decision` and `test_process_death_after_sql_commit_before_anchor_is_fail_stop` kill a target process on either side of SQL COMMIT. Respectively zero rows or one committed row with blocked reopen survive. The verifier head stays unchanged in both. `test_committed_but_uncheckpointed_acceptance_is_fail_stop` checks the verifier's distinct publication boundary. |
| Old database or jointly restored stores | `test_target_ledger_restore_without_checkpoint_is_fenced`, `test_target_and_checkpoint_restore_still_need_live_pending_verifier`, `test_db_rollback_and_joint_rollback_have_distinct_retention_limits` and `test_checkpoint_absence_is_an_availability_failure` compare each store with surviving external references. |

In `test_joint_store_restore_requires_a_separately_retained_head`, a cold restart after a complete rollback of both authorities without the separately retained newest head produced a second body for the original packet. Only one commitment remained visible in the restored lineage. Supplying the previously retained head refused that restored state. The unpinned replay is an observed failure of local custody.

A new source mutation counts only when the designated assertion fails on the altered copy and passes on the original. `test_byoa002_qualification.test_crash_skip_or_wrong_module_never_counts` and `test_unchanged_or_preexisting_failures_are_not_mutation_detections` check this distinction.

## Five verdicts for this host

| Gate | Scope of the verdict |
| --- | --- |
| A · Measured agent | `PASS` requires the installed SDK to drive the selected authorized function, a successful measured 001 cell and a checked report. The framework remains outside that measured cell. |
| B · Principal separation | `UNSUPPORTED` for independently administered gateway/owner custody. The local positive controls use one UID. |
| C · Independent verifier and history custody | `UNSUPPORTED`. A reviewer can verify historical evidence against preselected pins. This host supplies no independently administered verifier and retained store. |
| D · Recovery and rollback | `CONDITIONAL` on the tested local transactions, surviving references, clock and failure points. Original commitment and historical reconciliation cannot attest recipient delivery. |
| E · Qualification readiness | `BLOCKED` for production, arbitrary-agent confinement and formal qualification. Certification is `NOT_ISSUED`. |

[Operator procedure](QUORVANE_BYOA_002.md) · [Trust and recovery assumptions](QUORVANE_BYOA_002_BOUNDARY.md)
