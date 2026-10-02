# KonnaxionDiag v4.2 — Validation report

Date: 2026-10-02

## Current v4.2 suite

Executed from the packaged v4.2 source:

```text
26 passed
```

Coverage includes the historical v4.1 regression set plus new v4.2 checks for:

- exact ReleaseSet construction;
- artifact-byte changes modifying `release_set_digest`;
- evidence changes modifying only `security_evidence_set_digest`;
- universal attestation signature/domain/subject binding;
- SEC-registry ingestion of universal attestations;
- PEP denial on authorization tampering;
- PEP denial on ReleaseSet mismatch/tampering;
- PEP denial after authorization expiry;
- signed RiskAcceptance release/finding binding and requester/approver separation.

## Static validation

The full Python tree is compiled with `compileall` as part of packaging validation. CLI smoke checks cover `--version`, `--help`, `sign-attestation`, `verify-attestation` argument registration and `verify-admission` registration.

## Important boundary

The Konnaxion Agent / Capsule Manager source is **not present in this KonnaxionDiag package**. Consequently, v4.2 implements and tests the PEP verifier contract but does not claim that the external Agent's current `handle_instance_start()` has already been patched.

`docs/KX_AGENT_PEP_INTEGRATION.md` specifies the required P0 Agent-side regression tests and integration contract.

## Historical baselines

The earlier v4.1 package recorded 20 passing KonnaxionDiag tests and a 46-test migrated legacy-domain sample. Those historical numbers are retained in the v4.1 changelog/report but were not re-run as separate external suites during this v4.2 packaging pass.
