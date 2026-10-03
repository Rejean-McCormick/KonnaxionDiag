# Changelog

## 4.2.4 - S04W generated-artifact filtering

- Web Trust source scanning now ignores generated frontend artifact/report directories such as `frontend/artifacts`, Playwright reports, `.next`, coverage, dist/build, and test-results.
- Prevents Playwright trace bundles from being misclassified as authored Konnaxion browser sinks while preserving artifact inspection in the dedicated repository/security hygiene scans.
- Regression coverage verifies that generated trace JavaScript cannot trigger `app.web_trust.browser_sinks`.

## 4.2.3 - Runtime continuation + bounded Web Trust scan

- N05 no longer gets suppressed solely because N03 failed: N00 remains a strict prerequisite, but the frontend build verdict is order-only for N05 so local runtime/HTTP probes can still execute during `release-all`.
- `release-all` still skips Playwright; the dedicated Playwright button/campaign remains explicit.
- S04W now traverses frontend sources through the bounded scanner and honors configured excluded directories such as `node_modules`, `.next`, `artifacts`, coverage and build output.
- Added an explicit Web Trust source-scan coverage finding; hitting the configured file limit fails closed instead of silently truncating the security scan.
- Regression validation: 47 tests pass; S04W scans the Konnaxion snapshot (543 bounded files) in well under one second in the validation environment.

## 4.2.2 - Operator dashboard + compact timestamps

- Human-facing timestamps now render as `[HH:MM]` only; date, seconds and timezone remain only in machine JSON evidence.
- Added a tabbed launcher: Santé générale, Fonctionnel N00-N11, Sécurité S00-S14 and Campagnes.
- Added `Quick test`, `Test All` and separate `Playwright` actions on the first tab.
- Added `health-quick` and `playwright` campaigns; `release-all` retains its configured Playwright skip.
- Added live level status tracking, PASS/WARN/BLOCKED/FAIL counters, campaign progress, persistent global log, evidence/doctor/triage actions.
- Preserved hidden Windows subprocesses, UTF-8 output cleanup and offline security continuation.

## 4.2.1 - Windows log encoding + offline security continuation

- Forced UTF-8 for Python diagnostic children and added robust UTF-8/Windows-codepage decoding for captured subprocess output.
- Stripped ANSI/OSC terminal control sequences from captured command output and requested no-color output from child tools.
- Replaced non-ASCII campaign separators/heartbeats in the live console path with ASCII-safe equivalents, eliminating the visible replacement-character artifacts in normal KonnaxionDiag messages.
- Security remote dependencies S06-S14 now use order-only orchestration where appropriate: an unavailable/disabled VPS no longer cancels downstream levels before they can run their own local/static checks.
- S14 now executes even when prior remote evidence is blocked, so it can emit the real aggregate release-gate finding instead of a synthetic dependency block.
- Dependency-blocked/fail-fast levels are explicitly logged with timestamp and reason instead of silently disappearing from the live sequence.
- Remote readiness is evaluated before sudo requirements, producing a coherent network/VPS-unavailable reason when remote execution cannot run.
- Preserved release-all Playwright skipping, hidden Windows subprocesses, and timestamped live/evidence logs.
- Validation: 40 tests passing plus an offline-security smoke run proving S05 -> S13 continue independently.

## Unreleased — quiet Windows subprocesses

- KonnaxionDiag-launched subprocesses now use Windows `CREATE_NO_WINDOW`, preventing CMD/PowerShell/Python console windows from flashing during GUI diagnostics.
- Runtime child processes retain their process-group behavior so stop/cleanup semantics are unchanged.
- `release-all` Playwright skipping remains scoped by `konnaxion.release_all_skip_playwright`.

## 4.2.0 — Exact ReleaseSet + universal attestation + PEP contract

### ReleaseSet / subject binding

- Replaced the generic release subject with `konnaxiondiag.release-set.v1`.
- Release identity now has explicit fields for source commit/tree, capsule, image digests, runtime pack, policy bundle, infra manifest, SBOM and provenance.
- File-backed ReleaseSet components are SHA-256 digested from exact bytes.
- `security_evidence_set_digest` is signed separately from `release_set_digest` to avoid cryptographic self-reference.
- `release-set.json` is emitted alongside the final verdict.

### Release authorization / PEP

- Added `konnaxiondiag.release-authorization.v1` with exact subject, policy version, issuance, expiration, run ID and nonce.
- Release verdict schema advanced to `konnaxiondiag.release-verdict.v5`.
- Added `assurance.pep.verify_release_authorization()` and `kdiag verify-admission`.
- PEP verifier recomputes the active ReleaseSet and fails closed on signature, subject, freshness or policy mismatch.
- The verifier intentionally exposes no caller-controlled bypass/skip flag.

### Universal attestations

- Added `konnaxiondiag.attestation.v1` with issuer, ReleaseSet subject, evidence type, policy/evidence digests, freshness and nonce.
- Added domain-separated `sign-attestation` and `verify-attestation` CLI flows.
- SEC-01..SEC-53 external evidence now consumes the universal envelope by default.
- Added migration-only compatibility for v4.1 specialized SEC attestations; disabled by default.

### Risk acceptance / recovery

- Added `konnaxiondiag.risk-acceptance.v1` with approval ID, requester/approver identities, requester separation, expiry, exact finding fingerprint, ReleaseSet binding and policy version.
- Restore drill strict mode now requires a universal signed `recovery.restore-drill` attestation bound to the current ReleaseSet, backup, restore target, trust/revocation epochs and audit anchor.

### Structure

- Added top-level `assurance/` package and machine-readable assurance registry.
- Kept `Nxx`, `Sxx` and `SEC-xx` as separate taxonomies; no `S15..S67` expansion.
- Added `codex/mappings.json` for AI/tool ingestion.

### Validation

- Current suite: 26 passing tests.
- New tests cover artifact-byte ReleaseSet binding, evidence-cycle separation, universal attestation binding, exact-release PEP admission, expiry rejection, post-signature tamper rejection, strong RiskAcceptance binding and universal SEC-contract ingestion.


## 4.1.0 — Security Assurance update

### Release authority

- Added deterministic `release_subject` binding for final release authorization.
- Release subject binds Git commit/tree, clean-worktree state, security-policy digest, contract-registry digest, Capsule Manager artifact subjects, and a run-specific evidence-set digest.
- Target mutation protection is now included inside the signed final release decision.
- `execution.allow_target_mutation=false` now activates tracked-file protection even if `protect_tracked_files` is disabled.

### Signed evidence

- Added generic domain-separated Ed25519 evidence signatures.
- Added `sign-evidence`, `verify-evidence`, and `sign-disposition` CLI commands.
- Capsule Manager `security-gate.json` can no longer qualify a release by content alone: release mode requires trusted signature verification, freshness, instance binding, and manifest/image subject fields.
- Restore-drill evidence now supports required trusted signature verification, freshness, operator metadata, and backup/environment subject binding.

### Risk acceptance

- Security warning dispositions can require approver identity, approval time, expiration, exact release-subject scope, and trusted Ed25519 signature.
- Default v4.1 policy enables all of those requirements.

### Supply chain

- Non-local container/base images can be required to use immutable `@sha256:` references.
- Local build outputs are expected to be bound by exact image digests in the signed Capsule Manager subject.

### Senior Security Codex

- Added machine-readable `security_contracts.json` for SEC-01 through SEC-53.
- S14 now evaluates Security Codex assurance contracts.
- Native validators currently cover SEC-29, SEC-33, and SEC-43 where KonnaxionDiag has authoritative evidence.
- All other controls require fresh, release-subject-bound, signed attestations from the responsible external authority.
- Added per-contract trusted-key and trusted-issuer configuration to avoid cross-domain attestation authority.

### Validation

- Expanded the project test suite from 11 to 20 tests.
- Added regression coverage for signature domain separation, stale evidence, scoped/expiring signed dispositions, stable subject identity, dirty-source rejection, target-mutation binding, the 53-contract registry, external contract attestations, and native SEC-29 composition.
