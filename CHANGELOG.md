# Changelog

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
