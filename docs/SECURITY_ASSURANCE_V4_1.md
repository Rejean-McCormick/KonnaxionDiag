# KonnaxionDiag v4.1 — Security Assurance Architecture

KonnaxionDiag v4.1 treats a release decision as an **authorization over an exact security subject**, not as a collection of green checks.

## Trust model

KonnaxionDiag is a **Security Assurance Authority**. It does not become the root/KMS/Kubernetes/CI authority for the ecosystem. Controls are enforced where they belong; KonnaxionDiag verifies their evidence and blocks release when the evidence is missing, stale, untrusted, ambiguous, or bound to another subject.

```text
source / CI / Konfid / Capsule Manager / runtime / recovery / AI gates
                   | signed attestations + native evidence
                   v
              KonnaxionDiag
          deterministic release subject
                   |
              signed verdict
                   v
        Capsule Manager / deployment PEP
                   |
        exact subject match before deploy
```

The deployment PEP MUST verify the release signature and MUST compare the object it is about to deploy with `release-verdict.json.release_subject`. A signed PASS for another commit, manifest, image set, or policy set is not reusable authority.

## Release subject

`release-all` now emits `release_subject` with:

- Git commit SHA and tree SHA;
- clean-worktree state;
- hash of the effective security policy configuration;
- Capsule Manager subject claims, including manifest/image identities;
- a run-specific evidence-set digest;
- a stable `subject_sha256` used to scope approvals and external attestations.

The stable subject hash deliberately excludes warning dispositions and private-key file locations, preventing circular approvals. The final Ed25519 release signature still covers the complete verdict, including evidence digest, dispositions outcome, target-protection result, and consumer contract.

A dirty source tree or missing Git identity blocks a release when `release_gate.subject_binding.required=true`.

## Signed Capsule Manager Security Gate

The remote `security-gate.json` is no longer trusted because it exists on the target host. For release use, KonnaxionDiag requires a detached Ed25519 signature in `security-gate.sig` and checks:

- signature domain: `konnaxiondiag-capsule-security-gate`;
- trusted public key;
- exact payload digest;
- `issued_at` freshness and optional `expires_at`;
- configured `instance_id` binding;
- subject fields `instance_id`, `manifest_digest`, and `image_digests` by default;
- complete required Capsule Manager checks with no missing, skipped, blocking, or unknown required evidence.

This converts the Capsule Manager gate from host-local JSON into a cryptographically verifiable attestation.

## Warning/risk dispositions

Release-security WARN exceptions are authorization objects, not comments. The default v4.1 policy requires:

- accepted status;
- rationale;
- `approved_by`;
- `approved_at`;
- `expires_at`;
- exact `scope.release_subject_sha256`;
- Ed25519 signature from a trusted approval key.

The signature domain is `konnaxiondiag-security-warning-disposition`. A disposition for one release subject cannot authorize another.

Operational flow:

```text
1. run release-all -> BLOCKED, obtain release_subject.subject_sha256
2. create disposition JSON scoped to that subject
3. kdiag sign-disposition disposition.json --key <approval-private.pem> --output disposition.signed.json
4. place the signed object under release_gate.security_warn_dispositions.<finding-id>
5. rerun release-all
```

The subject hash remains stable across diagnostic reruns as long as the source, Capsule subject, and security policy remain the same.

## Restore/recovery attestations

A successful restore drill is no longer represented by unsigned booleans. S13 requires, by default:

- the existing isolated restore success assertions;
- non-empty operator identity;
- subject binding including `backup_digest` and `environment_id`;
- a recent `performed_at` value (30 days by default);
- optional expiration validation;
- detached Ed25519 signature using domain `konnaxiondiag-restore-drill`;
- a trusted recovery-attestation public key.

Default runtime paths are under `.konnaxiondiag/assurance/` so evidence can remain outside the source release set while still being locally consumable.

## Immutable container dependencies

S03 can now enforce immutable `@sha256:` references for non-local container/base images. Locally built Konnaxion images are intentionally handled differently: their exact output digests must appear in the signed Capsule Manager subject.

Thus the release chain becomes:

```text
source commit/tree
  + immutable external/base images
  + locally built image digests
  + runtime manifest digest
  + security policy digest
  + evidence set
  -> signed release authorization
```

## Senior Security Codex contracts (SEC-01…SEC-53)

`security_contracts.json` contains all 53 Senior Security Codex patterns. S14 loads this registry during release qualification.

KonnaxionDiag has native validators only where it can genuinely demonstrate the invariant from its own evidence:

- `SEC-29 Admission by Digest and Attestation` — immutable non-local images + passing signed Capsule Manager gate;
- `SEC-33 Release Set as a Security Object` — deterministic release subject with Capsule artifact identities;
- `SEC-43 Compromise-Ready Recovery` — passing signed/fresh/scoped restore drill.

All other contracts require an external attestation from the authority that actually owns the control. This prevents KonnaxionDiag from self-certifying identity, KMS, Kubernetes, AI-agent, audit-anchor, or CI properties it cannot observe authoritatively.

Each external file is placed by default at:

```text
<target>/.konnaxiondiag/assurance/security-contracts/SEC-XX.json
<target>/.konnaxiondiag/assurance/security-contracts/SEC-XX.json.sig
```

Payload schema:

```json
{
  "schema": "konnaxiondiag.security-contract-attestation.v1",
  "contract_id": "SEC-01",
  "status": "PASS",
  "issuer": "konfid-assurance",
  "issued_at": "2026-10-02T14:00:00Z",
  "expires_at": "2026-10-03T14:00:00Z",
  "subject": {
    "release_subject_sha256": "<64 hex>"
  },
  "evidence_sha256": "<64 hex digest of authoritative evidence>"
}
```

The detached signature purpose is unique per contract:

```text
konnaxiondiag-security-contract-attestation:SEC-01
```

This prevents a valid attestation for SEC-01 from being replayed as evidence for SEC-02.

To sign one:

```powershell
kdiag sign-evidence .konnaxiondiag/assurance/security-contracts/SEC-01.json `
  --purpose konnaxiondiag-security-contract-attestation:SEC-01 `
  --key C:\secure\konfid-attestation-ed25519.pem `
  --output .konnaxiondiag/assurance/security-contracts/SEC-01.json.sig
```

By default `security_assurance.required_contracts="all"`: no evidence means no claim of full codex coverage and therefore no release PASS.

Trust can be scoped per control with `security_assurance.trusted_public_keys_by_contract` / `trusted_issuers_by_contract`, or by authority group with `trusted_public_keys_by_authority_group` / `trusted_issuers_by_authority_group`. The registry defines eight authority groups: `identity`, `authorization`, `protocol_boundaries`, `cryptography`, `supply_chain`, `kubernetes_runtime`, `audit_recovery`, and `agentic_ai`. The shipped policy sets `allow_global_trust_fallback=false`, so a generic ecosystem key cannot silently attest every domain.

## Target mutation policy

`execution.allow_target_mutation=false` is now connected to the runner. It forces tracked-file protection even if `protect_tracked_files` were otherwise disabled. Any tracked target mutation detected during diagnostics becomes release-blocking and is included **inside** the final signed release decision.

This is still a detection-and-blocking control, not an OS write sandbox. KonnaxionDiag intentionally does not pretend otherwise.

## Evidence signing commands

```powershell
# Generic detached evidence signature
kdiag sign-evidence evidence.json --purpose <domain> --key private.pem --output evidence.json.sig

# Verify evidence
kdiag verify-evidence evidence.json evidence.json.sig --purpose <domain> --public-key trusted-public.pem

# Sign an inline security warning disposition
kdiag sign-disposition disposition.json --key approval-private.pem --output disposition.signed.json
```

Private keys should remain outside source repositories. `KDIAG_EVIDENCE_SIGNING_KEY_PASSWORD` can provide a PEM password without placing it on the command line.

## What v4.1 still deliberately does not do

KonnaxionDiag does not itself implement workload identity, KMS rotation, Kubernetes admission, CI isolation, AI tool authorization, independent audit anchoring, or other ecosystem controls. For those, it verifies signed SEC-contract attestations from the responsible authority. The control remains at its proper enforcement point; KonnaxionDiag owns the release decision.
