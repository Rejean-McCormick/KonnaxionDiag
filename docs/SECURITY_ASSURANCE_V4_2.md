# Security Assurance v4.2

KonnaxionDiag v4.2 formalizes release security as an exact subject, a set of independently verifiable attestations, and a fail-closed authorization consumed by the real enforcement point.

## 1. Taxonomies remain separate

- `N00..N11`: functional qualification.
- `S00..S14 + S04W`: security qualification campaigns.
- `SEC-01..SEC-53`: architectural security invariants.
- Evidence/attestations: facts used to prove an invariant.
- PEP: the component that actually rejects the protected transition.

SEC IDs are **not** mapped to new S-level numbers. The relationship is many-to-many.

## 2. ReleaseSet v1

`release-set.json` is the exact release object that may be activated. Its identity includes:

- source commit and Git tree identity;
- capsule digest(s);
- immutable image digests;
- runtime-pack digest;
- policy-bundle digest;
- infrastructure-manifest digest;
- SBOM digest;
- provenance digest;
- effective KonnaxionDiag security-policy digest;
- Security Codex registry digest.

Configured file components are SHA-256 digested from bytes. A component can contain several files; its component digest is the canonical digest of the selected relative paths and their file digests.

### No cryptographic cycle

`security_evidence_set_digest` is recorded in the ReleaseSet document but is **not** part of `release_set_digest`.

That is deliberate. External attestations bind to `release_set_digest`; the final signed authorization covers both the immutable ReleaseSet identity and `security_evidence_set_digest`. If evidence were included in the subject digest, an attestation would need to sign a digest that includes itself.

## 3. Signed release authorization

`release-verdict.json` now uses `konnaxiondiag.release-verdict.v5` and embeds:

```text
ReleaseAuthorization
├── subject = release_set_digest
├── verdict
├── policy_version
├── issued_at
├── expires_at
├── run_id
└── nonce
```

The detached Ed25519 release signature covers the complete verdict, authorization, ReleaseSet and evidence-set digest.

## 4. PEP admission verifier

`assurance.pep.verify_release_authorization()` and the CLI command below are designed for Capsule Manager / Konnaxion Agent:

```bash
kdiag verify-admission \
  release-verdict.json \
  release-verdict.sig \
  release-set.json \
  --public-key /etc/konnaxion/trust/kdiag-release.pub \
  --policy-version konnaxion-security-policy-v1
```

The verifier:

1. recomputes and validates the active ReleaseSet digest;
2. verifies the detached Ed25519 authorization signature;
3. requires an activation-acceptable verdict;
4. requires `authorization.subject == active release_set_digest`;
5. checks issuance/expiration, nonce, run ID and policy version;
6. fails closed on any missing, stale, invalid or mismatched state.

There is intentionally no `skip`, `run_security_gate` or caller-controlled bypass parameter.

## 5. Universal attestation v1

External evidence now uses a common envelope:

```text
Attestation
├── issuer
├── subject.release_set_digest
├── evidence_type
├── status = PASS
├── issued_at / expires_at
├── policy_digest
├── evidence_digest
├── nonce
├── statement
└── detached Ed25519 signature
```

Signature domain separation is derived from `evidence_type`:

```text
konnaxiondiag-attestation:<evidence_type>
```

Examples:

- `security.contract.SEC-01`
- `security.contract.SEC-27`
- `recovery.restore-drill`

The v4.1 specialized SEC attestation format is rejected by the default v4.2 policy. A migration-only compatibility path still exists when explicitly enabled.

## 6. SEC-01..SEC-53

The canonical machine-readable registry remains `security_contracts.json`.

Native validators are limited to controls KonnaxionDiag can actually prove. Other controls require a signed attestation from the owning authority. Trust can be scoped by contract or authority group; global-key fallback remains disabled by default.

## 7. RiskAcceptance v1

A security WARN acceptance can now require:

- schema `konnaxiondiag.risk-acceptance.v1`;
- `approval_id`;
- `requested_by`;
- one or more distinct `approved_by` identities;
- requester/approver separation;
- approval timestamp and expiration;
- exact `release_set_digest`;
- exact finding fingerprint;
- policy version;
- detached trusted signature.

A config edit can therefore no longer create a permanent, unscoped exception under the default v4.2 policy.

## 8. Recovery evidence

The default recovery policy rejects the legacy boolean-only restore document. It expects `konnaxiondiag.attestation.v1` with `evidence_type = recovery.restore-drill`, bound to:

- current `release_set_digest`;
- backup digest;
- restore-target identity;
- environment ID;
- trust epoch before/after;
- revocation epoch;
- independent audit anchor.

The statement also records operator identity, start/completion times and the actual restore verification results.

## 9. Strict ReleaseSet configuration

The shipped profile requires all senior components:

```text
source
capsule
images
runtime_pack
policy_bundle
infra_manifest
sbom
provenance
```

Exact files for the non-runtime components must be configured under `release_set.components`. Missing configured artifacts are release blockers rather than silently omitted evidence.

## 10. CLI additions

```bash
kdiag build-release-set --target <repo>
kdiag sign-attestation attestation.json --key private.pem --output attestation.json.sig
kdiag verify-attestation attestation.json attestation.json.sig --release-set release-set.json --public-key issuer.pub
kdiag verify-admission release-verdict.json release-verdict.sig release-set.json --public-key kdiag-release.pub
```

## 11. Remaining external integration

KonnaxionDiag now provides the exact contract the Agent PEP must enforce, but the Agent source is a separate component. See `KX_AGENT_PEP_INTEGRATION.md` for the required non-bypassable integration.
