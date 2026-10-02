# Konnaxion Agent PEP integration contract

This document describes the P0 integration required in the Konnaxion Agent / Capsule Manager. The Agent source was not part of the KonnaxionDiag v4.2 package, so these changes cannot be truthfully claimed as applied here.

## Required invariant

For any production activation action, **the caller cannot choose whether security admission runs**.

A field such as:

```python
run_security_gate: bool = True
```

must not be authoritative at the PEP. For `instance.start` and every other security-gated activation action, the Agent decides that admission is mandatory.

Preferred behavior:

- remove the public flag entirely; or
- reject `run_security_gate=false` for a gated action; and
- use the Agent-owned `SECURITY_GATED_ACTIONS` set as the authoritative policy trigger.

## Required activation sequence

```text
request
  ↓
Agent authenticates caller
  ↓
Agent determines action ∈ SECURITY_GATED_ACTIONS
  ↓
load exact active ReleaseSet
  ↓
verify KonnaxionDiag release-verdict.sig
  ↓
verify authorization freshness/policy
  ↓
recompute active ReleaseSet digest
  ↓
require active digest == authorization.subject
  ↓
ACTIVATE
```

Unknown, missing, expired, unsigned or mismatched evidence must reject activation.

## Reference Python integration

The Agent can call the library directly:

```python
from assurance.pep import verify_release_authorization

ok, detail = verify_release_authorization(
    verdict,
    verdict_signature,
    trusted_public_keys=release_authority_keys,
    active_release_set=active_release_set,
    allowed_verdicts=("PASS",),
    expected_policy_version=EXPECTED_RELEASE_POLICY_VERSION,
)
if not ok:
    raise SecurityAdmissionDenied(detail)
```

or execute `kdiag verify-admission` as a tightly controlled local verifier.

## Regression tests required in the Agent repo

At minimum:

1. `instance.start` with `run_security_gate=false` is rejected or the parameter is ignored and admission still executes.
2. A valid authorization for ReleaseSet A cannot activate ReleaseSet B.
3. An expired authorization is rejected.
4. A post-signature modification of the verdict is rejected.
5. Missing release authorization is rejected.
6. A Manager/admin caller cannot bypass `SECURITY_GATED_ACTIONS`.
7. A valid PASS cannot be reused after policy/trust epoch invalidation if the Agent policy requires an epoch check.

## Security-gate producer migration

The Agent should also migrate its `security-gate.json` evidence to `konnaxiondiag.attestation.v1` and bind it to the exact `release_set_digest`. Until that producer is updated, KonnaxionDiag retains the signed v4.1 Capsule Security Gate verifier for compatibility; it should not be treated as the final long-term envelope.
