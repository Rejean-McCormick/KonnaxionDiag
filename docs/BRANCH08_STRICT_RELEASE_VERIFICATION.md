# Branch 08 — Strict release verification and independent assurance

**Status:** local verifier source and tests, not host activation or universal security qualification.

## Implemented

The strict `assurance/pep.py` path validates exact `konnaxiondiag.release-set.v1` identity binding, a trusted Ed25519 detached signature, signed verdict and authorization scope, non-expired time bounds, expected policy version, required component completeness, measured release digest, clean S14 security/functional results and caller-bypass prohibition. It performs **no** Docker or host measurement; the Agent must independently measure the real deployment bytes.

The branch 08 change makes direct `verify_release_authorization` return an explicit `(False, detail)` for malformed JSON objects, rather than escaping an unchecked exception. `verify_activation_admission` already denies malformed objects. Neither success grants a deployment credential; the enforcing Agent remains responsible for privileged effects.

## Evidence

```console
python -m pytest -q tests/test_agent_activation_pep_v425.py tests/test_assurance_v42.py tests/test_branch08_pep_invalid_input.py
```

The two-sided Agent consumer test is in Konnaxion Capsule Manager: `KONNAXIONDIAG_SOURCE=/path/to/KonnaxionDiag python -m pytest -q tests/test_branch08_bilateral_admission.py`. Its positive fixture and negative mismatched-image/verdict cases exercise the actual verifier with ephemeral keys, but do not prove live host admission or full release qualification.

## Remaining gates

Select authoritative qualification policy and signer trust roots, run complete S14 and functional campaigns on pinned deployment inputs, independently validate exact host measurements, and attach actual host PEP/activation/rollback receipts. Preserve separate diagnostic, authorization, admission and execution states.
