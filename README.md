# KonnaxionDiag

**Version:** `4.2.4` | **Scope:** Independent functional diagnostics, security qualification and exact release-admission evidence for Konnaxion.

KonnaxionDiag combines the LevelUpDiag (`N00`–`N11`) and SecurityDiag (`S00`–`S14`, including `S04W`) campaigns under a common execution and evidence engine. Functional verdicts, security campaigns and the `SEC-01`–`SEC-53` architectural controls retain separate meanings.

## Security and admission boundary

**Qualification is not enforcement.** KonnaxionDiag may produce an independently signed qualification/denial, but the actual Policy Enforcement Point (PEP)—Capsule Manager, Konnaxion Agent or admission controller—must verify that decision before allowing a protected transition. A signed result is not a substitute for an enforcement integration.

```text
N00–N11 → S00–S04 → S04W → S05–S14
                          ↓
                  SEC-01–SEC-53 map
                          ↓
              Exact ReleaseSet qualification
                          ↓
              Signed ReleaseAuthorization
                          ↓
                     PEP verification
```

## ReleaseSet and signed evidence

ReleaseSet v1 binds the deployable subject to specific source commit/tree, capsule, image digests, runtime pack, policy bundle, infrastructure manifest, SBOM and provenance. The release set digest and the security evidence set digest are handled separately to avoid circular attestation. Mandatory missing components block the release.

External evidence uses `konnaxiondiag.attestation.v1` with issuer, exact release subject, evidence type/digest, policy digest, timestamps/expiry, nonce, statement and detached Ed25519 signature. Strict acceptance of a security `WARN` requires an explicit, time-bounded, signed risk acceptance bound to the exact finding, ReleaseSet, policy and approver identities.

## Operational commands

```powershell
python kdiag.py doctor
python kdiag.py list
python kdiag.py run release-all
python kdiag.py build-release-set --target <repo>
python kdiag.py sign-attestation evidence.json --key issuer.pem --output evidence.json.sig
python kdiag.py verify-attestation evidence.json evidence.json.sig --release-set release-set.json --public-key issuer.pub
python kdiag.py verify-admission release-verdict.json release-verdict.sig release-set.json --public-key release-authority.pub
```

`release-all` retains established campaign taxonomies and sequencing. Optional `konnaxion.release_all_skip_playwright=true` marks selected N05 browser probes `SKIP`; it does not reclassify missing checks as `PASS`. Dedicated `full-local` and `i18n-validation` campaigns still run their browser checks. Unavailable VPS endpoints should block only dependent remote evidence and must not prevent otherwise viable local checks from running; missing required remote proof still fails release admission.

## Integration status

The independent verifier exists on the diagnostic side. The Konnaxion Agent source was not included in the supplied diagnostic archive; integration into its `handle_instance_start()` PEP path still requires separate implementation and evidence. **Do not claim full enforcement from the presence of the verifier alone.**

Evidence typically resides under `.konnaxiondiag/current/`, including level results, correlation, `release-set.json`, `release-verdict.json` and `release-verdict.sig`.

Refer to `docs/SECURITY_ASSURANCE_V4_2.md` and `docs/KX_AGENT_PEP_INTEGRATION.md` for architecture and the mandatory Agent integration.
