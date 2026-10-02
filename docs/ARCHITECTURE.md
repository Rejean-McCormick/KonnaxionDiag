# Architecture KonnaxionDiag v4.2

```text
                         KonnaxionDiag
                +-------------+-------------+
                |                           |
          LevelUp profile              Security profile
             N00-N11              S00-S14 + S04W
                |                           |
                +-------------+-------------+
                              |
                      evidence / findings
                              |
                       assurance layer
          +-------------------+-------------------+
          |                   |                   |
      ReleaseSet        SEC-xx contracts    RiskAcceptance
          |                   |                   |
          +-------------------+-------------------+
                              |
                   signed ReleaseAuthorization
                              |
                              v
                   Capsule Manager / Agent PEP
                  recompute exact ReleaseSet
                  verify subject + signature
                  fail closed before ACTIVATE
```

## Authority boundary

KonnaxionDiag does not gain execution authority merely because it validates security. It qualifies an exact release object and issues a bounded authorization. The receiver-side PEP owns the final transition.

## Taxonomy boundary

```text
Nxx     functional qualification
Sxx     security qualification campaigns
SEC-xx  architectural security invariants
Evidence signed facts supporting invariants
PEP     actual transition enforcement
```

The mapping is many-to-many. `SEC-01..SEC-53` are not expanded into `S15..S67`.

## ReleaseSet and evidence

`release_set_digest` covers the exact deployable release identity. `security_evidence_set_digest` is kept separate and signed in the final verdict, avoiding self-referential attestation hashing.

External authorities emit `konnaxiondiag.attestation.v1` bound to the ReleaseSet. S14 combines native evidence and trusted attestations. The final release signature covers the ReleaseSet, the evidence-set digest and the bounded authorization.

## PEP integration

The PEP must use `assurance.pep.verify_release_authorization()` or an equivalent implementation. Caller-supplied options cannot disable gating for protected actions. See `KX_AGENT_PEP_INTEGRATION.md`.
