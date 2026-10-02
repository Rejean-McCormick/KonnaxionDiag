# KonnaxionDiag v4 — Validation report

Date: 2026-10-02

## Source baselines

The supplied LevelUpDiag snapshot passed its selected baseline tests before migration:

```text
10 passed
```

The supplied SecurityDiag snapshot passed its selected baseline tests before migration:

```text
8 passed
```

## KonnaxionDiag v4 tests

The v4-specific suite validates the shared command runner, manifest/taxonomy, S04W extraction, Web Trust behavior, warning disposition logic and exact detached Ed25519 release signing.

```text
11 passed
```

## Migrated legacy-domain regression sample

A namespace-adapted sample of legacy tests was executed against the migrated v4 implementation. It covers i18n, source audit, Universe/World audit, focus logic, redaction, bounded scanner behavior, SSH/remote helpers, Capsule Manager helpers, common-auth, Django check environment and firewall-port parsing.

```text
46 passed
```

## Runtime smoke — S04W

`kdiag run S04W` was executed against the supplied Konnaxion application snapshot. Dependency closure was:

```text
S00 -> S01 -> S04 -> S04W
```

Results:

```text
S00  PASS
S01  WARN   (snapshot has no .git repository metadata)
S04  PASS
S04W PASS
```

This confirms that S04W executes through the unified worker/report/evidence path. The campaign-level WARN is expected from the isolated SmartSnap checkout lacking Git metadata.

## Runtime smoke — N11 evidence correlation

`kdiag run universe-quick` was executed against the same isolated application snapshot. N11 successfully read current-run evidence directly from `.konnaxiondiag/current/levels` and reported full expected-level coverage.

The campaign itself returned FAIL because the isolated SmartSnap did not include the required sibling `Konnaxion_Worlds` repository. That failure is domain evidence, not a runner/infrastructure failure.

## Consolidation invariants checked

- `N00..N11` IDs preserved.
- `S00..S14` IDs preserved.
- `S04W` added as an independent security level.
- `release-all` order is N-profile first, then S-profile, then cross-domain correlation/final gate.
- N07 no longer launches SecurityDiag recursively.
- One canonical evidence root: `.konnaxiondiag`.
- One Python GUI launcher: `KonnaxionDiagLauncher.pyw`.
- One manifest: `kdiag_manifest.json`.
- One base configuration: `kdiag.config.json`.
- Security WARN findings require an explicit accepted disposition with rationale.
- `release-all` signing fails closed when signing is required and no key is configured.
- Detached Ed25519 signature verification detects post-signature payload mutation.
