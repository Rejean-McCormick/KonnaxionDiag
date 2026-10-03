# KonnaxionDiag v4.2.4

KonnaxionDiag consolide **LevelUpDiag** et **SecurityDiag** autour d’un moteur commun tout en gardant séparés les verdicts fonctionnels (`Nxx`), les campagnes de qualification sécurité (`Sxx`) et les invariants architecturaux (`SEC-xx`).

```text
KonnaxionDiag
├── diagcore/                  runner, worker isolation, config, evidence, correlation, release gate
├── profiles/
│   ├── levelup/               N00..N11
│   └── security/              S00..S14 + S04W
├── assurance/
│   ├── release_set.py         ReleaseSet v1
│   ├── attestation.py         universal signed attestations
│   ├── pep.py                 fail-closed activation verifier
│   ├── contracts/             assurance schemas
│   └── verifiers/
├── codex/                     SEC-01..SEC-53 mappings
├── schemas/
├── security_contracts.json    canonical SEC registry
├── KonnaxionDiagLauncher.pyw
├── kdiag.py
├── kdiag_manifest.json
└── kdiag.config.json
```

## Principe de sécurité

**Qualifier n’est pas enforcer.** KonnaxionDiag produit une autorisation ou un refus signé. Le PEP réel — Capsule Manager / Konnaxion Agent / admission controller — doit exiger cette autorisation avant la transition protégée.

`release-all` exécute les campagnes existantes sans renommer les taxonomies. Pour accélérer la qualification locale, `konnaxion.release_all_skip_playwright=true` conserve N05 mais marque les deux automatisations navigateur (smoke Playwright et probe FR/EN) en `SKIP`. Les campagnes dédiées comme `full-local` et `i18n-validation` continuent d’exécuter Playwright.

Depuis v4.2.1, une cible VPS indisponible ne provoque plus de cascade qui annule les niveaux sécurité suivants. Les dépendances distantes concernées servent à ordonner la collecte; chaque niveau s’exécute et marque uniquement ses preuves distantes comme `BLOCKED`/`INFRA_ERROR`, tout en continuant ses contrôles locaux lorsqu’il en possède. Le gate de release reste fail-closed tant qu’une preuve distante obligatoire manque.

Le pipeline de capture force aussi UTF-8 pour les processus Python, récupère les sorties Windows UTF-8/CP1252 et supprime les séquences ANSI afin d’éviter les caractères `�` et les codes couleur bruts dans le log.

```text
N00..N11 -> S00..S04 -> S04W -> S05..S14
                                  ↓
                      SEC-01..SEC-53 evidence map
                                  ↓
                     exact ReleaseSet qualification
                                  ↓
                      signed ReleaseAuthorization
                                  ↓
                              PEP verify
```

## ReleaseSet v1

La v4.2 remplace le `release_subject` générique par un vrai **ReleaseSet** explicite : source commit/tree, capsule, image digests, runtime pack, policy bundle, infra manifest, SBOM et provenance.

Le `release_set_digest` couvre l’objet déployable. Le `security_evidence_set_digest` est signé séparément dans le verdict afin d’éviter une circularité où une attestation devrait signer un digest contenant l’attestation elle-même.

Le profil livré est fail-closed : les composants ReleaseSet obligatoires absents bloquent la release.

## Attestations universelles

Les preuves externes utilisent `konnaxiondiag.attestation.v1` :

```text
issuer
subject.release_set_digest
evidence_type
issued_at / expires_at
policy_digest
evidence_digest
nonce
statement
signature Ed25519 détachée
```

Les `SEC-01..SEC-53` utilisent ce même modèle. Le trust peut être limité par contrat ou par authority group.

## Risk acceptance

Un WARN sécurité n’est acceptable sous le profil strict que via un objet `konnaxiondiag.risk-acceptance.v1` signé, expirant et lié à la fois :

- au ReleaseSet exact;
- au fingerprint exact du finding;
- à la policy version;
- aux identités demandeur/approbateur.

## PEP admission

KonnaxionDiag fournit maintenant le verifier que le PEP doit appeler :

```powershell
kdiag verify-admission `
  release-verdict.json `
  release-verdict.sig `
  release-set.json `
  --public-key C:\trust\kdiag-release.pub `
  --policy-version konnaxion-security-policy-v1
```

Il n’existe aucun argument permettant au caller de désactiver l’admission.

**Important :** le source du Konnaxion Agent n’est pas inclus dans cette archive. Le verifier est donc implémenté et testé côté KonnaxionDiag, mais l’intégration P0 dans `handle_instance_start()` doit être appliquée dans le repo Agent. Voir `docs/KX_AGENT_PEP_INTEGRATION.md`.

## Commandes

```powershell
python kdiag.py doctor
python kdiag.py list
python kdiag.py run release-all
python kdiag.py build-release-set --target <repo>
python kdiag.py sign-attestation evidence.json --key issuer.pem --output evidence.json.sig
python kdiag.py verify-attestation evidence.json evidence.json.sig --release-set release-set.json --public-key issuer.pub
python kdiag.py verify-admission release-verdict.json release-verdict.sig release-set.json --public-key release-authority.pub
```

## Evidence

`release-all` écrit notamment :

```text
<Konnaxion>/.konnaxiondiag/current/
├── levels/.../result.json
├── correlation.json
├── summary.json
├── release-set.json
├── release-verdict.json
└── release-verdict.sig
```

## Documentation

- `docs/SECURITY_ASSURANCE_V4_2.md` — architecture v4.2 complète.
- `docs/KX_AGENT_PEP_INTEGRATION.md` — intégration non contournable côté Agent.
- `security_contracts.json` — registre canonique SEC-01…SEC-53.
- `assurance/registry.json` — contrats et taxonomies machine-readable.
