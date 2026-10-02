# Security model

KonnaxionDiag v4.2 est une **Security Assurance / Release Authorization Authority**, pas un super-admin universel.

Une release acceptable signifie :

1. un `ReleaseSet v1` exact et canonique a été construit;
2. les campagnes N/S requises ont produit une evidence acceptable;
3. les invariants SEC requis disposent de preuves natives ou d’attestations universelles signées par leurs autorités;
4. les exceptions éventuelles sont des `RiskAcceptance` signés, expirants et correctement scoppés;
5. un `ReleaseAuthorization` borné dans le temps a été signé pour **ce `release_set_digest` précis**.

Le PEP doit ensuite :

1. recomputer l’identité du ReleaseSet actif;
2. vérifier `release-verdict.sig` contre une clé de release trustée;
3. vérifier verdict, expiration, nonce/run, policy version;
4. exiger `active_release_set_digest == authorization.subject`;
5. échouer fermé sur tout état absent, inconnu, périmé ou incohérent.

Le caller ne doit jamais pouvoir demander au PEP de ne pas appliquer sa politique. Pour les actions gated, une option comme `run_security_gate=false` ne peut donc pas être une décision d’autorité.

Les attestations externes utilisent `konnaxiondiag.attestation.v1` avec domain separation par `evidence_type`. Une signature authentifie l’émetteur; elle ne rend pas un émetteur non autoritaire légitime. Les trust anchors doivent rester scopés par contrat/domaine autant que possible.

Le profil par défaut v4.2 refuse les anciennes attestations SEC spécialisées et les anciens restore-drill booléens, sauf opt-in explicite de migration.

Voir `docs/SECURITY_ASSURANCE_V4_2.md` et `docs/KX_AGENT_PEP_INTEGRATION.md`.
