# Architecture KonnaxionDiag v4

```text
                    KonnaxionDiag / diagcore
                             |
                 +-----------+-----------+
                 |                       |
           LevelUp profile          Security profile
              N00-N11            S00-S04-S04W-S14
                 |                       |
                 +-----------+-----------+
                             |
                  .konnaxiondiag/current
                             |
                   cross-domain correlation
                             |
                    FINAL RELEASE GATE
                             |
                release-verdict.json + .sig
                             |
                       Capsule Manager
                             |
                       Konnaxion Agent
```

`diagcore` n'accorde aucun privilège supplémentaire au diagnostic. Les niveaux distants de sécurité restent soumis aux garde-fous de configuration, SSH et au modèle de permissions déjà porté par SecurityDiag.
