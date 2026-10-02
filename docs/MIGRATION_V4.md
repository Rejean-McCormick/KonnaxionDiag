# Migration LevelUpDiag + SecurityDiag -> KonnaxionDiag v4

## Ce qui fusionne

Le runner, l'isolation worker, la configuration, le manifeste, la rétention d'evidence, la redaction, le reporting, la corrélation et l'interface graphique deviennent des services de `diagcore`.

## Ce qui reste séparé

Les niveaux `Nxx` restent le profil fonctionnel LevelUp. Les niveaux `Sxx` restent le profil sécurité et gardent leur pouvoir de blocage autonome. Les IDs ne sont pas renumérotés.

## Changement S04W

Le `S04` de SecurityDiag 1.3.0 contenait déjà les contrôles Web Trust. v4 les extrait dans `S04W` sans réécrire leurs règles. Le helper de qualification reste partagé avec S04 pour éviter de dupliquer la logique, mais seul `S04W` l'exécute.

## Changement N07

L'intégration historique où N07 lançait `SecurityDiag S04` et lisait `.securitydiag/latest` est désactivée en mode unifié. Cela supprime le runner imbriqué, la récursion potentielle et le second arbre d'evidence.

## Arbre d'evidence

Les anciens roots `.levelupdiag` et `.securitydiag` deviennent `.konnaxiondiag`. `N11` lit directement `current/levels/Nxx/result.json`; `S14` lit le même run pour `Sxx`.

## Campagnes

Les campagnes LevelUp historiques restent présentes. Les campagnes SecurityDiag exactes sont exposées comme `security-repo`, `security-host`, `security-external`, `security-incident`, `security-predeploy`, `security-release`. Les nouveaux workflows opératoires sont `developer`, `precommit`, `predeploy`, `incident` et `release-all`.

## WARN sécurité dispositionné

Un WARN n'est pas implicitement accepté. Pour une exception temporaire :

```json
{
  "release_gate": {
    "security_warn_dispositions": {
      "finding.id": {
        "status": "accepted",
        "rationale": "Justification revue et bornée."
      }
    }
  }
}
```

Une entrée vide, un statut non accepté ou l'absence de justification ne dispositionne pas le WARN.

## Capsule Manager / Agent

La frontière reste inchangée : KonnaxionDiag qualifie, Capsule Manager orchestre et l'Agent conserve la frontière privilégiée. KonnaxionDiag n'effectue aucune remédiation privilégiée.
