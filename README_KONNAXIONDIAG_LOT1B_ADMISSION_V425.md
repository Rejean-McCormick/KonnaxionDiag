# Lot 1B — KonnaxionDiag v4.2.5 / admission de release stricte

**Cible** : `C:\mycode\Konnaxion\KonnaxionDiag` (extraire ce pack à la racine du dépôt).

**Source audité** : `KonnaxionDiag_Code_snapshot.zip`, relevé le 18 octobre 2026 à 21:28.

## Installation (PowerShell 7)

```powershell
cd C:\mycode\Konnaxion\KonnaxionDiag
.\PREVIEW_KDIAG_LOT1B.cmd
.\INSTALL_KDIAG_LOT1B.cmd
.\VERIFY_KDIAG_LOT1B.cmd
```

Le `PREVIEW` est en lecture seule. `INSTALL` compare les SHA-256 des **10 fichiers** attendus, teste d'abord sur une copie isolée du dépôt, puis installe exclusivement ces fichiers si et seulement si leurs empreintes initiales sont conformes. La copie source est conservée dans `C:\mycode\Konnaxion\Tandem_Local\lot1b_konnaxiondiag\backups\`. La nouvelle exécution d'`INSTALL` est idempotente. `VERIFY` vérifie les empreintes après installation et relance les tests. `ROLLBACK_KDIAG_LOT1B.cmd` restaure les fichiers précédents **uniquement s'ils sont restés inchangés**, sinon refuse l'écrasement.

Aucun téléchargement de dépendances ou confirmation interactive n'est déclenché. Python 3.10+, `pytest` et `cryptography` doivent être disponibles dans l'interpréteur de lancement. Si l'un manque, l'installation **refuse** d'avancer. Ne pas installer de secrets ni de clés privées dans le dépôt.

## Fonction fournie

- KonnaxionDiag **4.2.5** conserve la CLI existante `verify-admission`.
- Nouvelle API `assurance.pep.verify_activation_admission(...)` et CLI **`verify-activation`** pour un consommateur PEP (Capsule Agent).
- `PASS` uniquement. Vérification Ed25519 et métadonnées de signature, politique attendue, fraîcheur/expiration, ReleaseSet signé, composants de production, qualification sécurité `S14`, protection de la cible, intégrité de l'identité et concordance avec **l'empreinte de release mesurée indépendamment par l'Agent**.
- Sortie CLI `ADMIT` (0) / `DENY` (20) et rapport JSON pour intégration contrôlée.
- 23 nouveaux tests de sécurité, portant le total de 48 à 71 sur la plateforme locale de vérification.

### Exemple **de contrat**, pas une commande de déploiement

```text
python kdiag.py verify-activation \
    release-verdict.json release-verdict.sig release-set.json \
    --public-key <cle-publique-de-confiance> \
    --policy-version <version-de-politique-fixee-par-agent> \
    --measured-digest sha256:<empreinte-mesuree-par-agent>
```

**Contrainte capitale** : Le seul passage d'une empreinte `--measured-digest` ne prouve pas qu'elle provient des artefacts déployés. **L'Agent doit la calculer lui-même**, depuis son inventaire de capsules, d'images immuables et de politiques. Il ne doit jamais copier la valeur depuis la requête du Manager, le verdict signé ou le JSON de preuve. Le vérificateur ne mesure pas les artefacts à la place de l'Agent.

## Ce qui reste à intégrer (Lot 1C)

L'Agent du Capsule Manager doit ensuite **appeler ce vérificateur et imposer le verdict au point d'activation**, en utilisant ses vraies clés publiques de confiance et la mesure indépendante de la release active. L'Agent Linux distant ne change pas avec ce pack. Cette mise à jour ne déclenche aucun déploiement ni accès à Neon/Orgo/Konfid. Le lot 1A de durcissement local du Security Gate reste distinct et préservé.

**GO LIVE / admission cryptographique réelle : non encore validés.**
