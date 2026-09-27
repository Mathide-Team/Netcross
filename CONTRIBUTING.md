# Contribuer à Netcross

Merci de votre intérêt pour Netcross. Ce guide décrit le workflow de
contribution, les conventions de code, et le processus de release.

## Démarrage rapide

```bash
# Cloner et installer les dépendances de développement
git clone https://github.com/MathildeDec/Netcross.git
cd Netcross
pip install -e ".[dev]"

# Vérifier que l'environnement est fonctionnel
PYTHONPATH=src python -m pytest tests/ -q
ruff check src/ tests/
ruff format --check src/ tests/
PYTHONPATH=src lint-imports
```

Prérequis système : `tshark` (paquet `wireshark-cli` ou `tshark`).

## Workflow Git

### Branches

Le dépôt suit un modèle `dev → main` :

- **`main`** : branche stable, toujours déployable. Les PR vers `main`
  sont rejetées par le guard-main.yml si elles ne viennent pas de `dev`.
- **`dev`** : branche d'intégration. Toutes les feature PRs ciblent `dev`.
  Sa protection est décrite dans [Protection de `dev`](#protection-de-dev).
- **`feature/issue-NNN-description`** : une branche par issue, créée
  depuis `dev` :

  ```bash
  git checkout -b feature/issue-123-ma-feature dev
  ```

### Protection de `dev`

La règle de protection de `dev` est **versionnée** dans
[`.github/branch-protection/dev.json`](.github/branch-protection/dev.json)
(issue #334). C'est la charge utile exacte de l'API GitHub :

- checks obligatoires avant fusion : « Qualité (lint, format,
  import-linter, tests) », « Tests GTK4 (Xvfb) », « Paquets (deb installé,
  rpm vérifié) » et « Construction (mkdocs build --strict) ». « Types
  (mypy) » n'en fait pas partie, car il est volontairement non bloquant
  (`continue-on-error`, voir `ci.yml`) ;
- branche à jour exigée avant fusion (`strict`) ;
- règle appliquée **aussi aux administrateurs** (`enforce_admins`) :
  l'incident à l'origine de #334 (PR #316 à #327 fusionnées CI rouge)
  venait d'un compte administrateur ;
- pas d'historique linéaire imposé : les releases `dev → main` et les
  réconciliations (#373, #461) sont des merge commits ;
- ni force-push ni suppression de la branche.

Une protection de branche est un réglage du dépôt : seul un administrateur
peut l'appliquer ou la modifier, avec :

```bash
gh api -X PUT repos/MathildeDec/Netcross/branches/dev/protection \
    --input .github/branch-protection/dev.json
```

Toute modification passe par une PR sur ce fichier, puis par cette même
commande. Le workflow « Protection de dev » (push sur `dev`, chaque jour,
et à la demande) compare la protection réelle au fichier et échoue sur tout
écart. La suite de tests vérifie de son côté que chaque check requis
correspond à un job qui tourne sur les PR vers `dev` : renommer un job
requis sans mettre la règle à jour bloquerait sinon toutes les PR.
Vérification manuelle :

```bash
python3 scripts/check_branch_protection.py              # état réel (API GitHub)
python3 scripts/check_branch_protection.py --hors-ligne # règle <-> workflows
```

Sans droit d'administration, l'exigence de branche à jour (`strict`) n'est
pas lisible par l'API : elle est signalée en avertissement, jamais supposée
conforme.

### Pull Requests

1. Créer une branche depuis `dev` (voir ci-dessus).
2. Coder + écrire les tests.
3. Vérifier localement : `ruff check`, `ruff format --check`, `lint-imports`,
   `pytest`.
4. Pousser et créer la PR vers `dev` :

   ```bash
   gh pr create --base dev --head feature/issue-123-ma-feature
   ```

5. La CI tourne automatiquement : un seul workflow (`ci.yml`) couvre le
   lint, les tests, la couverture, l'import-linter, la construction de la
   documentation (mkdocs) et la validation des catalogues i18n. La
   couverture par PR est commentée par `pr-coverage.yml` (issue #463).
6. Une fois la CI verte et la review approuvée, merger vers `dev`.
7. Périodiquement, synchroniser `dev` vers `main` via une PR dédiée.

### Conventions de commit

Format : `type(#issue): description courte`

Types : `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `perf`.

Exemples :
```
feat(#145): statistiques de flux et conversation
fix(#149): détection de mouvement latéral sur ports non standards
docs(#216): documentation CLAUDE.md
```

## Conventions de code

### Style

- **Lint** : `ruff check` (règles : E, W, F, I, B, C4, UP, SIM, N, PERF, RUF, TID)
- **Format** : `ruff format` (line-length=120, Python 3.9+)
- **Imports** : `ban-relative-imports = "all"` — imports absolus uniquement
- **Architecture** : contrat import-linter avec couches strictes :

  ```
  netcross_gtk4 → netcross_report → netcross_api → netcross_core → pcap_parser
  ```

  Une couche ne peut importer que les couches inférieures. `pcap_parser` est
  la couche la plus basse et ne peut importer de `netcross_core`.

### Tests

- Framework : `pytest` avec `pytest-cov`
- Pattern : utiliser `make_pkt(**overrides)` de `tests/conftest.py` pour
  créer des paquets synthétiques (le modèle `Pkt` a 78+ champs requis).
- `list.append` dans une boucle déclenche `PERF401` — utiliser des
  compréhensions de liste.
- `dict()` déclenche `C408` — utiliser des littéraux `{}`.
- Lancer : `PYTHONPATH=src python -m pytest tests/ -v`
- Seuil de couverture : la CI échoue sous `fail_under` (`pyproject.toml`,
  80 %). Vérifier en local avec `uv run pytest --cov -q`. Le seuil se relève
  quand la base monte, il ne se baisse pas pour faire passer une PR — voir
  `docs/quality/seuil-couverture.md`.

### Ajouter un détecteur de sécurité

1. Créer `src/netcross_core/security/nom_module.py` avec :
   - Une `@dataclass` pour les seuils (`_NomThresholds`)
   - Une `@dataclass` pour le résultat (`NomResult`)
   - Une fonction `detect_nom(packets) -> NomResult`
2. Intégrer dans `netcross_core/security/findings.py` via une fonction
   `nom_findings(result) -> list[dict]` et l'ajouter à `apply_security_findings`.
3. Ajouter les champs correspondants sur `Report` dans `models.py`.
4. Écrire les tests dans `tests/test_nom_module.py`.
5. Documenter dans le canvas de l'issue.

### Chaînes traduisibles

Les textes affichés à l'utilisateur passent par `netcross_core.i18n`
(`_()`, `ngettext()`, `N_()`) ; après en avoir ajouté ou modifié, lancer
`scripts/i18n-update.sh` et committer `lang/`. Voir
[docs/i18n.md](docs/i18n.md).

## Releases

1. Merger toutes les PRs prévues vers `dev`.
2. Synchroniser `dev` vers `main` via une PR.
3. Taguer : `git tag v1.X.0 -m "Release v1.X.0"`.
4. Mettre à jour `CHANGELOG.md`.
5. Créer la release GitHub depuis le tag.

## Signaler un bug ou une vulnérabilité

- **Bug fonctionnel** : ouvrir une issue GitHub avec le label `bug`.
- **Vulnérabilité de sécurité** : suivre la procédure décrite dans
  [SECURITY.md](SECURITY.md) — ne pas ouvrir d'issue publique.
