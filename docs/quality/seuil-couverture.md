# Seuil de couverture bloquant

La CI échoue si la couverture totale de `src/` passe sous **80 %**. Le chiffre est dans `pyproject.toml`, section `[tool.coverage.report]`, clé `fail_under`. C'est la seule source : `ci.yml` l'applique via `pytest --cov`, et le commentaire de couverture des PR le lit pour l'afficher.

## Pourquoi maintenant, et pourquoi 80 %

L'issue #246 demandait de décider ce seuil **après** le traitement de `netcross_gtk4/app.py` (#285), pas avant. Un seuil fixé plus tôt aurait été calé sur le plus gros trou du projet, puis n'aurait plus rien retenu une fois ce trou réduit.

| Date | Couverture de `dev` | Événement |
|---|---|---|
| 2026-09-21 | 76,7 % | base de référence de #224 |
| 2026-09-22 | 78,9 % | mesure de #246 |
| 2026-09-23 | 82,2 % | après #285 lots 1 à 4, #286, #287, #288 |

Le 2026-09-23, la mesure donne 82,2 % en local sans tshark, et le même chiffre sur la base `dev` dans les commentaires de PR.

Deux points de marge, pas davantage :

- **Assez** pour absorber une PR qui ajoute légitimement du code GTK. Ce code n'est pas testable en CI (PyGObject absent), voir #285 et la page « Couverture de la GUI » ajoutée par la PR #327.
- **Pas plus**, parce qu'un seuil à 70 % laisserait passer la suppression de plusieurs milliers de lignes de tests sans rien signaler.

## Seuil du total réel : 95 % (audit #462)

Le seuil de 80 % porte sur la mesure du job Qualité, sans PyGObject : les modules `netcross_gtk4` y comptent pour 0 %. Depuis #943, le job « Couverture combinée (Qualité + GTK4) » fusionne cette mesure avec celle du job GTK4 (Xvfb) et obtient le total réel toutes sources confondues.

| Date | Total réel combiné | Événement |
|---|---|---|
| 2026-10-18 | 98,2 % | premier passage du job combiné (#944) |

L'audit #462 demandait de passer à 95 %. Ce seuil est appliqué au total réel par le job combiné (`coverage report --fail-under=95` dans `ci.yml`) : 3,2 points de marge. Le seuil de `pyproject.toml` reste à 80 % pour le job Qualité, qui ne peut pas mesurer la GUI.

## Ce que le seuil ne dit pas

Le seuil est un plancher contre la régression, pas un objectif. Le principe de #246 tient toujours : on vise les chemins d'erreur, les branches de dégradation et les sorties réellement produites, module par module. Un test écrit pour faire monter le chiffre sans rien vérifier est pire que pas de test, puisqu'il fait croire que la vérification a eu lieu.

## Faire évoluer le seuil

- **Le relever** quand la base monte durablement, en gardant environ deux points de marge. Le commentaire de couverture de chaque PR affiche la marge restante.
- **Ne jamais le baisser pour faire passer une PR.** Une PR sous le seuil ajoute des tests, ou explique dans sa description pourquoi le code ajouté n'est pas testable. Dans ce second cas, le seuil se discute dans une issue dédiée, pas dans la PR.
- Pas de `# pragma: no cover` pour atteindre le seuil. La raison est la même que pour `app.py` : une exclusion fait monter le chiffre sans rien tester.

## Commentaire de couverture des PR

`pr-coverage.yml` lance pytest avec `--cov-fail-under=0`. Sans cela, une PR sous le seuil ferait échouer ce job avant la publication du commentaire, qui est justement l'endroit où l'écart est expliqué. Le blocage reste dans `ci.yml`.

Le commentaire indique l'un de ces trois états :

- la marge restante au-dessus du seuil ;
- **« Sous le seuil bloquant »**, qui annonce l'échec du job Tests ;
- l'absence de seuil, si `fail_under` a été retiré.

Un test (`tests/test_pr_coverage_comment.py`) vérifie que les deux workflows restent cohérents avec ce fonctionnement.
