# Journalisation et mode debug

Netcross journalise avec [loguru](https://loguru.readthedocs.io/) : tous les modules obtiennent leur logger par `netcross_core.logging_config.get_logger(__name__)` (issue #245). Les messages de log sont en français et sont écrits sur **stderr**. La sortie normale des commandes (rapports, tableaux) reste sur stdout.

## Niveaux

| Réglage | Effet |
|---|---|
| (aucun) | niveau `INFO` |
| `NETCROSS_LOG_LEVEL=WARNING` | n'affiche que les avertissements et les erreurs |
| `--debug` ou `NETCROSS_DEBUG=1` | **mode debug** (niveau `DEBUG`) |
| `NETCROSS_LOG_LEVEL=DEBUG` | mode debug |
| `NETCROSS_LOG_LEVEL=TRACE` | mode debug, avec en plus les traces appelées pour chaque paquet (par exemple les adresses non IP) |

`NETCROSS_LOG_LEVEL` est prioritaire sur `NETCROSS_DEBUG`. Un niveau inconnu retombe sur `INFO` avec un avertissement.

## Mode debug : suivre l'exécution

L'option `--debug` est disponible sur toutes les commandes : `netcross`, `netcross-diff`, `netcross-batch`, `netcross-history`, `netcross-lua-doc` et `netcross-ai-models`. Elle existe aussi pour la GUI GTK4 (`netcross-gui --debug`, ou `python3 -m netcross_gtk4.app --debug` depuis les sources). Pour l'API REST, utiliser `NETCROSS_DEBUG=1`.

En mode debug :

- chaque étape instrumentée émet une trace `DEBUG` (décisions, comptages, chemins, branches de repli) ;
- chaque ligne indique le **processus et le thread émetteurs**, car les analyses GTK tournent dans des threads et le parsing multi-captures dans un pool :

  ```text
  2026-09-25 15:50:49.883 | DEBUG    | MainProcess:MainThread | netcross_core.logging_config:configure_logging:129 - tracing debug actif : niveau=DEBUG fichier=aucun pid=12710 python=3.14.3
  ```

- les `logger.exception` affichent la **pile complète avec la valeur des variables** (`backtrace` et `diagnose` de loguru) :

  ```text
    File ".../cross_capture_analyzer_cli.py", line 2641, in main
      pkts = parse_capture(label, path, raise_on_error=True)
             │             │      └ 'tests/data/does_not_exist.pcap'
             │             └ 'A'
  ```

!!! warning "Données sensibles"
    En mode debug, les tracebacks annotés peuvent contenir des valeurs issues des captures (adresses, contenus). Le mode debug sert au diagnostic : ne pas le laisser actif en production et ne pas partager ses logs sans les relire.

## Copier les logs dans un fichier

`NETCROSS_LOG_FILE=chemin` ajoute une copie des logs dans un fichier, avec rotation à 10 Mo et 5 fichiers conservés, sans codes couleur. C'est pratique pour la GUI, dont le stderr n'est pas visible quand elle est lancée depuis le menu du bureau :

```bash
NETCROSS_LOG_FILE=~/netcross-debug.log netcross-gui --debug
```

## Utiliser `pcap_parser` comme bibliothèque (issue #446)

`pcap_parser` est la couche la plus basse du projet : il n'importe pas `netcross_core` (contrat import-linter) et utilise loguru directement. En usage bibliothèque (script, notebook, code tiers), sans appel à `configure_logging()`, le handler par défaut de loguru écrirait sur stderr dès le niveau `DEBUG`.

Pour éviter ce bruit, `pcap_parser/__init__.py` désactive loguru pour son propre package (`logger.disable("pcap_parser")`). Les points d'entrée Netcross (CLI, GUI, API) le reactivent via `configure_logging()` (`logger.enable("pcap_parser")`), quel que soit l'ordre des imports.

**En usage bibliothèque seule**, pour voir les logs de `pcap_parser` :

```python
from loguru import logger
logger.enable("pcap_parser")

from pcap_parser import parse_capture
# les logs DEBUG de pcap_parser sont maintenant visibles
```

Ou en appelant `configure_logging()` de `netcross_core` (qui active aussi le format structuré et le niveau configurable) :

```python
from netcross_core.logging_config import configure_logging
configure_logging("DEBUG")  # active pcap_parser + tous les modules netcross

from pcap_parser import parse_capture
```

Sans l'un de ces deux appels, `pcap_parser` est silencieux.

## Règles pour les contributeurs

Ces règles sont vérifiées par `tests/test_loguru_regles.py` et `tests/test_loguru_formatting.py` :

- chaque `except` contient un appel loguru (`logger.debug`, `warning`, `error`, `exception`, ou `trace` pour du code appelé à chaque paquet) ;
- aucun `import logging` : loguru le remplace ;
- tout module qui définit des fonctions a un logger au niveau du module ;
- les messages utilisent les placeholders `{}` de loguru avec autant d'arguments que de `{}`, jamais d'accolades brutes sans argument ;
- les messages résument (comptages, drapeaux, chemins) plutôt que de sérialiser des objets entiers ;
- les messages de log ne sont pas traduits : ils restent en français.

Les `print()` qui produisent la sortie d'une commande (rapport texte, résumé NetFlow, messages d'erreur d'usage des CLI) ne sont pas des logs et restent des `print()`.
