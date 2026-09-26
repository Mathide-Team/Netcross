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

`pcap_parser` est la couche la plus basse du projet : il n'importe pas `netcross_core` (contrat import-linter) et utilise loguru directement. Sans précaution, un script, un notebook ou du code tiers qui l'importe seul hériterait du handler par défaut de loguru, qui écrit sur stderr dès le niveau `DEBUG`.

`pcap_parser/__init__.py` applique donc la [convention loguru pour les bibliothèques](https://loguru.readthedocs.io/en/stable/overview.html#suitable-for-scripts-and-libraries) : `logger.disable("pcap_parser")`. Les points d'entrée Netcross (CLI, GUI, API) le réactivent via `configure_logging()` (`logger.enable("pcap_parser")`), et `--debug`, `NETCROSS_DEBUG` et `NETCROSS_LOG_LEVEL` agissent alors aussi sur `pcap_parser`. `netcross_core.logging_config` importe `pcap_parser` en tête de module : le `disable` s'exécute toujours avant le premier `enable`, quel que soit l'ordre des imports.

**Effet de bord à connaître** : utilisé seul, `pcap_parser` n'écrit plus rien, **pas même ses warnings ni ses erreurs**, tant que ses journaux ne sont pas réactivés. Deux façons de le faire :

```python
# 1. Avec la configuration Netcross (format, niveau, NETCROSS_LOG_FILE)
from netcross_core.logging_config import configure_logging

configure_logging("DEBUG")

from pcap_parser import parse_capture
```

```python
# 2. Avec loguru seul : importer pcap_parser AVANT d'appeler enable,
#    sinon le disable de son __init__ annule le enable.
import pcap_parser
from loguru import logger

logger.enable("pcap_parser")
```

Les processus fils de `parse_captures_parallel` réimportent `pcap_parser` et `netcross_core` : ils suivent `NETCROSS_DEBUG` et `NETCROSS_LOG_LEVEL`, hérités de l'environnement, mais pas l'option `--debug`, qui n'agit que dans le processus principal.

## Règles pour les contributeurs

Ces règles sont vérifiées par `tests/test_loguru_regles.py` et `tests/test_loguru_formatting.py` :

- chaque `except` contient un appel loguru (`logger.debug`, `warning`, `error`, `exception`, ou `trace` pour du code appelé à chaque paquet) ;
- aucun `import logging` : loguru le remplace ;
- tout module qui définit des fonctions a un logger au niveau du module ;
- les messages utilisent les placeholders `{}` de loguru avec autant d'arguments que de `{}`, jamais d'accolades brutes sans argument ;
- les messages résument (comptages, drapeaux, chemins) plutôt que de sérialiser des objets entiers ;
- les messages de log ne sont pas traduits : ils restent en français.

Les `print()` qui produisent la sortie d'une commande (rapport texte, résumé NetFlow, messages d'erreur d'usage des CLI) ne sont pas des logs et restent des `print()`.
