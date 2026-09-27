# Guide utilisateur

Ce guide s'adresse à celles et ceux qui **utilisent** Netcross pour dépanner
un réseau : administrateurs, équipes support, ingénieurs réseau. Il n'exige
aucune connaissance du code. Pour contribuer au projet, voir plutôt
`CONTRIBUTING.md` et la section Architecture.

## À quoi sert Netcross

Une capture Wireshark prise à un seul endroit montre qu'un problème
existe, rarement **où** il apparaît. Netcross compare plusieurs captures
prises **au même moment** à différents points d'un chemin réseau (poste
client, sortie de LAN, WAN, datacenter...) et localise le segment où les
choses se dégradent :

- un paquet vu en amont mais jamais en aval : **perte** sur ce segment ;
- un écart de temps entre deux points : **latence et gigue** du segment ;
- un TTL qui diminue : **nombre de routeurs** traversés ;
- un marquage QoS, une taille de segment TCP ou une option qui change :
  **équipement qui modifie le trafic** en route.

Il fonctionne aussi sur une seule capture (diagnostic TCP, DNS, HTTP, TLS,
sécurité...), mais c'est à plusieurs points qu'il apporte le plus.

## Parcours conseillé

| Étape | Page |
|---|---|
| 1. Installer l'outil et `tshark` | [Installation](installation.md) |
| 2. Réussir des captures exploitables | [Préparer les captures](preparer-captures.md) |
| 3. Lancer une première analyse, en ligne de commande | [Première analyse](premiere-analyse.md) |
| 4. Ou avec l'interface graphique | [Interface graphique](interface-graphique.md) |
| 5. Comprendre ce que dit le rapport | [Lire le rapport](lire-le-rapport.md) |
| 6. Comparer avant/après un changement | [Comparer deux situations](comparer.md) |
| En cas de souci | [Dépannage](depannage.md) |

Deux captures d'exemple sont fournies dans
[`docs/guide/exemples/`](https://github.com/MathildeDec/Netcross/tree/dev/docs/guide/exemples)
pour s'entraîner sans rien capturer soi-même. Les sorties montrées dans ce
guide ont été obtenues avec ces fichiers.

## Les outils fournis

| Commande (paquet .deb/.rpm) | Depuis les sources | Rôle |
|---|---|---|
| `netcross` | `python3 src/cross_capture_analyzer_cli.py` | Analyse croisée de captures |
| `netcross-diff` | `python3 src/cross_capture_diff_cli.py` | Comparaison avant/après |
| `netcross-gui` | `cd src && python3 -m netcross_gtk4.app` | Interface graphique |
| `netcross-batch` | `python3 src/cross_capture_batch_cli.py` | Un dossier entier de captures ([Mode batch](../batch-mode.md)) |
| `netcross-history` | `python3 src/cross_history_cli.py` | Historique des analyses enregistrées |
| `netcross-lua-doc` | `python3 src/netcross_lua_doc_cli.py` | Documentation hors ligne de l'API Lua de Wireshark |
| `netcross-ai-models` | `python3 src/netcross_ai_models_cli.py` | Modèles du module IA local ([Module IA](../module-ia.md)) |

Une API REST est également disponible pour l'intégrer à d'autres outils :
voir [API REST](../api-rest.md).
