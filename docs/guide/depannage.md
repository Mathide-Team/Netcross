# Dépannage

## Un fichier n'a pas été lu

```text
[LAN] ECHEC sur lan.pcap : tshark introuvable dans le PATH [...]
ATTENTION : au moins un fichier n'a pas pu etre lu [...]
```

!!! danger "Le rapport produit après un ECHEC est incomplet"
    L'analyse continue avec les fichiers lus, et le rapport qui suit peut
    paraître normal, voire annoncer « aucune perte », alors qu'un point, ou
    tous, manquent. Vérifiez toujours les lignes de chargement avant de lire
    le reste. Pour un script, ne vous fiez pas au code de sortie : il vaut
    actuellement 0 même dans ce cas (défaut suivi dans le dépôt).

Causes les plus fréquentes :

| Message | Cause | Solution |
|---|---|---|
| `tshark introuvable dans le PATH` | Wireshark en ligne de commande absent | `sudo apt install tshark` ou `sudo dnf install wireshark-cli` |
| `The file "..." doesn't exist` | Chemin erroné | Vérifier le chemin, relatif au dossier courant |
| `fichier de capture introuvable : ...` | Chemin erroné | Vérifier le chemin, relatif au dossier courant |
| `droits insuffisants pour lire ... (proprietaire uid ..., droits ...)` | Fichier illisible pour l'utilisateur, souvent créé ou téléchargé en root | Appliquer la commande `chown`/`chmod` proposée dans le message |
| `You don't have permission to read the file` | tshark confiné (paquet snap, AppArmor) qui ne peut pas ouvrir ce dossier | Netcross réessaie automatiquement en transmettant le fichier à tshark sur son entrée standard (ligne `lecture via l'entrée standard` dans le journal) ; si l'échec persiste, copier la capture dans votre dossier personnel |

!!! tip "Pas besoin de root pour lire une capture"
    Seule la capture en direct sur une interface demande des privilèges
    (groupe `wireshark` ou capacités de `dumpcap`). Pour analyser un fichier,
    les droits de lecture suffisent : lancer Netcross avec `sudo` empêche en
    revanche l'interface graphique de s'afficher (voir plus bas).

!!! warning "Capture tronquée"
    Une capture interrompue brutalement (disque plein, arrêt forcé) est lue
    jusqu'à la coupure, **sans message** : le rapport porte alors sur une
    partie seulement du trafic. Comparez le nombre de paquets et la durée
    affichés dans « Métadonnées de capture » à ce que vous attendiez, ou
    vérifiez le fichier avec `capinfos fichier.pcapng`.

## Messages d'erreur de la ligne de commande

| Message | Explication |
|---|---|
| `Format invalide pour --capture: lan.pcap (attendu NOM=chemin[,chemin2,...])` | Chaque capture doit être nommée : `--capture LAN=lan.pcap` |
| `unrecognized arguments: ...` | Option inconnue ou mal orthographiée : voir `--help` |
| `... mutuellement exclusif ...` ou `... incompatible avec ...` | Deux options qui ne se combinent pas, par exemple `--live` et `--capture`, ou `--redact` et `--tls` |

## Le résultat semble faux

- **Des pertes partout, ou une topologie incohérente** : les captures ne
  couvrent peut-être pas la même période. Vérifiez les durées dans la
  section « Métadonnées de capture ».
- **Un NAT entre deux points** : sans `--nat-tolerant`, les paquets
  traduits ne sont pas reconnus d'un point à l'autre et passent pour des
  pertes.
- **Une latence négative ou absurde** : les horloges des machines de
  capture ne sont pas synchronisées. Lisez la « latence corrigée ».
- **L'ordre des points est faux** : imposez-le avec `--order A,B,C`.
  Netcross signale alors toute incohérence avec ce qu'il observe.
- **Des paquets comptés en double** : un port miroir mal configuré peut
  copier deux fois le même trafic. Utilisez `--detect-duplicates`, puis
  `--exclude-duplicates`.

## Grosses captures

Une capture de plusieurs Go peut épuiser la mémoire.

- `--parallel` accélère la lecture, à condition d'avoir plusieurs cœurs.
- `--sample 1/50` n'analyse qu'un paquet sur 50.
- `--max-packets 1000000` s'arrête au millionième paquet.
- Mieux encore : filtrer dès la capture (`tcpdump ... host 203.0.113.10`),
  ou découper le fichier avec `editcap`.

## L'interface graphique ne démarre pas

- `impossible d'ouvrir l'interface graphique (aucun affichage accessible)` :
  la GUI a été lancée sans session graphique utilisable, le plus souvent en
  root (`sudo`, `su`) ou via SSH. Relancez-la avec votre utilisateur habituel,
  sans `sudo`. Sans affichage, toutes les analyses restent disponibles en
  ligne de commande : `netcross --help` (depuis les sources :
  `python3 src/cross_capture_analyzer_cli.py --help`).
- `No module named 'gi'` : PyGObject est absent. Installez
  `python3-gi gir1.2-gtk-4.0` (Debian/Ubuntu) ou
  `python3-gobject gtk4` (RHEL/Rocky). Il ne s'installe pas avec pip.
- Sur Rocky/RHEL 8, GTK4 n'est pas toujours disponible : utilisez la ligne
  de commande (`./install.sh --cli-only`), qui offre toutes les analyses.

## Premier lancement

Au premier démarrage, Netcross ne trouve encore ni filtres BPF enregistrés
(`~/.netcross/bpf_filters.json`) ni, lancé depuis les sources, de catalogue
de traduction compilé. Ces deux situations sont normales : le catalogue de
filtres prédéfinis est proposé et l'interface s'affiche en français. Elles ne
produisent plus de message `ERROR` ; le détail reste visible avec `--debug`.

## Obtenir plus de détails

`--debug` (ou la variable `NETCROSS_DEBUG=1`) active le journal détaillé ;
`NETCROSS_LOG_FILE=netcross.log` l'écrit dans un fichier. Pour signaler un
problème, joignez ce journal et la sortie complète : ils ne contiennent
pas les paquets eux-mêmes. `--support-ticket ticket.json --support-consent`
produit un ticket de support anonymisé, transmissible sans exposer
l'adressage du réseau ([Tickets de support](../support-tickets.md)).
