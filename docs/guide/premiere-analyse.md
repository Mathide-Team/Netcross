# Première analyse

Ce tutoriel utilise les deux captures d'exemple du dépôt,
`docs/guide/exemples/lan.pcap` et `wan.pcap`. Elles décrivent une situation
simple et **connue d'avance**, ce qui permet de vérifier que Netcross la
retrouve :

- un poste (`10.0.0.5`) ouvre trois connexions HTTPS vers un serveur
  (`203.0.113.10`) ;
- le trafic est capturé côté LAN, puis côté WAN après un routeur ;
- chaque paquet met 4 ms pour aller d'un point à l'autre ;
- **5 paquets** de la première connexion n'arrivent jamais côté WAN.

Le script `generer_exemple.py`, dans le même dossier, recrée ces fichiers.

## Lancer l'analyse

Chaque capture est passée avec `--capture NOM=fichier`. Le nom est libre :
c'est ainsi que le point apparaîtra dans le rapport.

```bash
python3 src/cross_capture_analyzer_cli.py \
    --capture LAN=docs/guide/exemples/lan.pcap \
    --capture WAN=docs/guide/exemples/wan.pcap \
    --triage \
    --pdf-report rapport.pdf
```

Avec le paquet installé, `netcross` remplace
`python3 src/cross_capture_analyzer_cli.py`.

L'ordre des `--capture` n'a pas d'importance : Netcross déduit lui-même
l'ordre des points. `--triage` ajoute en fin de sortie le classement des
problèmes par priorité, et `--pdf-report` produit le rapport à transmettre.

## Ce que Netcross a trouvé

Extraits de la sortie, dans l'ordre où ils apparaissent :

```text
[LAN] 129 paquets IP/TCP/UDP/ICMP charges depuis docs/guide/exemples/lan.pcap
[WAN] 124 paquets IP/TCP/UDP/ICMP charges depuis docs/guide/exemples/wan.pcap
```

Les deux fichiers ont été lus. Vérifiez toujours ces lignes en premier : un
fichier illisible y apparaît sous la forme `ECHEC` (voir
[Dépannage](depannage.md)).

```text
-- Topologie deduite (delta TTL + recouvrement de flux entre points) --
  LAN -> WAN  (confiance 100%, 121 flux communs, votes TTL 121/121, couverture 96%)
```

Netcross a retrouvé l'ordre des points : le trafic passe par le LAN puis
par le WAN. Tous les indices vont dans le même sens (« votes TTL 121/121 »).

```text
-- Pertes potentielles (paquet vu en amont, absent a ce point) --
  WAN             : 5 paquets manquants
```

Les **5 paquets perdus** sont retrouvés et situés : vus au LAN, jamais
arrivés au WAN. Le problème se trouve donc entre ces deux points.

```text
-- Latence / gigue entre points (necessite horloges synchronisees) --
  LAN -> WAN : n=121  moy=4.00ms  min=4.00ms  max=4.00ms  gigue=0.00ms

-- Sauts de routeur (delta TTL) entre points --
  LAN -> WAN : 1 saut(s) routeur le plus frequent (121/121 flux, amont->aval)
```

La latence de 4 ms et le routeur unique entre les deux points sont eux
aussi retrouvés.

```text
-- Integrite de capture : trous de sequence TCP --
  WAN             : 3 trou(s), 2500 octet(s) manquant(s) (0 de capture, 0 perte(s) reseau, 3 indetermine(s))
```

Vu depuis TCP, les 5 paquets perdus forment 3 trous (deux pertes sont
consécutives deux fois). La cause est « indéterminée » parce que les
captures ne contiennent pas d'accusé de réception du serveur : Netcross ne
peut pas trancher entre un paquet perdu sur le réseau et un paquet
simplement absent de la capture. Quand il ne peut pas conclure, il le dit
plutôt que de deviner.

## Le triage : par où commencer

```text
1. LAN -> WAN  -- score 3.0
   categories impliquees : Saturation
     [anomalie    ] Saturation     : pertes concentrees sur un palier de debit tres stable, [...]
                                     -> limitation/policing probable (seuil configure) [...]

2. WAN  -- score 1.0
   categories impliquees : Pertes
     [a_surveiller] Pertes         : 5 paquets manquants a ce point (4.1% des flux vus)
Score de sante : 72/100 (A surveiller)
```

Le triage classe les segments du plus urgent au moins urgent. Ici, le
segment LAN → WAN arrive en tête : les pertes s'y produisent alors que le
débit est parfaitement stable, ce qui ressemble à une limitation de débit
(policing) configurée sur un équipement. Dans cet exemple synthétique, le
débit est constant par construction, d'où ce diagnostic. Sur un vrai
réseau, c'est une piste à confirmer en regardant la configuration de
l'équipement situé entre les deux points.

Le **score de santé** résume l'ensemble sur 100. Son interprétation est
détaillée dans [Lire le rapport](lire-le-rapport.md).

## Le rapport PDF

`rapport.pdf` reprend ces résultats sous une forme lisible par des
non-spécialistes : page « Par où commencer » avec le score de santé,
synthèse, vue d'ensemble (topologie, débit, latence, pertes par point),
graphiques par protocole et par port, puis le détail de chaque module
d'analyse.

## Et ensuite

- Les mêmes captures dans l'interface graphique :
  [Interface graphique](interface-graphique.md).
- Toutes les sections du rapport : [Lire le rapport](lire-le-rapport.md).
- Les options les plus utiles :

| Besoin | Option |
|---|---|
| Rapport lisible par un script | `--json-report rapport.json` |
| Détail de chaque flux en tableur | `--detail-csv flux.csv` |
| Diagnostic des certificats TLS et de QUIC | `--tls`, `--quic` |
| Recherche de vulnérabilités et de tentatives d'attaque | `--security-report` ([Rapport de sécurité](../security-report.md)) |
| Un NAT entre deux points | `--nat-tolerant` |
| Anonymiser les adresses avant de partager le rapport | `--redact` |
| Imposer ou valider l'ordre des points | `--order LAN,WAN` |
| Capturer en direct plutôt que lire des fichiers | `--live LAN:eth0` |

La liste complète s'obtient avec `--help`.
