# Comparer deux situations

Après un changement (nouvelle configuration, remplacement d'un
équipement, correctif appliqué), la vraie question est : « est-ce mieux
qu'avant ? ». `cross_capture_diff_cli.py` (commande `netcross-diff`)
analyse deux jeux de captures et liste ce qui s'est dégradé ou amélioré.

- **baseline** : la situation de référence, souvent « avant » ;
- **courant** : la situation à juger, souvent « après ».

Utilisez les **mêmes noms de points** des deux côtés (`LAN`, `WAN`...),
sinon Netcross ne peut pas comparer point par point.

## Exemple : le problème est-il corrigé ?

Le dossier `docs/guide/exemples/` contient la situation « avant »
(`lan.pcap`, `wan.pcap`, avec 5 paquets perdus) et une situation « après »
corrigée (`lan_apres.pcap`, `wan_apres.pcap`, sans perte).

```bash
python3 src/cross_capture_diff_cli.py \
    --baseline LAN=docs/guide/exemples/lan.pcap \
    --baseline WAN=docs/guide/exemples/wan.pcap \
    --current  LAN=docs/guide/exemples/lan_apres.pcap \
    --current  WAN=docs/guide/exemples/wan_apres.pcap \
    --triage
```

```text
0 regression(s), 1 amelioration(s), 0 point(s) a verifier

-- AMELIORATIONS --
  [Pertes        ] WAN                  : taux de pertes 4.1% (5/121) -> 0.0% (0/126)
[...]
Score de sante : 100/100 (Bon)
```

La correction est confirmée : les pertes côté WAN sont passées de 4,1 % à 0.
Le score de santé mesure ici **l'ampleur des régressions**, et non l'état
absolu du réseau : 100 signifie « aucune dégradation par rapport à la
référence ».

## Utilisation dans un script ou une CI

La commande se termine avec le **code 1 dès qu'une régression est
détectée**, et 0 sinon. En inversant les deux jeux de l'exemple :

```text
1 regression(s), 0 amelioration(s), 0 point(s) a verifier

-- REGRESSIONS (ca allait mieux avant) --
  [Pertes        ] WAN                  : taux de pertes 0.0% (0/126) -> 4.1% (5/121)
```

Code de sortie : 1. On peut ainsi bloquer un déploiement qui dégrade le
réseau, par exemple :

```bash
netcross-diff --baseline LAN=reference.pcapng --current LAN=nouvelle.pcapng \
    --diff-csv ecarts.csv || echo "Régression réseau détectée, voir ecarts.csv"
```

## Dans l'interface graphique

Cochez **Mode comparaison** dans l'onglet Configuration : deux listes
apparaissent, **Baseline** et **Courant**. Ajoutez les captures de chaque
côté avec les mêmes noms de points, puis lancez l'analyse. Le rapport
affiché est celui de `netcross-diff`.

La case « Triage des écarts (classement des segments) » et son champ
« Top » ajoutent au rapport le classement des segments à regarder en
premier, ainsi que le score de santé, comme `--triage` et
`--triage-top-n` (défaut : 5). Les options d'analyse (fenêtre NAT,
coupure silencieuse, doublons...) s'appliquent aux deux côtés.

Pour capturer le courant **en direct**, cochez aussi « Capture en
direct » : le panneau des points de capture remplace la liste Courant, et
la comparaison démarre à l'arrêt de la capture (équivalent de
`--live-current`, voir [Interface graphique](interface-graphique.md)).

## Options utiles

| Besoin | Option |
|---|---|
| Rapport PDF de la comparaison | `--pdf-report comparaison.pdf` |
| Détail des écarts en tableur | `--diff-csv ecarts.csv` |
| Export structuré | `--json-report comparaison.json` |
| Capturer le « courant » en direct | `--live-current LAN:eth0` (avec `--live-duration 60`) |
| Diagnostics TLS/QUIC de chaque côté | `--tls`, `--quic` |
| Garder une trace de chaque comparaison | `--history-db suivi.db`, puis `netcross-history --db suivi.db` |

La référence (`--baseline`) est toujours un fichier : on ne compare qu'à
une situation déjà enregistrée.

## Comparer des postes entre eux

Pour le cas « ce poste fonctionne, l'autre non », sur les **mêmes**
captures, utilisez plutôt l'analyse principale avec `--client-group` :

```bash
python3 src/cross_capture_analyzer_cli.py \
    --capture LAN=lan.pcapng --capture WAN=wan.pcapng \
    --client-group PosteOK=10.0.0.5 \
    --client-group PosteKO=10.0.0.12 \
    --client-reference PosteOK \
    --client-diff-csv postes.csv
```

Chaque poste est analysé séparément, puis comparé au poste de référence.
