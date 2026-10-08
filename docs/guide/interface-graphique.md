# Interface graphique

L'interface graphique propose les mêmes analyses que la ligne de commande,
sans commande à écrire. Elle se lance avec :

```bash
netcross-gui                          # paquet installé
cd src && python3 -m netcross_gtk4.app  # depuis les sources
```

Elle comporte trois onglets : **Configuration**, **Travail** et
**Résultats**. Les captures d'écran ci-dessous ont été prises avec les
captures d'exemple de [Première analyse](premiere-analyse.md).

## Configuration

![Onglet Configuration, avec les deux captures d'exemple](images/01-configuration.png)

1. **Ajouter une capture** ouvre un sélecteur de fichiers. Répétez
   l'opération pour chaque point.
2. Renommez chaque point dans le champ de gauche (`LAN`, `WAN`...). Deux
   lignes de même nom forment un seul point : ce sont les fichiers
   successifs d'une capture en rotation, lus dans l'ordre de la liste.
3. **Rangez les points dans l'ordre du chemin réseau** avec les flèches,
   du plus proche de la source au plus éloigné. Contrairement à la ligne
   de commande, l'interface utilise cet ordre tel quel par défaut. Si vous
   ne le connaissez pas, cochez « Déduire la topologie automatiquement » :
   Netcross le retrouve seul, comme en ligne de commande sans `--order`.
4. Choisissez les options, puis cliquez sur **Lancer l'analyse**.

Une seule capture suffit. Le rapport omet alors les sections qui comparent
des points entre eux (topologie, pertes, latence, sauts de routeur) : il
l'indique par une ligne « Capture unique : sections multi-points omises ».
Avec un pcapng pris sur plusieurs interfaces, cochez « Séparer les
interfaces d'un pcapng » : chaque interface devient un point, et l'analyse
croisée se fait entre elles (voir [Préparer les captures](preparer-captures.md)).

Options principales :

| Case ou champ | Effet | Équivalent en ligne de commande |
|---|---|---|
| Triage (classement des segments) et « Top » | Classe les segments à regarder en premier | `--triage`, `--triage-top-n` |
| Corrélation tolérante au NAT | Nécessaire si un NAT est traversé entre deux points | `--nat-tolerant` |
| Lecture parallèle des captures | Plus rapide sur une machine multicœur | `--parallel` |
| Détecter / Exclure les doublons inter-captures | Repère les paquets vus deux fois (miroir mal configuré) | `--detect-duplicates`, `--exclude-duplicates` |
| Anonymiser les adresses IP/MAC | Rapport partageable sans adresses réelles | `--redact` |
| Diagnostic TLS, Diagnostic QUIC/HTTP3 | Certificats, négociations, QUIC | `--tls`, `--quic` |
| Rapport de sécurité | Vulnérabilités et tentatives d'attaque | `--security-report` |
| Notifier si, webhook, Slack, courriel, Détail complet | Envoie un résumé du rapport de sécurité quand son pire constat atteint le seuil choisi (voir [Notifications](../notifications.md)). Nécessite « Rapport de sécurité » ; une URL invalide bloque le lancement. Le résultat de chaque canal s'affiche au journal | `--notify-on`, `--notify-webhook`, `--notify-slack`, `--notify-email`, `--notify-detail` |
| Fenêtre temporelle (ms) | Précision des mesures de débit (réduire pour les micro-rafales) | `--bucket-ms` |
| Séparer les interfaces d'un pcapng | Un fichier capturé sur plusieurs interfaces devient un point par interface, nommé `NOM:INTERFACE` | `--split-interfaces` |

Réglages fins, à ne modifier qu'en connaissance de cause :

| Champ ou bouton | Effet | Équivalent en ligne de commande |
|---|---|---|
| Fenêtre NAT (ms) | Écart maximal entre deux observations d'un même paquet traduit par un NAT. Actif seulement avec la corrélation tolérante au NAT (défaut : 200 ms) | `--nat-window-ms` |
| Coupure silencieuse (s) | Silence au-delà duquel une connexion inactive est signalée comme coupée par un NAT ou un pare-feu. 0 = défaut (60 s) | `--idle-timeout-seconds` |
| Table des noms... / Retirer | Charge un fichier JSON ou YAML de noms lisibles des hôtes (`srv-ad`, `imprimante-rdc`...), repris dans les exports CSV et JSON | `--names` |
| Seuil doublons (ms) | Écart maximal pour considérer deux paquets identiques comme doublons | `--duplicate-threshold-ms` |

En haut de l'onglet, deux cases changent de mode :

- **Mode comparaison** : deux listes de captures, Baseline et Courant,
  pour comparer deux situations. Ce mode a ses propres cases : seuils de
  pertes et de latence, Diagnostic TLS/QUIC et « Triage des écarts »
  (voir [Comparer deux situations](comparer.md)) ;
- **Capture en direct** : un nom, une interface réseau et un filtre BPF
  facultatif par point, au lieu de fichiers. Démarrage et arrêt manuels,
  ou durée maximale. Demande les droits de capture (voir
  [Installation](installation.md)).
  Deux options propres à ce mode : « Rotation de capture » (enregistre
  aussi la capture brute en fichiers tournants) et « Rapport HTML en
  continu ». Ce dernier publie pendant la capture une page `index.html`
  rafraîchie toutes les N secondes (débit, protocoles, hôtes, état de
  chaque point) dans le répertoire choisi, ou dans un répertoire temporaire
  indiqué au journal. Avec « Servir la page », elle est aussi servie sur
  `http://127.0.0.1:PORT/` (port 0 : port libre, indiqué au journal).
  Équivalent de `--live-report`, `--live-report-interval` et
  `--live-report-serve`.

Les deux cases se combinent : **Mode comparaison** et **Capture en
direct** cochées ensemble comparent un baseline enregistré (liste
Baseline) avec un courant capturé en direct (panneau live, qui remplace la
liste Courant). La comparaison démarre à l'arrêt de la capture (bouton ou
durée maximale), avec les seuils et le triage du mode comparaison.
Diagnostic TLS/QUIC, rotation de capture et rapport en continu ne sont
pas disponibles dans cette combinaison. Équivalent de `--live-current` et
`--live-duration` de `cross_capture_diff_cli.py`.

Ces deux modes ne se combinent pas entre eux.

## Travail

![Onglet Travail pendant l'analyse](images/02-travail.png)

Le journal suit chaque étape en temps réel : lecture de chaque fichier
avec son nombre de paquets, corrélation, analyse, mise en forme. Vérifiez
que chaque point a bien chargé des paquets.

## Résultats

![Onglet Résultats](images/03-resultats.png)

La zone principale affiche le même rapport que la ligne de commande
(voir [Lire le rapport](lire-le-rapport.md)). En bas, **Exporter en PDF**,
**Exporter en CSV** et **Exporter en JSON** produisent les mêmes fichiers
que `--pdf-report`, `--detail-csv` et `--json-report`, et
**Nouvelle analyse** revient à la configuration.

Sous le rapport, plusieurs sections se déplient :

- **Cartographie des communications** : qui parle à qui. Un rond par hôte
  (taille proportionnelle au volume), une flèche par sens. **En rouge**, les
  hôtes et échanges qui portent au moins un signal d'anomalie
  (retransmission, alerte tshark). Filtres par protocole, nombre d'échanges
  affichés et « Anomalies seulement ». Deux flèches par conversation TCP
  permettent de voir qu'un sens passe et que l'autre ne répond pas.

  ![Cartographie des communications](images/04-cartographie.png)

- **Annotations / signets** : une étiquette et un commentaire sur un
  numéro de trame (celui qu'affiche Wireshark), pour un point donné.
  Chaque annotation est enregistrée à côté de la capture, dans
  `<capture>.annotations.json`, et retrouvée à la prochaine analyse des
  mêmes fichiers. Clic droit pour ajouter ou supprimer.
- **Dashboard analytique** et **Exploration statistique** : vues
  interactives par segment, flux, hôte et protocole, avec tri et
  regroupement.
- **Sécurité** : le rapport de sécurité, si la case correspondante était
  cochée, avec export HTML et JSON.

Après une comparaison ou une capture en direct, certaines sections sont
grisées : elles ont besoin des fichiers de capture d'une analyse simple.

!!! warning "Grosses captures"
    Le **Dashboard analytique** affiche une ligne par flux, sans limite.
    Sur une capture volumineuse, le déplier peut rendre la fenêtre très
    lente ou dépasser la hauteur de l'écran. Préférez alors
    l'**Exploration statistique** (Top-N réglable) ou l'export CSV.
    Le défaut est suivi dans le dépôt.

## Ce que l'interface ne fait pas

Certaines fonctions restent réservées à la ligne de commande : fusion,
découpage, conversion et rejeu de captures, notifications, plugins,
module IA, historique des analyses, base CVE complète (`--cve-db`),
export SIEM. Voir `--help` et les pages de la section Analyses.
