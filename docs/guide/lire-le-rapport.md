# Lire le rapport

Le rapport est le même en console, dans l'interface graphique et dans le
PDF, où il est mis en forme. Il est long parce qu'il passe en revue
chaque module d'analyse, **même quand il n'y a rien à signaler**. Une
ligne « aucun ... détecté » est donc une information : le module a tourné
et n'a rien trouvé.

## Dans quel ordre le lire

1. **Les lignes de chargement** (`[LAN] 129 paquets ... charges`) : chaque
   point doit avoir été lu. Une ligne `ECHEC` signifie que le résultat est
   incomplet (voir [Dépannage](depannage.md)).
2. **Le triage et le score de santé**, en fin de rapport avec `--triage`,
   ou en première page du PDF.
3. **La topologie déduite** : si l'ordre des points trouvé ne correspond
   pas à la réalité, le reste de l'analyse (pertes, latence) est à prendre
   avec prudence. Imposez alors l'ordre avec `--order`.
4. Seulement ensuite, **le détail** des sections mises en avant par le
   triage.

## Le score de santé

```text
Score de sante : 72/100 (A surveiller)
```

| Score | Libellé | Lecture |
|---|---|---|
| 85 à 100 | Bon | Rien de significatif |
| 60 à 84 | A surveiller | Des signaux à examiner, sans urgence |
| 35 à 59 | Degrade | Plusieurs problèmes réels |
| 0 à 34 | Critique | À traiter en priorité |

Chaque constat a un poids : 3 pour une **anomalie**, 1 pour un constat
**à surveiller**, 0 pour une simple **information**. Un segment touché
par plusieurs catégories de problèmes à la fois (par exemple pertes
**et** latence **et** retransmissions) reçoit un bonus : plusieurs preuves
indépendantes qui convergent sont plus fiables qu'un indice isolé. Le
score vaut 100 sans aucun constat, puis baisse de plus en plus lentement
quand le total des poids augmente. Dans l'exemple, une anomalie et un
constat à surveiller (poids total 4) donnent 72.

Le score est une **aide au tri**, pas un verdict. Un réseau à 72 peut
avoir un vrai problème localisé, et un réseau à 90 peut en cacher un que
les captures n'ont pas vu.

## Le triage

```text
1. LAN -> WAN  -- score 3.0
   categories impliquees : Saturation
     [anomalie    ] Saturation     : pertes concentrees sur un palier de debit tres stable, [...]
```

Chaque entrée est un **segment** (`LAN -> WAN`, entre deux points) ou un
**point** (`WAN`). Les segments sont classés du plus au moins urgent.
Chaque constat indique :

- sa **gravité** : `anomalie`, `a_surveiller` ou `info` ;
- sa **catégorie** : Pertes, Latence, Saturation, TCP, DNS, TLS, etc. ;
- une phrase d'explication et, quand c'est possible, des **preuves** : les
  paquets ou échanges précis qui ont conduit au constat, à retrouver dans
  Wireshark par leur numéro de trame.

## Les sections principales

Avec une seule capture, les sections qui comparent des points entre eux
(topologie, points sans relation directionnelle, pertes, trafic hors
chemin, latence, sauts de routeur, changements QoS entre points) ne sont
pas affichées. Elles sont remplacées par une seule ligne :

```text
-- Capture unique : sections multi-points omises (topologie, pertes, latence, sauts de routeur, QoS entre points) --
```

Les autres sections (TCP, DNS, HTTP, TLS, VLAN, fragmentation...) restent
présentes.

| Section | Ce qu'elle dit | À quoi faire attention |
|---|---|---|
| Topologie déduite | L'ordre des points sur le chemin, avec un niveau de confiance | Une confiance faible ou « ambigu » : fournir `--order` |
| Pertes potentielles | Paquets vus en amont et jamais revus à ce point | Le trafic qui ne passe pas par ce point est compté à part, comme « hors chemin », pas comme une perte |
| Latence / gigue | Temps de passage entre deux points | Nécessite des horloges synchronisées. Sinon, lire la « latence corrigée » |
| Sauts de routeur | Nombre de routeurs entre deux points (baisse du TTL) | Un nombre instable signale un changement de route |
| QoS (DSCP) | Marquage modifié en route | Distingue un switch (niveau 2) d'un routeur (niveau 3) |
| Fragmentation / MTU, PMTUD | Paquets trop gros pour un tunnel ou un lien | Un « trou noir PMTUD » bloque les connexions sans erreur visible |
| Coupure NAT/pare-feu silencieuse | Connexion inactive dont l'état a été oublié par un équipement | Seuil réglable avec `--idle-timeout-seconds` |
| Débit, corrélation débit/pertes | Charge par point, et type de perte | Saturation progressive, limitation nette (policing) ou pertes sans lien avec le débit |
| TCP | Fenêtre à zéro, ACK dupliqués, RST, retransmissions classées par cause | Une retransmission « rapide » est un fonctionnement normal |
| Trous de séquence TCP | Données jamais vues à un point | « de capture » : défaut de la capture, pas du réseau |
| DNS, HTTP, DHCP, SIP, RTP | Transactions incomplètes, erreurs, durées | Une erreur 5xx ou un SERVFAIL est souvent un problème **applicatif**, pas réseau |
| Décomposition réseau / serveur | Part du temps passée sur le réseau et côté serveur | Tranche entre « le réseau est lent » et « l'application est lente » |

Quand Netcross ne peut pas conclure, il l'écrit (« indéterminé »,
« impossible de conclure ») plutôt que de deviner. C'est volontaire.

## Les autres formats

- **PDF** (`--pdf-report`) : destiné à être transmis. Il s'ouvre sur « Par
  où commencer » (score et segments prioritaires), suivi d'une synthèse,
  de graphiques et du détail par module.
- **JSON** (`--json-report`) : les mêmes informations, structurées pour
  un script ou un outil de supervision.
- **CSV** (`--detail-csv`) : une ligne par flux, pour un tableur.
- **Rapport de sécurité** (`--security-report`, `--security-html`) : voir
  [Rapport de sécurité](../security-report.md).
