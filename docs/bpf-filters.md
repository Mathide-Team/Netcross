# Filtres BPF : catalogue, sauvegarde et partage

Job 47 (issue #167). Les filtres BPF de la capture en direct
(`--live LABEL:INTERFACE[:BPF]`, onglet « Capture en direct » de la GUI) se
saisissaient à la main à chaque session. Ils peuvent désormais être choisis
dans un catalogue, sauvegardés sous un nom, et partagés.

Code : `netcross_core.models.BPFFilter` et `netcross_core.bpf_filters`.

## Dans la GUI

Chaque point de capture en direct a, à droite du champ « filtre BPF » :

- un **menu déroulant « Filtres… »** : le catalogue prédéfini, puis vos filtres
  sauvegardés. Choisir un filtre recopie son expression dans le champ. Si vous
  éditez ensuite le champ à la main, le menu revient sur « Filtres… » (il
  n'annonce plus un filtre qui n'est plus celui du champ) ;
- un **bouton disquette** : enregistre le filtre *courant* du champ sous un nom
  (description facultative). Le nouveau filtre apparaît aussitôt dans le menu
  de tous les points de capture.

Les erreurs (champ vide, nom déjà pris par le catalogue, fichier illisible,
erreur d'écriture) s'affichent dans la fenêtre de sauvegarde ; rien n'est
écrit dans ces cas.

## Par l'API

Issue #906. La bibliothèque est aussi gérée par l'API REST, sur le même
fichier (celui du serveur : `$NETCROSS_API_BPF_FILTERS` s'il est défini,
sinon `~/.netcross/bpf_filters.json` du compte qui exécute l'API) :

```bash
# catalogue prédéfini puis filtres enregistrés ("predefined": true/false)
curl -H "X-API-Key: $NETCROSS_API_TOKEN" http://localhost:8000/bpf-filters

# enregistrer (ou remplacer) un filtre
curl -X PUT -H "X-API-Key: $NETCROSS_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"expression": "host 10.0.0.1 and tcp", "description": "Serveur web"}' \
  "http://localhost:8000/bpf-filters/Serveur%20web"

# supprimer
curl -X DELETE -H "X-API-Key: $NETCROSS_API_TOKEN" "http://localhost:8000/bpf-filters/Serveur%20web"
```

Mêmes règles qu'en GUI : un nom du catalogue est refusé (409), une
expression vide aussi (422), un fichier illisible n'est jamais écrasé (500,
fichier intact). Un filtre enregistré par l'API est aussitôt utilisable par
`--bpf-library NOM` et apparaît dans le menu « Filtres… » de la GUI.

## Catalogue prédéfini

| Nom | Expression BPF |
|---|---|
| HTTP | `tcp port 80` |
| HTTPS | `tcp port 443` |
| DNS | `port 53` |
| TCP (retransmissions) | `tcp` |
| TCP SYN/RST | `tcp[tcpflags] & (tcp-syn\|tcp-rst) != 0` |
| ARP | `arp` |
| ICMP | `icmp or icmp6` |
| DHCP | `udp port 67 or udp port 68` |
| SIP | `port 5060 or port 5061` |
| QUIC | `udp port 443` |
| Fragments IPv4 | `(ip[6:2] & 0x3fff) != 0` |

Les 11 expressions ont été compilées avec libpcap 1.10.4 (`tcpdump -d`).

**« TCP (retransmissions) » capture tout le TCP**, pas seulement les
retransmissions : BPF est un filtre sans état, il ne peut pas reconnaître un
paquet comme retransmis. La détection se fait ensuite, à l'analyse.

## Fichier de sauvegarde

Par défaut : `~/.netcross/bpf_filters.json` (dossier créé au besoin). Absent au
premier lancement : c'est normal.

```json
{
  "version": 1,
  "filters": [
    {
      "name": "mon serveur",
      "expression": "host 10.0.0.1 and tcp",
      "description": "accès au serveur SQL"
    }
  ]
}
```

`description` est facultative. Une simple liste d'objets (sans l'enveloppe
`version`/`filters`) est aussi acceptée en lecture.

Règles :

- les noms sont comparés sans tenir compte de la casse ni des espaces de
  bordure ; enregistrer un filtre de même nom **remplace** l'ancien ;
- les noms du catalogue sont **réservés** : les enregistrer est refusé, et une
  entrée de même nom trouvée dans un fichier édité à la main est ignorée
  (pour ne pas afficher de doublon) ;
- l'écriture est atomique (fichier temporaire puis remplacement) ;
- un fichier illisible ou mal formé n'est **jamais écrasé** : la GUI démarre
  avec le seul catalogue (avertissement sur stderr) et refuse d'enregistrer
  tant que le fichier n'est pas réparé ou supprimé.

## Partager des filtres

Le fichier est du JSON lisible : il suffit de le copier (ou de coller ses
entrées dans celui d'un collègue). En Python, chaque fonction accepte un
`path` explicite :

```python
from netcross_core.bpf_filters import available_bpf_filters, upsert_bpf_filter
from netcross_core.models import BPFFilter

upsert_bpf_filter(BPFFilter("voix", "udp portrange 10000-20000"), "equipe.json")
available_bpf_filters("equipe.json")  # catalogue + filtres de equipe.json
```

## Limites

- **La syntaxe BPF n'est pas validée** par netcross (cela exigerait libpcap).
  L'expression est transmise telle quelle à tshark (`-f`), qui la rejette avec
  son propre message si elle est invalide.
- Pas de suppression ni d'édition d'un filtre sauvegardé dans la GUI : éditer
  ou effacer l'entrée dans le fichier JSON.
