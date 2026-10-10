# Remontée de tickets anonymisés (issue #269)

Netcross peut produire un **ticket de support anonymisé** : un fichier JSON
autoportant décrivant un incident (crash, erreur de traitement) ou
simplement l'état d'un run qui s'est bien passé, transmissible à un tiers
sans exposer l'adressage réel du réseau ni l'identité de l'opérateur.

Trois principes gouvernent cette fonctionnalité.

1. **Rien n'est produit sans autorisation explicite.** `--support-ticket`
   seul échoue ; il faut `--support-consent`. Ce n'est pas un
   avertissement que l'on peut ignorer, c'est une précondition vérifiée au
   moment de l'écriture (`ConsentRequiredError` côté API).
2. **L'anonymisation précède l'écriture.** Le texte réel ne transite dans
   aucun champ du fichier : il est nettoyé au moment de la construction du
   ticket. Un ticket est donc sûr à transmettre dès l'instant où il existe.
3. **On remonte toujours quelque chose, même quand tout va bien.** Un run
   sans incident produit un ticket de nature `diagnostic` qui atteste
   explicitement du bon fonctionnement. Voir
   [la règle de traçabilité](quality/traceability-rule.md) : un champ vide
   est un résultat affirmé, pas une information manquante.

## Utilisation en ligne de commande

```bash
# Ticket de diagnostic après un run normal
python3 src/cross_capture_analyzer_cli.py \
    --capture POINT_A=/chemin/a.pcapng \
    --capture POINT_B=/chemin/b.pcapng \
    --support-ticket ticket.json \
    --support-consent
```

En cas de crash, un gestionnaire installé en début de run écrit le ticket
avec la trace d'appels anonymisée avant de laisser l'exception remonter
normalement — le crash n'est jamais masqué.

### Options

| Option | Rôle |
|---|---|
| `--support-ticket CHEMIN` | Fichier JSON à écrire |
| `--support-consent` | **Obligatoire.** Autorisation explicite |
| `--support-scope PORTEES` | Restreint le contenu (voir ci-dessous) |
| `--support-map CHEMIN` | CSV privé réel ↔ pseudonyme (à ne jamais transmettre) |
| `--support-marker CLE=VALEUR` | Marqueur de corrélation, répétable |

### Portées de consentement

L'utilisateur autorise des **catégories de contenu**, pas un ticket en
bloc. Par défaut les quatre portées sont accordées.

| Portée | Contenu |
|---|---|
| `environnement` | OS, version, architecture, version de Python, présence de tshark |
| `journal` | Lignes de journal joints au ticket |
| `trace_appels` | Trace d'appels Python en cas de crash |
| `marqueurs` | `trace_id`, `capture_id`, `run_id` de corrélation |

```bash
# Ticket minimal : ni journal, ni trace d'appels
--support-ticket t.json --support-consent --support-scope environnement,marqueurs
```

Ce qui n'est pas autorisé est **absent** du ticket, et son absence est
inscrite dans la section `auto_verification` du fichier. Le destinataire
distingue donc « contenu non autorisé » de « collecte défaillante ».

### Marqueurs de corrélation

Pour la campagne de tests sur cent traces
([plan d'anonymisation](quality/anonymization-plan.md)), les marqueurs
relient un ticket à une trace précise sans nommer le fichier réel :

```bash
--support-marker trace_id=T-042 --support-marker capture_id=C-7
```

Un `run_id` aléatoire est généré s'il n'est pas fourni.

## Ce qui est anonymisé

Le module `netcross_core.support.scrubber` traite le **texte libre** —
messages d'exception, traces d'appels, lignes de journal, chemins. Il
complète `netcross_core.redact`, qui ne traite que les champs structurés
de paquets déjà décodés ; aucun des deux ne remplace l'autre.

| Catégorie | Exemple réel | Résultat |
|---|---|---|
| `ipv4` | `10.1.2.3` | `192.0.2.1` (RFC 5737) |
| `ipv6` | `fe80::1c2d` | `2001:db8::1` (RFC 3849) |
| `mac` | `aa:bb:cc:dd:ee:ff` | `02:00:00:00:00:00` (OUI local) |
| `email` | `jean.dupont@acme.fr` | `user-1@example.invalid` |
| `url` | `https://intranet.acme.local/api` | `https://host-1.example.invalid/redacted` |
| `hostname` | `srv-compta.acme.local` | `host-1.example.invalid` |
| `capture` | `client_acme_site3.pcapng` | `capture-1.pcapng` |
| `path` | `/home/jdupont/…` | `/home/user-1/…` |
| `secret` | `password=S3cret` | `password=[SECRET-REDIGE]` |

Deux détails de conception qui comptent :

- **Les pseudonymes sont stables.** La même valeur réelle reçoit toujours
  le même pseudonyme dans tout le ticket — la trace d'appels, le journal et
  le nom de capture restent corrélables entre eux.
- **Un secret est écrasé, pas pseudonymisé.** Un mot de passe n'a aucune
  valeur de corrélation, seulement un risque de fuite. La *clé* est
  conservée (`password=`) car savoir qu'un secret figurait là est un signal
  de diagnostic utile.

### Limites assumées

Elles sont inscrites dans **chaque** rapport d'anonymisation, y compris
quand rien n'a été rédigé :

- un nom d'hôte sans point (`SRVCOMPTA01`) reste en clair — il est
  indissociable d'un mot ordinaire du message ;
- un identifiant métier libre (numéro de dossier, nom de site) reste en
  clair — aucun motif ne permet de le reconnaître.

Relire un ticket avant transmission reste donc une bonne pratique. C'est
précisément pour cela que ces limites sont écrites dans le fichier plutôt
que laissées à la découverte du lecteur.

## Structure du ticket

```json
{
  "schema_version": "1.0",
  "ticket_id": "…",
  "nature": "diagnostic",
  "cree_le": "2026-09-22T12:00:00+00:00",
  "consentement": { "accorde": true, "portees": ["environnement", "…"] },
  "marqueurs": { "trace_id": "T-042", "run_id": "a1b2c3d4e5f6" },
  "environnement": { "systeme": "Linux", "tshark_disponible": "oui" },
  "incident": null,
  "erreurs_traitement": [],
  "journal": ["captures analysees : 2"],
  "anonymisation": {
    "statut": "aucune_donnee_sensible_detectee",
    "total_occurrences": 0,
    "par_categorie": {},
    "limites": ["…"],
    "mapping_joint": false
  },
  "auto_verification": [
    { "controle": "incident", "statut": "ok",
      "detail": "aucune exception : execution sans incident signale" }
  ]
}
```

Les sections `anonymisation` et `auto_verification` sont **toujours**
présentes. `statut: "aucune_donnee_sensible_detectee"` affirme que la passe
a bien eu lieu et n'a rien trouvé — ce qui n'est pas la même chose qu'une
passe qui aurait échoué en silence.

## Le fichier de correspondance

`--support-map` écrit un CSV `valeur_reelle,pseudonyme,categorie` destiné à
**l'opérateur seul**. Il permet de relire plus tard un ticket anonymisé à
la lumière du vrai réseau (« à quelle machine correspond `host-3` ? »).

Le transmettre avec le ticket annulerait entièrement l'anonymisation. Même
discipline que `--redact-map`.

## Interface graphique (issues #674, #877)

Page Résultats, panneau « SIEM, ticket de support, historique », après
une analyse de fichiers :

| Réglage | Équivalent CLI |
| --- | --- |
| case « J'autorise la remontee d'un ticket anonymise » | `--support-consent` |
| cases « Environnement », « Journal », « Trace d'appels », « Marqueurs » (toutes cochées par défaut, au moins une) | `--support-scope` |
| champ des marqueurs `CLE=VALEUR`, séparés par `;` | `--support-marker` (répétable) |
| bouton « Ticket de support (--support-ticket)... » | `--support-ticket` |
| bouton « Correspondance du ticket (--support-map)... », actif après un ticket | `--support-map` |

Un marqueur mal formé est refusé avec le message de la CLI et aucun
ticket n'est écrit. La correspondance est celle du dernier ticket écrit
(même CSV que `--support-map`) ; une nouvelle analyse l'oublie.

## Utilisation programmatique

```python
from netcross_core.support import Consent, TextScrubber, build_ticket, write_ticket

consent = Consent(granted=True, source="gui")
scrubber = TextScrubber()

try:
    analyser()
except Exception as exc:
    ticket = build_ticket(
        consent=consent,
        kind="crash",
        exception=exc,
        markers={"trace_id": "T-042"},
        scrubber=scrubber,
    )
    write_ticket(ticket, "ticket.json")
```

`build_ticket()` ne touche jamais au disque ; seul `write_ticket()` écrit,
et il refuse (`ConsentRequiredError`) si le consentement porté par le ticket
n'est pas accordé. Il n'existe aucun chemin de code produisant un fichier
sans autorisation.
