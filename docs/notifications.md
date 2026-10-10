# Notifications sortantes

Netcross peut prévenir une équipe quand une analyse révèle un problème grave, par
**webhook** (JSON générique), **Slack** (webhook entrant, Block Kit) ou **courriel** (SMTP).
C'est ce qui rend utile une analyse planifiée (mode lot, tâche cron) : personne ne lit
les rapports d'une analyse qui tourne la nuit.

```bash
netcross-analyze --capture LAN=nuit.pcap --security-report --cve-db cve.db \
    --notify-on elevee --notify-slack "$NETCROSS_SLACK_WEBHOOK" \
    --security-html rapport.html
```

Dans l'interface graphique, les mêmes réglages sont sous les options d'analyse :
menu « Notifier si » (seuil), champs webhook, Slack et courriel, case « Détail
complet ». Ils exigent la case « Rapport de sécurité ». Mêmes garde-fous, même
configuration (`.netcross.toml`, variables d'environnement), même fenêtre
anti-répétition ; le résultat de chaque canal s'affiche au journal et dans la
section « Notifications » du rapport de sécurité.

L'API REST accepte les mêmes réglages sur `POST /captures` et
`POST /captures/multi` : `notify_on`, `notify_webhook`, `notify_slack`,
`notify_email`, `notify_detail`. Mêmes refus (canal sans seuil, URL
invalide, anonymisation `redact=true` qui supprime le rapport de sécurité :
réponse 400). La configuration lue est celle du serveur ; le résultat de
chaque canal est dans `security_report.notifications` de
`GET /analyses/{id}/report`. Les URL ne sont jamais enregistrées avec
l'analyse : seuls le seuil, le détail et les noms des canaux le sont.

```bash
curl -F file=@nuit.pcap -F label=LAN -F notify_on=elevee \
     -F notify_slack="$NETCROSS_SLACK_WEBHOOK" http://localhost:8000/captures
```

## Garde-fous

Un outil qui notifie trop est un outil qu'on coupe. Trois règles, dans cet ordre :

1. **Seuil explicite.** Sans `--notify-on`, aucune notification et **aucun appel
   réseau**, même si des canaux sont configurés dans `.netcross.toml` ou
   l'environnement. Donner `--notify-webhook`/`--notify-slack`/`--notify-email`
   sans `--notify-on` est une erreur, pas une option ignorée en silence.
2. **Une notification par analyse.** Un seul résumé : score, niveau, compteurs par
   sévérité, les trois pires constats au-dessus du seuil et le chemin du rapport.
   Jamais un message par constat.
3. **Anti-répétition.** L'empreinte du lot de constats au-dessus du seuil (sans les
   compteurs d'occurrences ni les numéros de trame) est mémorisée ; le même lot n'est
   pas re-notifié pendant la fenêtre de silence (`--notify-silence HEURES`, 24 h par
   défaut, `0` pour désactiver). L'état (`~/.cache/netcross/notify-state.json`, ou
   `--notify-state`) n'est enregistré que si au moins un canal a réussi.

Le seuil se compare au **niveau** du rapport de sécurité (sévérité du pire constat) :
`critique` > `elevee` > `moyenne` > `faible`.

## Ce qui sort du réseau

Une notification traverse un service tiers. En mode `--notify-detail resume` (défaut) :

- le texte des constats et le chemin du rapport passent par l'anonymiseur des
  tickets de support : adresses IP et MAC, noms d'hôte, courriels, URL et
  répertoires personnels pseudonymisés, secrets rédigés ;
- les champs structurés (hôte, port, source, bannière, version) ne sont **jamais**
  copiés ; une CVE est réduite à son identifiant et son score CVSS ;
- chaque détail est tronqué à 200 caractères.

`--notify-detail complet` envoie le texte brut des constats : à réserver à un canal
de confiance (webhook interne).

## Configuration des canaux

Priorité : ligne de commande > variables d'environnement > `.netcross.toml`.
Les identifiants SMTP ne se passent **jamais** en ligne de commande (ils finiraient
dans l'historique du shell et la liste des processus).

| Canal | Option | Variable d'environnement | `.netcross.toml` `[notify]` |
|---|---|---|---|
| Webhook | `--notify-webhook URL` | `NETCROSS_NOTIFY_WEBHOOK` | `webhook` |
| Slack | `--notify-slack URL` | `NETCROSS_SLACK_WEBHOOK` | `slack_webhook` |
| Courriel | `--notify-email a@x,b@y` | `NETCROSS_NOTIFY_EMAIL` | `email_to` |
| SMTP | -- | `NETCROSS_SMTP_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `_FROM` | `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `smtp_from`, `smtp_starttls` |

```toml
[notify]
slack_webhook = "https://hooks.slack.com/services/..."
email_to = "soc@example.org"
smtp_host = "smtp.example.org"
smtp_port = 587
smtp_starttls = true
silence_hours = 12
```

Seules les URL `http://` et `https://` sont acceptées. Le webhook reçoit le résumé en
JSON (`source`, `score`, `level`, `threshold`, `by_severity`, `total`, `top`,
`report_path`, `fingerprint`, `anonymized`). Si Slack refuse les blocs (HTTP 400), un
second envoi en texte seul est tenté.

## Traçabilité

Un canal en échec ne fait **jamais** échouer l'analyse : l'échec est journalisé en
WARNING et apparaît dans le rapport de sécurité (texte, JSON, HTML) :

```
-- Notifications --
  notification webhook : envoyee
  notification slack : echec, delai depasse
  notification courriel : non configuree
```

Un envoi silencieusement raté est pire que pas d'envoi : on croit être prévenu.
