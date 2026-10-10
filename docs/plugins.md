# Plugins : détecteurs et sorties tierces

Deux besoins justifient un système de plugins, et seulement eux :

1. **un détecteur propre à un site** (signature interne, protocole métier maison) qui
   n'a pas à entrer dans le dépôt Netcross et dont l'auteur ne devrait pas avoir à forker ;
2. **une sortie propre à une plateforme** (format SIEM interne) qui n'a pas sa place dans
   `siem_export.py`.

## Deux points d'extension

```python
class Detector(Protocol):
    name: str

    def analyse(self, contexte: DetectorContext) -> list[dict]: ...


class Exporter(Protocol):
    name: str

    def export(self, report, chemin: Path) -> None: ...
```

Les protocoles et la vue `DetectorContext` sont dans `netcross_core.plugins`.

### Schéma des constats

Un détecteur renvoie des constats au **même schéma que `Report.security_findings`** :
ils traversent tels quels le tableau de bord, le rendu texte, le JSON, le HTML et
l'export SIEM. Pas de section de rapport dédiée : un plugin qui en aurait besoin serait
le signe d'un point d'extension mal placé.

| Clé | Obligatoire | Valeur |
|---|---|---|
| `category` | oui | `exploit`, `anomalie`, `cve` (autre valeur : rangée en anomalie) |
| `severity` | oui | `critique`, `elevee`, `moyenne`, `faible` |
| `detail` | oui | texte non vide |
| `point`, `host`, `port`, `service`, `version`, `cve_id`, `cvss`, `src`, `signature_id` | non | scalaires JSON |
| `cves` | non | liste de chaînes |

Un constat hors schéma (clé manquante, sévérité inconnue, objet non sérialisable,
flottant infini) est **ignoré et compté** : `detecteur x : partiel, 3 constat(s),
1 invalide(s) ignore(s) -- premier motif : ...`. Netcross ajoute la clé `plugin`
(nom du détecteur) ; le rapport l'affiche : `[plugin x]`.

## Découverte et chargement

- **Paquet installé** : `entry_points` des groupes `netcross.detectors` et
  `netcross.exporters`.

  ```toml
  # pyproject.toml du plugin
  [project.entry-points."netcross.detectors"]
  smb_site = "netcross_smb_site:DetecteurSmb"
  ```

- **Fichier local** : `--plugin-path mon_plugin.py` (répétable). Le module déclare
  `DETECTORS = [...]` et/ou `EXPORTERS = [...]` (instances, ou classes sans argument).

### Chargement explicite

Un plugin installé n'est **pas** un plugin autorisé. Seuls les noms listés dans
`--plugins` s'exécutent :

```bash
netcross-analyze --capture LAN=trace.pcap --security-report \
    --plugin-path examples/plugins/detecteur_telnet.py --plugins telnet_clair

netcross-analyze --capture LAN=trace.pcap --plugins siem_maison \
    --plugin-export siem_maison=sortie.xml

netcross-analyze --list-plugins --plugins telnet_clair   # installés ET non autorisés
```

- La découverte des entry points ne lit que les métadonnées : le code d'un plugin
  installé non autorisé n'est **jamais importé**.
- Un fichier `--plugin-path` est importé (donner le chemin vaut consentement), mais ses
  détecteurs et exporteurs ne s'exécutent que s'ils sont nommés dans `--plugins`.
- Les détecteurs nécessitent `--security-report` (leurs constats y vivent).

## Interface graphique (issue #867)

Dans les options d'analyse, la ligne « Plugins » reprend les options de la
CLI, avec les mêmes règles :

| Champ | Équivalent CLI |
| --- | --- |
| « Plugins (--plugins) » : noms séparés par des virgules | `--plugins` |
| « Fichiers plugins » : chemins séparés par `;` | `--plugin-path` (répétable) |
| « Exports NOM=FICHIER » : séparés par `;` | `--plugin-export` (répétable) |
| bouton « Lister (--list-plugins) » : tableau dans le journal | `--list-plugins` |

Les plugins sont chargés au lancement de l'analyse ; un réglage incohérent
(fichiers sans nom autorisé, export d'un exporteur non nommé, export mal
formé, détecteur sans « Rapport de securite ») bloque le lancement avec le
même message que la CLI. Les constats des détecteurs arrivent dans le
rapport de sécurité (section « Plugins » et exports JSON/PDF/HTML), les
exporteurs écrivent après l'analyse, et chaque ligne de trace apparaît dans
le journal.

## Isolation

- **Un plugin qui échoue ne fait pas échouer l'analyse.** L'exception est attrapée,
  journalisée (WARNING) et **signalée dans le rapport** (section « Plugins » du texte,
  clé `plugins` du JSON, liste du HTML) :

  ```
  -- Plugins --
    detecteur telnet_clair : ok, aucun constat
    detecteur fragile : erreur, constats absents -- RuntimeError: protocole inattendu
    plugin fantome : refuse -- introuvable (ni installe ni dans --plugin-path)
  ```

  Un détecteur muet parce que planté se distingue ainsi d'un détecteur qui n'a rien trouvé.

- **Contexte en lecture seule.** `contexte.packets`, `contexte.report` et
  `contexte.findings` sont des vues : les conteneurs sont rendus en copies figées
  (tuples, `MappingProxyType`) et toute affectation lève `PluginAccessError`.
  L'exporteur reçoit lui aussi le `Report` en vue lecture seule. En défense en
  profondeur, les constats du cœur sont photographiés avant chaque détecteur et restaurés
  s'ils ont changé.

## Contrat d'import

Un plugin n'importe que la bibliothèque standard et `netcross_core` — **jamais**
`netcross_report` ni `netcross_gtk4` : un exporteur reçoit le `Report`, pas le moteur de
rendu. Le contrat est vérifié **avant exécution** par lecture de l'AST du fichier source ;
un plugin en infraction est refusé (`plugin x : refuse -- ... importe netcross_report`).

## Limites de sécurité

!!! warning "Code tiers"
    Un plugin est du **code Python arbitraire exécuté dans le processus** qui analyse du
    trafic potentiellement hostile. Les vues en lecture seule protègent contre l'erreur et
    la négligence, **pas contre la malveillance** : un plugin peut lire des fichiers, ouvrir
    des connexions, contourner la vue par introspection. N'autorisez que des plugins dont
    vous avez lu le code, comme vous le feriez pour tout script exécuté avec vos droits.

- Pas de délai maximal : un plugin qui boucle bloque l'analyse (Ctrl+C l'interrompt).
- La vérification des imports est statique : un import dynamique (`importlib`,
  `__import__`) lui échappe.
- Pour un entry point dans un sous-paquet, le paquet parent est importé pour localiser
  le module avant la vérification.

## Exemple

[`examples/plugins/detecteur_telnet.py`](https://github.com/MathildeDec/Netcross/blob/dev/examples/plugins/detecteur_telnet.py)
signale les sessions Telnet en clair, en une trentaine de lignes.
