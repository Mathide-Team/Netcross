# Module IA local (`netcross_ai`)

Module **optionnel** (issue #146, FLOW-5) : trois usages qui s'exécutent entièrement
sur la machine de traitement. Aucune API cloud, aucun envoi de données.

```bash
pip install "netcross[ai]"      # ou : uv sync --extra ai   (installe scikit-learn)
```

Sans ce module, Netcross fonctionne normalement ; seules `--ai-anomalies` et
`--ai-classify` refusent de démarrer, avec la commande d'installation. Le résumé par
gabarit (`--ai-summary`) ne dépend de rien.

## 1. Anomalies par rapport à une baseline

Une **baseline** est un ensemble de flux de trafic normal. Elle se construit en passant
une ou plusieurs captures saines (chaque passage **enrichit** le fichier) :

```bash
netcross-analyze --capture LAN=lundi.pcapng  --ai-baseline-save base-bureau.json --ai-baseline-label bureau
netcross-analyze --capture LAN=mardi.pcapng  --ai-baseline-save base-bureau.json
netcross-analyze --capture LAN=incident.pcapng --ai-anomalies base-bureau.json --ai-report ia.json
```

- Modèle : Isolation Forest (scikit-learn), 200 arbres, graine fixe (même baseline → mêmes
  scores). 20 flux minimum dans la baseline.
- Caractéristiques par flux, issues des statistiques FLOW-4 (`Report.flow_anomalies`) :
  nombre de paquets et d'octets (log), entropie des tailles, taille médiane, ratio montant,
  régularité (CV des intervalles), moyenne et écart-type des tailles SPLT, intervalle moyen,
  part de petits (< 100 o) et de gros (> 500 o) paquets.
- Chaque flux atypique est **expliqué** : caractéristiques à plus de 3 écarts-types de la
  baseline, par exemple `ratio_montant = 0.99 (baseline 0.2 +/- 0.058)`.
- La baseline est un JSON de **nombres** (schéma `netcross.ai.baseline/1`), jamais un modèle
  sérialisé par pickle : un fichier reçu ne peut pas exécuter de code. Le modèle est
  réentraîné à chaque chargement (quelques dixièmes de seconde).

## 2. Classification de flux avec confiance

Les règles de FLOW-4 ne distinguent pas un tunnel d'un flux C2 ou d'une exfiltration :
contre l'opacification, seul un modèle entraîné sur des exemples fonctionne. Le jeu
d'entraînement se constitue à partir des captures elles-mêmes :

```bash
# 1. flux de la capture, pré-étiquetés par les règles (normal/interactif/transfert/obfusque)
netcross-analyze --capture A=labo.pcapng --ai-training-export entrainement.json
# 2. corriger / compléter les "label" : tunnel, c2, exfiltration...
# 3. classer d'autres captures
netcross-analyze --capture A=incident.pcapng --ai-classify entrainement.json
```

Forêt aléatoire (200 arbres, classes équilibrées, graine fixe) ; 10 exemples et 2 classes
minimum. Chaque flux reçoit une étiquette et une **confiance** (probabilité de la classe),
affichées à côté de la classification par règles pour comparaison.

## 3. Résumé exécutif, corrélations, recommandations

```bash
netcross-analyze --capture A=trace.pcapng --security-report --ai-summary                  # gabarit
netcross-analyze --capture A=trace.pcapng --security-report --ai-summary ollama:llama3:8b-instruct-q4_K_M
netcross-analyze --capture A=trace.pcapng --security-report --ai-summary llamacpp --ai-endpoint http://127.0.0.1:8080
```

| Moteur | Dépendance | Texte |
|---|---|---|
| `template` (défaut) | aucune | déterministe, construit à partir des faits |
| `ollama:MODELE` | [ollama](https://ollama.com) lancé en local (`/api/generate`) | rédigé par le modèle |
| `llamacpp` | `llama-server` de llama.cpp en local (`/completion`) | rédigé par le modèle |

- Le modèle ne reçoit que des **faits** (constats de sécurité, services, classes de flux,
  anomalies IA), jamais de paquets, avec la consigne de n'inventer aucun fait.
- Le point d'accès doit être une adresse de **boucle locale** (127.0.0.1, ::1, localhost) :
  toute autre adresse est refusée avant l'analyse.
- Les corrélations (une même machine cumulant CVE, signature d'exploit, mouvement latéral,
  flux atypique…) et les recommandations (mise à jour d'un service vulnérable, isolement,
  inspection d'un flux classé tunnel/C2/exfiltration…) sont **toujours** calculées par
  règles, donc vérifiables, et affichées à côté du texte du modèle.
- Si le modèle est injoignable ou répond vide, le gabarit est utilisé et c'est signalé.

`--security-report` n'est pas obligatoire, mais sans lui le rapport ne contient pas de
constats de sécurité à résumer.

## Sortie JSON

`--ai-report FICHIER.json` (schéma `netcross.ai/1`) : `anomalies` (flux, score 0-1,
`is_anomaly`, raisons), `classification` (étiquette, confiance, classification par règles),
`summary` (moteur, texte, corrélations, recommandations, motif de repli éventuel), et les
métadonnées de baseline / jeu d'entraînement utilisés.

## API REST (issue #866)

`POST /analyses/{analysis_id}/ai` (formulaire multipart) applique les mêmes
usages à une analyse terminée de l'API. Rien n'est conservé sur le serveur :
les fichiers joints vivent le temps de la requête et les documents produits
reviennent dans la réponse, que le client garde.

| Champ | Équivalent CLI | Réponse |
| --- | --- | --- |
| `baseline_save=true` (+ `baseline_label`) | `--ai-baseline-save`, `--ai-baseline-label` | `baseline_saved.flows`, `baseline_document` |
| fichier `baseline_base` (avec `baseline_save`) | baseline existante enrichie | idem, vecteurs cumulés |
| fichier `baseline` | `--ai-anomalies` | `anomalies`, `baseline` (`flows`, `label`) |
| `training_export=true` | `--ai-training-export` | `training_exported.samples`, `training_document` |
| fichier `training` | `--ai-classify` | `classification`, `training.labels` |
| `summary` (+ `endpoint`) | `--ai-summary`, `--ai-endpoint` | `summary` |

Mêmes validations que la CLI (`400`) : au moins un usage, `baseline_label`
et `baseline_base` sans `baseline_save`, `endpoint` sans `summary`, moteur
inconnu, point d'accès hors boucle locale (celle du **serveur**), baseline ou
jeu d'entraînement invalide ou trop petit. `baseline` et `training`
nécessitent scikit-learn (extra `ai`) : `503` sinon. Une analyse relue depuis
SQLite après redémarrage répond `409` (flux non conservés).

```bash
curl -F baseline_save=true -F baseline_label=bureau http://localhost:8000/analyses/a1b2c3d4e5f6/ai > ref.json
jq .baseline_document ref.json > base.json
curl -F baseline=@base.json -F summary=template http://localhost:8000/analyses/f6e5d4c3b2a1/ai
```

`netcross-ai-models` (paquets de modèles, boîte d'envoi) manipule des
fichiers du poste et reste en CLI.

## Partage de modèles et remontée hors connexion

Issue #271. Les baselines (« bons états transactionnels ») et les exemples
étiquetés peuvent enrichir une **base commune** : ils sont exportés en
**paquet de modèle** ZIP, remontés sur le dépôt par un ticket `modeles`, puis
importés par d'autres postes. Ces commandes ne nécessitent pas scikit-learn.

```bash
# export (consentement obligatoire), mise en file pour plus tard
python3 src/netcross_ai_models_cli.py export --baseline base-bureau.json \
    --training entrainement.json --name bureau-lan --description "LAN bureautique" \
    --consent -o bureau-lan.zip --queue

python3 src/netcross_ai_models_cli.py inspect bureau-lan.zip     # vérification
python3 src/netcross_ai_models_cli.py outbox list                # en attente

# une fois connecté : URL du ticket pré-rempli + archive à joindre
python3 src/netcross_ai_models_cli.py outbox send --open
python3 src/netcross_ai_models_cli.py outbox done bureau-lan     # -> envoyes/

# enrichir sa base locale avec un paquet de la base commune
python3 src/netcross_ai_models_cli.py import commun.zip --baseline base-bureau.json --training entrainement.json
```

### Ce que contient un paquet

| Fichier | Contenu |
|---|---|
| `manifest.json` | schéma `netcross.ai.modelpack/1`, nom, date (jour), comptes, caractéristiques, SHA-256 des fichiers |
| `baseline.json` | vecteurs de caractéristiques du trafic normal |
| `training.json` | exemples `{"features": [...], "label": "..."}` |
| `TICKET.md` | corps du ticket `modeles` |

**Sans garder d'infos** : seuls des vecteurs de caractéristiques voyagent
(aucune adresse, aucun port, aucun nom d'hôte, aucun horodatage de paquet,
aucune charge utile) ; ils sont arrondis à 4 chiffres significatifs et
mélangés ; libellé et description passent par l'anonymiseur des tickets de
support. Un jeu d'entraînement local (qui contient les flux complets pour
pouvoir être corrigé) est réduit à ses vecteurs à l'export.

**À l'import**, l'archive est vérifiée : fichiers attendus uniquement (ni
chemin, ni script, ni pickle), tailles bornées, empreintes SHA-256, schémas,
version des caractéristiques, exemples sans flux brut. Rien n'est exécuté.

### Hors connexion

La boîte d'envoi (`~/.netcross/outbox/modeles`, option `--outbox`) garde les
paquets jusqu'à ce que le poste soit connecté. `outbox send` teste seulement la
connectivité (connexion TCP vers github.com, rien n'est transmis) : hors ligne,
il sort avec le code **3** (utilisable par une tâche planifiée pour réessayer) ;
en ligne, il affiche pour chaque paquet l'URL de création du ticket (titre,
étiquette `modeles`, corps pré-rempli) et le chemin de l'archive à joindre —
les pièces jointes GitHub ne se déposent que depuis l'interface web. Netcross
n'envoie jamais rien lui-même et ne stocke aucun jeton.
