"""
netcross_core.expert_rules -- bibliotheque de regles d'expertise reseau
DECLARATIVE (FEATURES.md section 6.2), dernier chantier de la Session 2
de la section 13.3 ("moteur d'evenements d'expertise") apres la cloture
cote ExpertEvent en Session 45 (voir expert_model.py/wireshark_expert.py
pour les onze champs deja livres -- category/layer/protocol/severity/
confidence/first_seen/last_seen/flow_keys/packet_evidence/remediation).

Portee de la Session 46 : le CONTRAT (`Rule`, douze champs -- voir sa
docstring ci-dessous, calques EXACTEMENT sur la liste de la section 6.2)
et un premier CATALOGUE de QUINZE regles couvrant les treize regles
"deja presentes" nommees explicitement par la section 6.2 : "pertes par
segment, retransmissions TCP, fenetres a zero, RST, SYN sans reponse,
variation de TTL, remarking QoS, fragmentation, saturation, bufferbloat,
RTP, DHCP et SIP" (les "retransmissions TCP" se decomposent en trois
signatures deja distinctes et deja classees separement par tshark --
fast/RTO/spurious, voir _analyse_retransmission_types dans analysis.py --
plutot qu'une seule entree qui masquerait leurs trois severites
differentes ; les douze autres concepts nommes correspondent chacun a
une seule entree).

Portee de la Session 47 : HUIT regles supplementaires (23 au total)
couvrant CINQ des SIX "regles nouvelles" listees par la section 6.2 a la
suite des treize precedentes : "DNS lent, PMTUD black hole, NAT/FW
silencieux, anomalies L2, options TCP incompatibles, negociations TLS
incompletes, etc." VERIFIE dans le code avant redaction, jamais suppose :
malgre le mot "nouvelles" (la section 6.2 a sans doute ete redigee avant
que ces detecteurs n'existent), CINQ des SIX sont en realite DEJA
implementes aujourd'hui, par des sessions anterieures et independantes
de ce chantier de bibliotheque de regles -- `Finding.category` porte
deja DNS/PMTUD/NAT-Pare-feu/ARP/STP/VLAN, et `_analyse_tcp_options`
existe deja pour les options TCP. Seule "negociations TLS incompletes"
reste sans detecteur reel : aucun champ `Report` ne suit l'etat
d'avancement d'une negociation TLS (verifie par recherche exhaustive des
champs `tls_*`) -- non cataloguee ici, volontairement, plutot que
d'inventer une regle sans donnee reelle derriere. Un signal "TLS" existe
par ailleurs (certificat hors validite / substitue entre points, Session
26) mais ne correspond PAS a "negociations incompletes" (probleme
different : validite du certificat, pas achevement de la poignee de
main) -- explicitement laisse de cote, pas un candidat naturel de cette
liste precise. "anomalies L2" et "options TCP incompatibles" couvrent
chacune PLUSIEURS signaux deja distincts cote code : respectivement
trois (ARP/STP/VLAN, detecteurs prealablement independants) et deux
(Window Scale + SACK Permitted retires, qui partagent deja la meme
severite -- MSS clamped ajoute en plus, severite differente, meme
fonction source `_analyse_tcp_options` mais pas nomme par la section 6.2,
catalogue pour ne pas laisser un signal orphelin de son detecteur deja
formalise par ailleurs).

Ce module NE REIMPLEMENTE AUCUNE detection : chaque regle du catalogue
DECRIT un detecteur qui existe DEJA et qui reste la seule source de
verite (netcross_core.analysis pour le calcul des compteurs de Report,
netcross_report.synthesis.build_findings pour la transformation en
Finding avec son message/sa severite). Meme discipline que _KNOWN_FLAGS/
_REMEDIATION (netcross_core.wireshark_expert) : une table de reference
FORMALISEE a partir de code deja ecrit et deja teste, jamais une nouvelle
heuristique inventee ici. La section 6.2 elle-meme distingue "les
premieres regles a formaliser" (celles-ci, deja presentes) des "regles
nouvelles" a venir ensuite (DNS lent, PMTUD noir, NAT/FW silencieux,
anomalies L2, options TCP incompatibles, negociations TLS incompletes --
non traitees dans cette passe, voir CLAUDE.md).

`domain` reprend EXACTEMENT les valeurs de `Finding.category`
(netcross_report.synthesis) -- pas une nouvelle taxonomie -- pour que
`list_rules(domain=finding.category)` retrouve directement la ou les
regles qui decrivent un Finding deja produit, sans avoir a modifier
Finding ni ExpertEvent.

`severity` porte la severite la PLUS ELEVEE que la regle peut produire
(le pire cas) -- quand un detecteur produit plusieurs severites selon un
seuil (ex: pertes >= 5% -> anomalie, sinon a_surveiller), la gradation
exacte est documentee dans `thresholds`/`explanation`, jamais masquee.

`confidence` (0.0-1.0) reflete la nature de la methode de detection, PAS
une probabilite statistique calibree -- cinq paliers discrets, du plus
direct au plus infere :
- 0.9 : lecture directe d'une classification deterministe sans ambiguite
  NI hypothese structurelle d'aucune sorte, sur un seul paquet
  (classification NATIVE tshark, ou valeur de champ brute sans
  interpretation) -- les trois sous-types de retransmission TCP, fenetre
  TCP nulle ;
- 0.8 : lecture deterministe d'un champ/protocole natif sans ambiguite
  dans la donnee elle-meme, mais necessitant soit une correspondance par
  identifiant exact entre plusieurs points/paquets (xid DHCP, Call-ID
  SIP, id de transaction DNS, 5-tuple + sequence pour les options TCP/le
  VLAN), soit une agregation sur un seul point sans hypothese de
  topologie (BPDU STP) -- RST localise, DHCP, SIP, DNS lent, instabilite
  STP, changement de VLAN, options TCP retirees, MSS clamped ;
- 0.75 : correlation deterministe de DEUX signaux distincts mais reposant
  sur une hypothese structurelle assumee (attribution L2/L3 par delta de
  TTL, correlation fragmentation/encapsulation, correlation
  retransmissions-sans-progression / absence de signal ICMP(v6) evaluee
  sur la capture entiere plutot que sur une fenetre precise autour de
  CHAQUE tentative) -- remarquage QoS, fragmentation, PMTUD black hole ;
- 0.7 : heuristique deterministe dependant d'une hypothese de topologie/
  ordre des points, ou d'un seuil delibere non calibre a un equipement
  precis (ordre explicite ou deduit, correspondance SYN/SYN-ACK par
  numero de sequence, silence de 60s choisi pour filtrer le bruit
  applicatif sans connaitre le vrai timeout de l'equipement, ambiguite
  documentee entre vrai conflit et bascule HA/VRRP legitime) -- pertes
  par segment, variation de TTL, SYN sans reponse, coupure NAT/pare-feu
  silencieuse, conflit d'adresse IP (ARP) ;
- 0.6 : estimation statistique (quantiles, seuils de dispersion, modele
  de qualite d'appel simplifie) -- saturation, bufferbloat, MOS RTP.

`correlation_rule` reste `None` pour la majorite des regles (un seul
compteur/une seule classification suffit a les produire). CINQ regles du
catalogue croisent deja reellement DEUX signaux bruts distincts, mais via
un code FIGE entre deux compteurs precis -- PAS un moteur generique
capable de fusionner N ExpertEvent arbitraires selon une regle declaree
(section 6.1, moteur de correlation, Session 3 -- absent aujourd'hui) :
saturation (pertes + debit), bufferbloat (latence + debit), remarquage
QoS (DSCP + delta TTL), fragmentation (fragmentation + encapsulation),
PMTUD black hole (retransmissions sans jamais atteindre le point aval +
absence de signal ICMP(v6) au point amont sur toute la capture).

Volontairement NON traite meme apres ces deux sessions (voir CLAUDE.md) :
- negociations TLS incompletes (§6.2) -- aucun detecteur reel derriere,
  voir plus haut ;
- le signal TLS deja existant (certificat hors validite / substitue
  entre points, Session 26) -- concept different de "negociation
  incomplete", non nomme par §6.2, laisse a une decision explicite d'une
  session future plutot qu'absorbe ici par extension implicite ;
- un moteur d'EXECUTION qui evaluerait une `Rule` contre un `Report` pour
  PRODUIRE un ExpertEvent/Finding -- ce catalogue reste DESCRIPTIF,
  l'evaluation reelle continue de se faire dans le code procedural
  existant (analysis.py/synthesis.py), qui n'est pas modifie ici ;
- l'exposition du CONTENU du catalogue (thresholds/explanation/
  confidence/correlation_rule...) via --json-report/GUI -- toujours
  consomme uniquement par du code Python (et les tests) a ce stade ; voir
  Session 48 ci-dessous pour ce qui EST expose (un simple identifiant).

Portee de la Session 48 : premier cablage reel du catalogue a un
consommateur, via un champ `rule_id` (`str | None`) sur `Finding`
(netcross_report.synthesis) et `ExpertEvent` (expert_model.py) -- PAS le
moteur d'execution ci-dessus (toujours absent), seulement un identifiant
qui relie un Finding/ExpertEvent DEJA produit par le code procedural
existant a la regle qui le decrit ici, quand une correspondance EXACTE
existe (verifiee point par point, jamais par seule `category` -- voir
docstring de module de synthesis.py pour le detail complet, y compris la
liste des Finding volontairement laisses sans regle). Les VINGT-TROIS
regles du catalogue sont desormais toutes reliees a au moins un site de
construction de Finding reel (aucune regle orpheline de son cote), sans
qu'aucune n'ait ete devinee ou approximee pour y parvenir. Seul
`netcross_report.json_report` expose ce nouvel identifiant a ce jour
(cle `"rule_id"`) ; CLI `--triage`/PDF/GUI inchanges (voir docstring de
synthesis.py).

Portee de la Session 49 : HUIT regles supplementaires (31 au total),
choisies parmi les dix-sept sites de `Finding` restes volontairement
`rule_id=None` apres la Session 48 (voir liste exhaustive dans la
docstring de module de synthesis.py). Uniquement les signaux de nature
"formalisation" (meme discipline que les Sessions 46-47 : le detecteur
existe deja, non modifie ici) : les cinq paires signal-voisin-d'une-regle
-- `hop_delta_outliers` (Routage, a cote de `ttl_variation`),
`pcp_change` (QoS, a cote de `qos_dscp_remarking`),
`icmp_frag_needed`/`icmpv6_too_big` (Fragmentation, a cote de
`fragmentation_new` -- FUSIONNES en une seule regle, meme signal
fonctionnel cote IPv4/IPv6, meme severite, voir sa docstring de regle
ci-dessous), `syn_reply_missing` (TCP, a cote de `tcp_syn_no_synack` --
meme fonction source `_analyse_handshake`), et les QUATRE compteurs DNS
bruts (`dns_nxdomain_count`, `dns_servfail_count`, `dns_timeout`,
`dns_missing`, a cote de `dns_slow_resolution`) -- ici gardes comme
QUATRE regles distinctes plutot que fusionnes, memes discipline que les
trois sous-types de retransmission TCP (Session 46) : leurs severites
respectives (info/anomalie/anomalie/a_surveiller) different, les
fusionner masquerait cette gradation.

Explicitement PAS traitees cette session, decision reportee (voir
CLAUDE.md) : les TROIS categories encore entierement sans regle
(`"Reseau/Serveur"`, `"TLS"`, `"HTTP"`) -- aucune n'est nommee par la
section 6.2, contrairement aux cinq paires ci-dessus qui formalisent
chacune une extension directe d'un concept deja cite (TTL/QoS/
fragmentation/SYN-ACK/DNS). Une decouverte notable de cette session
n'a PAS change cette conclusion : `netcross_core.tls_diagnostics`
(module independant, voir sa propre docstring) suit deja l'etat complet
d'un handshake TLS (ClientHello/ServerHello/donnees applicatives -- son
`HandshakeStatus.verdict` distingue meme explicitement
"client_hello_no_reply"/"server_hello_no_data", tres proche en esprit de
"negociations TLS incompletes") mais produit son PROPRE type
`TlsFinding`, jamais un `synthesis.Finding` -- `rule_id` ne s'applique
qu'a ce dernier (voir docstring de module ci-dessus et de synthesis.py).
Batir "negociations TLS incompletes" pour de vrai suppose donc de
DECIDER explicitement, dans une session dediee, si le signal doit vivre
dans `Report`/`analysis.py` (pour rejoindre le pipeline `rule_id`) ou
rester dans `tls_diagnostics.py` (auquel cas il ne sera par construction
jamais cataloguable ici) -- pas une simple extension mecanique du geste
de la Session 49, qui ne touchait a aucun des deux fichiers.

Portee de la Session 51 (32 regles au total) : UNE des TROIS categories
entierement sans regle apres la Session 49 -- `"Reseau/Serveur"`
(decomposition applicatif/reseau, `server_processing_dominant`, UN seul
site de construction de `Finding`, voir synthesis.py). Retenue en
priorite parmi les trois candidats laisses ouverts par CLAUDE.md
("Prochaine feature") car elle ne nomme aucun nouveau concept
architectural (contrairement a `"TLS"`, qui recoupe la question non
tranchee des negociations incompletes ci-dessus) et ne requiert qu'UN
site de `Finding` (contre cinq pour `"HTTP"`, chacun avec sa propre
gradation de severite par code de statut -- extension mecanique jugee
trop large pour cette meme passe, voir CLAUDE.md). `"TLS"`/`"HTTP"`
restent donc entierement sans regle apres cette session, decision
explicitement reportee comme apres la Session 49.

Portee de la Session 52 (37 regles au total) : la DEUXIEME des trois
categories laissees ouvertes par la Session 51 -- `"HTTP"` (codes de
statut, Session 17, CINQ sites de construction de `Finding` dans
`synthesis.py::build_findings()`, bloc "-- HTTP --"). Retenue avant
`"TLS"` car, comme `"Reseau/Serveur"` en Session 51, elle ne nomme aucun
concept architectural non tranche (contrairement a `"TLS"`, qui recoupe
toujours la decision en suspens sur "negociations TLS incompletes"
identifiee en Session 49 et non revisitee ici) -- seul son NOMBRE de
sites (cinq, pas un) avait fait differer son traitement en Session 51,
pas une difficulte de fond. CINQ nouvelles regles, calquees sur le meme
geste que les quatre compteurs DNS bruts + `dns_slow_resolution`
(Session 47/49, meme forme de detecteur : codes de reponse categorises,
absence de reponse, message manquant entre deux points, latence moyenne
globale) :

- `http_client_error` (4xx, `Report.http_client_error_count`) --
  severite `info`, confiance `0.9`, meme registre que `dns_nxdomain` :
  erreur cote client/application, pas forcement un probleme reseau.
- `http_server_error` (5xx, `Report.http_server_error_count`) --
  severite `anomalie`, confiance `0.9`, meme registre que
  `dns_servfail` : echec cote serveur, souvent pris a tort pour un
  probleme reseau.
- `http_timeout` (`Report.http_timeout`) -- severite `anomalie`,
  confiance `0.8`, meme registre que `dns_timeout`, mais cle de
  transaction DIFFERENTE : DNS suit un identifiant de transaction
  16 bits (`Pkt.dns_txn_id`), HTTP suit `(connexion TCP, URI, Nieme
  occurrence de cette URI sur cette connexion)` -- voir la docstring de
  `_analyse_http` (`analysis.py`) pour la justification complete du
  choix (une position ordinale pure se desynchroniserait des qu'une
  requete entiere est perdue) et sa limite assumee (polling repete de
  la meme URI sur la meme connexion).
- `http_missing` (`Report.http_missing`) -- severite `a_surveiller`,
  confiance `0.8`, meme registre que `dns_missing` (perte localisee sur
  un segment precis, message vu a un point mais pas au point adjacent
  attendu), meme cle de transaction que `http_timeout` ci-dessus plutot
  qu'un identifiant DNS.
- `http_slow_response` (`Report.http_response_time_ms`, seuil moyenne
  > 500ms) -- severite `a_surveiller`, confiance `0.8`, meme registre
  que `dns_slow_resolution` (latence applicative percue a tort comme un
  probleme reseau) mais source de la mesure DIFFERENTE et documentee
  dans `_analyse_http` : `http.time`, calcule NATIVEMENT par le
  dissecteur HTTP de tshark par transaction (present uniquement sur le
  paquet de reponse), jamais recompose a la main via des timestamps
  minimaux comme DNS/DHCP/SIP -- verifie empiriquement en Session 17
  (capture HTTP/1.1 reelle sur loopback), pas une supposition.

Toutes les cinq restent AUTONOMES (`correlation_rule=None`, comme les
regles DNS dont elles s'inspirent) et sans site de `Finding` partage
entre elles (chacune des cinq boucles de `synthesis.py` ne produit
qu'une seule categorie de signal). `"TLS"` reste seule categorie
entierement sans regle apres cette session, decision architecturale
toujours ouverte (voir plus haut) -- pas revisitee ici.

Portee de la Session 53 (39 regles au total) : la DERNIERE categorie
laissee ouverte par la Session 49 -- `"TLS"`, DEUX sites de `Finding`
(certificat hors validite/pas encore valide, et certificat substitue
entre deux points -- Session 26, voir `_analyse_tls_certificate` dans
analysis.py). Clarification apportee cette session, en CORRIGEANT le
raisonnement tenu depuis la Session 49 (CLAUDE.md et les docstrings
des Sessions 51/52 affirmaient que cataloguer ce signal "recoupait" la
decision architecturale sur "negociations TLS incompletes", donc
"pas un simple geste mecanique") : verifie dans le code avant
redaction, cette affirmation etait INEXACTE. Le signal "negociations
incompletes" ne produit AUCUN `synthesis.Finding` aujourd'hui (il vit
exclusivement dans `TlsFinding`, type separe de
`netcross_core.tls_diagnostics`, jamais relie a `Finding.category`) --
il n'a donc jamais ete, et ne devient pas maintenant, un candidat a
une entree de CE catalogue, qui n'accepte comme `domain` que des
valeurs REELLEMENT produites par `Finding.category` (voir docstring de
module de synthesis.py). Les deux signaux ("certificat" et
"negociations incompletes") partagent la meme etiquette `"TLS"` en
langage naturel mais ne partageaient deja aucun code, aucun type, aucun
site de `Finding` commun -- cataloguer l'un ne prejuge donc
rigoureusement rien du sort de l'autre. Deux nouvelles regles, meme
discipline de formalisation que les Sessions 46-52 (le detecteur existe
deja, non modifie ici) :

- `tls_cert_invalid_dates` (`Report.tls_cert_invalid_dates`, PAR POINT)
  -- severite `anomalie`, confiance `0.8` (lecture native du champ
  certificat, agregation sur un seul point sans hypothese de topologie
  -- meme registre que `stp_instability`).
- `tls_cert_mismatch` (`Report.tls_cert_mismatch`, PAR PAIRE de points)
  -- severite `anomalie`, confiance `0.8` (correspondance par
  identifiant exact -- ici le 5-tuple de connexion -- entre deux
  points, meme registre que `vlan_change`).

Les deux restent AUTONOMES (`correlation_rule=None`) et a thresholds
vides (se declenchent sur toute occurrence, n > 0, meme discipline que
`stp_instability`/`vlan_change`). A l'issue de cette session, PLUS
AUCUNE categorie de `Finding` n'est entierement sans regle -- mais
"negociations TLS incompletes" (§6.2) reste, comme documente depuis la
Session 49, un signal ENTIEREMENT hors du systeme Finding/rule_id : la
decision architecturale (soit (a) le faire vivre dans
`Report`/`analysis.py`, soit (b) l'enrichir dans `tls_diagnostics.py`
en acceptant qu'il ne sera jamais catalogable ici) reste ouverte, non
traitee par cette session.

Portee de la Session 54 (41 regles au total) : la decision
architecturale ci-dessus, ENFIN tranchee -- **option (a) retenue**.
Raisonnement complet dans `docs/sessions/session-54.md` ; resume ici
des deux options et de pourquoi (a) l'a emporte :

- (a) faire vivre le signal dans `Report`/`analysis.py`, pour qu'il
  rejoigne pleinement ce catalogue -- RETENUE. Cout initialement
  surestime (voir CLAUDE.md avant cette session) : la crainte etait de
  devoir soit dupliquer le parsing manuel de
  `netcross_core.tls_diagnostics` (bytes bruts de la charge utile TCP),
  soit casser son independance deliberee. Verifie dans le code avant
  d'ecrire quoi que ce soit (meme discipline que la correction de la
  Session 53) : AUCUNE des deux n'etait necessaire. Le pipeline
  principal (`pcap_parser.protocols`, deja utilise pour le certificat
  ci-dessus) lit tshark en mode `-T ek` SANS restriction de champs --
  la dissection TLS NATIVE de tshark (type d'enregistrement, sous-type
  Handshake) y est deja integralement presente, il suffisait de lire
  DEUX champs EK supplementaires (`tls_tls_record_content_type`,
  `tls_tls_handshake_type` -- confirmes empiriquement par une capture
  TLS 1.2 reelle sur loopback, tshark 4.2.2, openssl s_server/curl,
  voir `docs/sessions/session-54.md`), exactement comme
  `extract_tls_certificate` le fait deja pour les champs X.509.
  Nouvelle fonction `pcap_parser.protocols.extract_tls_handshake`,
  totalement independante d'`extract_tls_certificate` ET de
  `tls_diagnostics.py` -- ce dernier reste inchange, toujours
  independant, comme concu.
- (b) enrichir `tls_diagnostics.py` en acceptant qu'il ne soit jamais
  catalogable ici -- ECARTEE, precisement parce que (a) s'est revelee
  ne pas couter ce qu'on craignait : rien ne justifiait d'accepter une
  lacune permanente de couverture quand l'option qui l'evite entierement
  n'etait pas plus couteuse a ecrire.

Deux nouvelles regles (39 -> 41), memes principes de calibration que
les regles deja au catalogue :

- `tls_handshake_no_reply` (`Report.tls_handshake_no_reply`, PAR POINT)
  -- ClientHello vu, aucun ServerHello jamais observe pour cette
  connexion a ce point. Severite `anomalie`, confiance `0.8`
  (correspondance par identifiant exact -- la connexion -- entre
  plusieurs paquets d'un MEME point, meme registre que
  `dhcp_issues`/`sip_issues`, PAS le registre 0.7 de `syn_no_synack`
  puisqu'aucun ordre de points n'est requis ici).
- `tls_handshake_incomplete` (`Report.tls_handshake_incomplete`, PAR
  POINT) -- ServerHello vu mais aucune donnee applicative jamais
  observee ensuite pour cette connexion a ce point. Memes severite et
  confiance que ci-dessus, meme registre.

Les deux restent AUTONOMES (`correlation_rule=None`) et a thresholds
vides (se declenchent sur toute occurrence, n > 0). Domaine `"TLS"`
partage avec les deux regles certificat de la Session 53 -- meme
`Finding.category`, quatre concepts desormais distincts sous la meme
etiquette naturelle, exactement la situation que la correction de la
Session 53 avait clarifiee comme sans risque technique. A l'issue de
cette session, `"negociations TLS incompletes"` (§6.2) n'est plus un
signal hors du systeme Finding/rule_id : TOUTES les categories ET tous
les signaux nommes par la section 6.2 sont desormais couverts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)


@dataclass
class Rule:
    """Une regle d'expertise reseau DECLARATIVE -- douze champs, calques
    EXACTEMENT sur le schema de la section 6.2 de FEATURES.md (aucun
    champ ajoute au-dela de cette liste, aucun retire) :

    id / domaine / preconditions / metriques requises / fenetre
    temporelle / seuils-percentiles / contexte requis / regle de
    correlation / severite / confiance / explication / pistes de
    verification.

    Objet de REFERENCE statique (comme _KNOWN_FLAGS/_REMEDIATION cote
    wireshark_expert.py) : construit une seule fois au chargement de ce
    module, a traiter en LECTURE SEULE par tout consommateur -- pas de
    dataclass "frozen" (incoherent avec le reste de ce projet, qui n'en
    utilise nulle part ailleurs, et un dict reste techniquement mutable
    meme derriere un champ fige) : seulement une convention documentee
    ici, comme pour les tables existantes.

    `id` : identifiant stable, snake_case, jamais reutilise pour une
    autre regle (comparable a un nom de flag EK cote wireshark_expert.py).

    `domain` : reprend EXACTEMENT une valeur de `Finding.category`
    (netcross_report.synthesis) -- voir docstring de module.

    `preconditions` : ce qui doit etre vrai/observe pour que la regle
    puisse produire un signal (texte libre).

    `required_metrics` : tuple de noms `Report.<champ>`/`Pkt.<champ>`
    (netcross_core.models) reellement lus par le detecteur decrit --
    verifiable directement dans analysis.py/synthesis.py, jamais une
    supposition.

    `time_window` : portee temporelle sur laquelle la regle agrege (toute
    la capture, par bucket de bucket_seconds...).

    `required_context` : hypotheses de topologie/capture necessaires
    (ordre des points connu ou deduit, nombre minimal de points...).

    `severity` : severite la PLUS ELEVEE que la regle peut produire (voir
    docstring de module) -- une des trois valeurs de
    netcross_report.synthesis.SEVERITY_ORDER ("anomalie", "a_surveiller",
    "info").

    `confidence` : voir l'echelle a cinq paliers documentee dans la
    docstring de module.

    `explanation` : ce que signifie le signal pour un analyste, y compris
    la gradation de severite exacte quand elle existe.

    `verification_leads` : piste(s) de verification technique concrete,
    meme registre que _REMEDIATION cote wireshark_expert.py (conditionnel/
    imperatif de suggestion, jamais une affirmation de diagnostic
    definitif).

    `thresholds` : seuils/percentiles NUMERIQUES nommes reellement
    utilises par le detecteur -- dict vide si la regle se declenche sur
    toute occurrence (n > 0) sans palier numerique supplementaire.

    `correlation_rule` : comment ce signal se combine a un AUTRE signal
    brut distinct, ou `None` pour une regle autonome -- voir docstring de
    module (cinq regles seulement portent une valeur non None ici, voir
    test_catalogue_cinq_regles_seulement_ont_une_correlation).
    """

    id: str
    domain: str
    preconditions: str
    required_metrics: tuple[str, ...]
    time_window: str
    required_context: str
    severity: str
    confidence: float
    explanation: str
    verification_leads: str
    thresholds: dict[str, float] = field(default_factory=dict)
    correlation_rule: str | None = None


# Ordre identique a celui du texte de la section 6.2. Chaque commentaire
# cite la fonction/le bloc source exact (analysis.py pour le calcul des
# compteurs Report, synthesis.py::build_findings pour la transformation
# en Finding) pour verification directe.
_RULE_CATALOG: tuple[Rule, ...] = (
    # -- pertes par segment -- analysis.py::analyse() (boucle principale,
    # Report.loss_count) + synthesis.py::build_findings() ("-- pertes --")
    Rule(
        id="loss_per_segment",
        domain="Pertes",
        preconditions=(
            "un point voit strictement moins de flux qu'un point en amont sur "
            "le meme chemin (Report.loss_count[p] > 0)."
        ),
        required_metrics=("Report.loss_count", "Report.seen_count"),
        time_window="agrege sur toute la duree de la capture, par point.",
        required_context=(
            "ordre des points de capture connu (--order) OU topologie deduite "
            "avec une couverture suffisante sur l'arc concerne (les arcs a "
            "faible couverture sont explicitement exclus -- voir "
            "topo_low_coverage dans analysis.py : un flux absent en aval peut "
            "avoir legitimement pris un autre chemin)."
        ),
        severity="anomalie",
        confidence=0.7,
        explanation=(
            "Un flux vu a un point amont mais jamais revu au point aval "
            "attendu. Le taux (paquets manquants / paquets vus a ce point) "
            "distingue une perte marginale (< 5%, a_surveiller) d'une perte "
            "significative (>= 5%, anomalie)."
        ),
        verification_leads=(
            "Comparer ce point aux points voisins pour situer le segment "
            "exact ; verifier la charge et les compteurs d'erreurs des "
            "interfaces sur ce segment avant de conclure a une perte reseau "
            "plutot qu'a une limite de couverture de capture."
        ),
        thresholds={"anomalie_rate_pct": 5.0},
    ),
    # -- retransmissions TCP (3 sous-types deja distingues nativement par
    # tshark) -- analysis.py::_analyse_retransmission_types() +
    # synthesis.py::build_findings() ("-- TCP avance --")
    Rule(
        id="tcp_retransmission_fast",
        domain="TCP",
        preconditions=(
            "tshark classe nativement le segment comme fast retransmission "
            "(Pkt.is_fast_retransmission) -- priorite spurious > fast > "
            "simple, un paquet n'est compte que dans une seule des trois "
            "categories de retransmission."
        ),
        required_metrics=("Report.retrans_fast", "Pkt.is_fast_retransmission"),
        time_window="par paquet, agrege en compteur par point sur toute la capture.",
        required_context=(
            "paquet TCP capture a ce point ; aucune correlation multi-points "
            "necessaire, la classification est faite point par point par "
            "tshark lui-meme."
        ),
        severity="info",
        confidence=0.9,
        explanation=(
            "Reaction a trois ACK dupliques (ou saut de MSS) -- recuperation "
            "rapide, signe d'un TCP qui reagit normalement a une perte "
            "isolee. Severite fixe, ne varie pas avec le volume."
        ),
        verification_leads=(
            "Aucune action en soi ; une frequence elevee et soutenue "
            "justifie de regarder tcp.analysis.duplicate_ack sur le meme "
            "flux pour confirmer des pertes regulieres plutot qu'un "
            "incident isole."
        ),
    ),
    Rule(
        id="tcp_retransmission_rto",
        domain="TCP",
        preconditions=(
            "tshark classe nativement le segment comme retransmission sans "
            "qu'aucun ACK duplique recent n'ait declenche de renvoi rapide "
            "(Pkt.is_retransmission and not is_fast_retransmission and not "
            "is_spurious_retransmission)."
        ),
        required_metrics=("Report.retrans_rto", "Pkt.is_retransmission"),
        time_window="par paquet, agrege en compteur par point sur toute la capture.",
        required_context="paquet TCP capture a ce point ; aucune correlation multi-points necessaire.",
        severity="a_surveiller",
        confidence=0.9,
        explanation=(
            "Renvoi apres expiration du minuteur de retransmission -- "
            "recuperation plus lente qu'une retransmission rapide, signe "
            "frequent d'un lien significativement perturbe ou d'un "
            "reordonnancement qui masque les ACK dupliques."
        ),
        verification_leads=(
            "Verifier le RTT et sa variance sur ce flux/segment ; un RTO "
            "frequent sur un chemin par ailleurs stable justifie de regarder "
            "la stabilite de la file d'attente (congestion, microcoupures)."
        ),
    ),
    Rule(
        id="tcp_retransmission_spurious",
        domain="TCP",
        preconditions=(
            "tshark classe nativement le segment comme spurious "
            "retransmission (Pkt.is_spurious_retransmission) -- la donnee "
            "renvoyee avait deja ete acquittee, visible dans cette meme "
            "capture."
        ),
        required_metrics=("Report.retrans_spurious", "Pkt.is_spurious_retransmission"),
        time_window="par paquet, agrege en compteur par point sur toute la capture.",
        required_context="paquet TCP capture a ce point ; aucune correlation multi-points necessaire.",
        severity="a_surveiller",
        confidence=0.9,
        explanation=(
            "Le renvoi n'etait pas necessaire : l'ACK de l'original n'etait "
            "simplement pas encore arrive assez tot. Indique souvent un "
            "minuteur de retransmission mal calibre par rapport au vrai RTT, "
            "ou un chemin de retour ACK asymetrique/plus lent."
        ),
        verification_leads=(
            "Comparer la stabilite du RTT entre les points de capture ; un "
            "taux de spurious eleve et persistant justifie de revoir le "
            "calibrage du minuteur de retransmission cote emetteur plutot "
            "que d'incriminer le reseau."
        ),
    ),
    # -- fenetres a zero -- analysis.py::analyse() (boucle principale,
    # Report.zero_window) + synthesis.py::build_findings() ("-- TCP avance --")
    Rule(
        id="tcp_zero_window",
        domain="TCP",
        preconditions="au moins un paquet du flux a ce point annonce une fenetre TCP nulle (Pkt.window == 0).",
        required_metrics=("Report.zero_window", "Pkt.window"),
        time_window="par flux, agrege en compteur de flux par point sur toute la capture.",
        required_context=(
            "flux TCP correle (5-tuple strict ou hash NAT-tolerant) vu a ce point ; aucun ordre de points necessaire."
        ),
        severity="a_surveiller",
        confidence=0.9,
        explanation=(
            "Le recepteur annonce qu'il ne peut plus accepter de donnees -- "
            "generalement parce que l'application cote recepteur ne "
            "consomme pas assez vite le tampon socket, plus rarement un vrai "
            "epuisement memoire."
        ),
        verification_leads=(
            "Verifier la charge CPU/IO de l'hote recepteur et la taille de "
            "son tampon de reception avant d'incriminer le reseau ; une "
            "fenetre nulle persistante precede souvent des retransmissions "
            "RTO en cascade."
        ),
    ),
    # -- RST -- analysis.py::analyse() (boucle principale, Report.rst_localized)
    # + synthesis.py::build_findings() ("-- TCP avance --")
    Rule(
        id="tcp_rst_localized",
        domain="TCP",
        preconditions=(
            "au moins un paquet RST (Pkt.flags contient 'R') est vu sur un "
            "flux qui n'apparait QU'A CE point parmi tous les points de "
            "capture fournis."
        ),
        required_metrics=("Report.rst_localized", "Pkt.flags"),
        time_window="par flux, agrege en compteur de flux par point sur toute la capture.",
        required_context=(
            "au moins deux points de capture fournis (sinon la notion de "
            "localisation exclusive n'a pas de sens) ; Report.rst_count "
            "reste le compteur brut non exclusif, affiche en texte/PDF mais "
            "jamais expose en Finding."
        ),
        severity="anomalie",
        confidence=0.8,
        explanation=(
            "Un RST vu a un seul point (absent de tous les autres) suggere "
            "une injection LOCALE plutot qu'un RST legitime emis par l'un "
            "des deux hotes et propage naturellement le long du chemin -- "
            "signature classique d'un firewall/IPS qui coupe la connexion."
        ),
        verification_leads=(
            "Verifier les regles/logs du firewall ou de l'IPS present a ce "
            "point ; comparer le motif du RST (contenu, timing) a une "
            "politique de filtrage connue plutot qu'a un comportement "
            "applicatif normal."
        ),
    ),
    # -- SYN sans reponse -- analysis.py::_analyse_handshake() +
    # synthesis.py::build_findings() ("-- TCP avance --")
    Rule(
        id="tcp_syn_no_synack",
        domain="TCP",
        preconditions=(
            "un segment SYN (sans ACK) n'a aucun SYN-ACK correspondant dans "
            "la table de flux (correspondance par 4-tuple inverse + "
            "ack == seq+1)."
        ),
        required_metrics=("Report.syn_no_synack", "Pkt.flags", "Pkt.seq", "Pkt.ack"),
        time_window="par connexion (SYN), agrege en compteur par point sur toute la capture.",
        required_context=(
            "ordre des points de capture connu (--order) et correlation "
            "stricte par 5-tuple ; regle desactivee en mode --nat-tolerant "
            "(voir _analyse_handshake)."
        ),
        severity="anomalie",
        confidence=0.7,
        explanation=(
            "Connexion TCP bloquee : aucun SYN-ACK n'est jamais observe, a "
            "aucun point de capture. Signature typique d'une ACL qui filtre "
            "le port, ou d'un service arrete/injoignable cote destination."
        ),
        verification_leads=(
            "Verifier l'etat du service ecoutant sur le port destination et "
            "les regles ACL/firewall entre le point de capture le plus "
            "proche de la source et la destination."
        ),
    ),
    # -- SYN-ACK qui n'atteint pas un point precis -- analysis.py::
    # _analyse_handshake() (meme fonction que tcp_syn_no_synack ci-dessus,
    # Report.syn_reply_missing) + synthesis.py::build_findings() ("-- TCP --")
    Rule(
        id="syn_reply_missing",
        domain="TCP",
        preconditions=(
            "un SYN-ACK correspondant (meme correspondance ack == seq+1 que "
            "tcp_syn_no_synack ci-dessus) est vu a au moins un point de "
            "capture, mais PAS au point p ou le SYN lui-meme a pourtant ete "
            "vu."
        ),
        required_metrics=("Report.syn_reply_missing", "Pkt.flags", "Pkt.seq", "Pkt.ack"),
        time_window="par connexion (SYN) et par point, agrege en compteur par point sur toute la capture.",
        required_context=(
            "meme correlation stricte par 5-tuple et meme ordre de points "
            "que tcp_syn_no_synack (meme fonction _analyse_handshake, meme "
            "garde --nat-tolerant)."
        ),
        severity="anomalie",
        confidence=0.7,
        explanation=(
            "A la difference de tcp_syn_no_synack (aucun SYN-ACK nulle "
            "part), ici le SYN-ACK existe bel et bien et atteint au moins "
            "un point -- mais pas CE point precis, alors que le SYN, lui, y "
            "est bien passe. Signature typique d'un filtrage ou d'un "
            "routage asymetrique localise sur le trajet RETOUR entre ce "
            "point et l'origine du SYN-ACK."
        ),
        verification_leads=(
            "Identifier le point ou le SYN-ACK EST vu (necessite de "
            "recouper avec l'ordre des points, non porte directement par "
            "Report.syn_reply_missing) pour cerner le segment retour en "
            "cause ; verifier le routage retour et les ACL sur ce trajet."
        ),
    ),
    # -- variation de TTL -- analysis.py::analyse() (boucle principale,
    # Report.ttl_unstable) + synthesis.py::build_findings() ("-- TTL / topologie --")
    Rule(
        id="ttl_variation",
        domain="Routage",
        preconditions="au moins deux valeurs de TTL distinctes observees pour les paquets du meme flux au meme point.",
        required_metrics=("Report.ttl_unstable", "Pkt.ttl"),
        time_window="par flux, agrege en compteur de flux par point sur toute la capture.",
        required_context="au moins deux paquets du meme flux avec un TTL renseigne au meme point.",
        severity="a_surveiller",
        confidence=0.7,
        explanation=(
            "Le TTL d'un meme flux change en cours de route vu d'un seul "
            "point -- signe possible de routage asymetrique (les paquets de "
            "ce flux n'empruntent pas systematiquement le meme chemin), plus "
            "rarement un artefact de capture (ex: paquets dupliques par un "
            "SPAN mal configure)."
        ),
        verification_leads=(
            "Correler avec Report.hop_delta_outliers et la topologie deduite "
            "(ECMP/re-routage) sur ce point ; verifier si un evenement de "
            "convergence de routage coincide avec l'apparition de la "
            "variation."
        ),
    ),
    # -- delta de sauts hors norme (ECMP/re-routage) -- analysis.py::
    # analyse() (boucle principale, Report.hop_delta/hop_delta_outliers) +
    # synthesis.py::build_findings() ("-- TTL / topologie --")
    Rule(
        id="hop_delta_outliers",
        domain="Routage",
        preconditions=(
            "pour une paire de points adjacents (a, b), le delta de TTL "
            "(pkt_a.ttl - pkt_b.ttl) d'un flux differe du delta le PLUS "
            "FREQUENT (mode statistique) observe sur l'ensemble des flux de "
            "cette meme paire."
        ),
        required_metrics=("Report.hop_delta", "Report.hop_delta_outliers", "Pkt.ttl"),
        time_window=(
            "par flux, compare au mode calcule sur TOUTE la capture pour la "
            "paire, agrege en compteur par paire de points adjacents."
        ),
        required_context=(
            "paire de points adjacents (a, b) ; TTL renseigne aux deux "
            "points pour le flux ; au moins un flux vu sur cette paire pour "
            "qu'un mode existe."
        ),
        severity="a_surveiller",
        confidence=0.7,
        explanation=(
            "La majorite des flux entre ces deux points subit le meme "
            "nombre de sauts (delta de TTL identique, chemin routier "
            "stable) -- ce flux-ci s'en ecarte, signe possible d'ECMP "
            "(chemin different mais equivalent) ou d'un re-routage "
            "ponctuel ; ne distingue pas les deux causes."
        ),
        verification_leads=(
            "Correler avec ttl_variation sur les memes points (un routage "
            "asymetrique ou une bascule ECMP peut produire les deux "
            "signaux a la fois) ; verifier la table de routage ou les "
            "hachages ECMP des equipements intermediaires si le volume "
            "d'outliers est significatif."
        ),
    ),
    # -- remarking QoS -- analysis.py::analyse() (boucle principale,
    # Report.qos_change/qos_l2_remark/qos_l3_remark) +
    # synthesis.py::build_findings() ("-- QoS --")
    Rule(
        id="qos_dscp_remarking",
        domain="QoS",
        preconditions="le DSCP du meme flux differe entre deux points adjacents du chemin (pkt_a.dscp != pkt_b.dscp).",
        required_metrics=("Report.qos_change", "Report.qos_l2_remark", "Report.qos_l3_remark", "Pkt.dscp", "Pkt.ttl"),
        time_window="par flux, agrege en compteur par paire de points adjacents sur toute la capture.",
        required_context=(
            "paire de points adjacents (a, b) ; le meme flux vu aux deux "
            "points, avec un TTL renseigne des deux cotes pour l'attribution "
            "L2/L3."
        ),
        correlation_rule=(
            "le changement de DSCP est croise avec le delta de TTL entre les "
            "deux points : delta nul -> equipement L2 (switch, pas de saut "
            "de routeur) ; delta non nul -> equipement L3 (routeur)."
        ),
        severity="a_surveiller",
        confidence=0.75,
        explanation=(
            "Le marquage de priorite DSCP est modifie en cours de chemin. La "
            "distinction L2/L3 (via le delta de TTL) precise si le "
            "remarquage vient d'un commutateur ou d'un routeur, utile pour "
            "cibler l'equipement a auditer."
        ),
        verification_leads=(
            "Verifier la politique de classification/remarquage QoS "
            "configuree sur l'equipement identifie (L2 ou L3 selon le delta "
            "de TTL) ; confirmer si le remarquage est volontaire (politique "
            "QoS du transporteur) ou une mauvaise configuration."
        ),
    ),
    # -- remarking 802.1p (PCP) -- analysis.py::analyse() (boucle
    # principale, Report.pcp_change, meme bloc de code que vlan_change) +
    # synthesis.py::build_findings() ("-- QoS --")
    Rule(
        id="pcp_change",
        domain="QoS",
        preconditions=(
            "le meme flux, tagge VLAN aux DEUX points adjacents (a, b), "
            "porte une priorite 802.1p (PCP) differente entre les deux."
        ),
        required_metrics=("Report.pcp_change", "Pkt.vlan_id", "Pkt.vlan_prio"),
        time_window="par flux, agrege en compteur par paire de points adjacents sur toute la capture.",
        required_context=(
            "paire de points adjacents (a, b) ; le flux doit etre tagge "
            "VLAN des DEUX cotes (Pkt.vlan_id renseigne) avec une priorite "
            "802.1p lisible -- meme garde que vlan_change (meme bloc de "
            "code) ; signal DIFFERENT du remarquage DSCP (qos_dscp_remarking "
            "ci-dessus, champ L3 independant du champ L2 ici concerne)."
        ),
        severity="a_surveiller",
        confidence=0.8,
        explanation=(
            "La priorite de trame 802.1p (PCP, marquage L2) est modifiee en "
            "cours de chemin -- contrairement au DSCP (marquage L3, deja "
            "couvert par qos_dscp_remarking), un remarquage PCP ne peut "
            "venir que d'un equipement qui retague la trame elle-meme "
            "(commutateur, point d'acces)."
        ),
        verification_leads=(
            "Verifier la politique de classification/remarquage 802.1p "
            "configuree sur les commutateurs entre ces deux points ; "
            "confirmer si le remarquage est une segmentation QoS volontaire "
            "ou une incoherence de configuration de trunk."
        ),
    ),
    # -- fragmentation -- analysis.py::analyse() (boucle fragmentation/MTU,
    # Report.frag_new/encap_frag_correlated) + synthesis.py::build_findings()
    # ("-- fragmentation / MTU --")
    Rule(
        id="fragmentation_new",
        domain="Fragmentation",
        preconditions=(
            "un meme datagramme, identifie par (src, dst, ip_id), est vu NON "
            "fragmente au point amont et FRAGMENTE au point aval."
        ),
        required_metrics=(
            "Report.frag_new",
            "Report.encap_frag_correlated",
            "Pkt.ip_id",
            "Pkt.is_fragment",
            "Pkt.encap_tags",
        ),
        time_window="par datagramme, agrege en compteur par paire de points adjacents sur toute la capture.",
        required_context=(
            "paire de points adjacents (a, b) ; ip_id renseigne "
            "(systematique en IPv4, seulement si deja fragmente au point "
            "amont en IPv6 -- limite documentee dans analysis.py)."
        ),
        correlation_rule=(
            "le meme datagramme (src, dst, ip_id) est croise avec un "
            "changement de pile d'encapsulation (encap_tags) entre les deux "
            "memes points -- une coincidence confirme qu'un tunnel reduit le "
            "MTU disponible plutot qu'une fragmentation sans cause "
            "identifiee."
        ),
        severity="anomalie",
        confidence=0.75,
        explanation=(
            "Un datagramme devient fragmente en cours de route. Quand ce "
            "changement coincide avec un changement de pile d'encapsulation "
            "sur le meme segment (au moins un datagramme correle), la cause "
            "probable est ce tunnel qui reduit le MTU disponible (anomalie) ; "
            "sinon, cause non identifiee (a_surveiller)."
        ),
        verification_leads=(
            "Verifier le MTU configure sur le tunnel identifie "
            "(Report.encap_change_examples pour le detail de la pile "
            "d'encapsulation) ; envisager un ajustement de MSS clamping ou "
            "de PMTUD cote emetteur."
        ),
        thresholds={"correlated_encap_change_min_count": 1.0},
    ),
    # -- signal ICMP(v6) de fragmentation necessaire -- analysis.py::
    # analyse() (boucle fragmentation/MTU, Report.icmp_frag_needed pour
    # IPv4 + Report.icmpv6_too_big pour IPv6, meme signification
    # fonctionnelle) + synthesis.py::build_findings() ("-- fragmentation /
    # MTU --", deux sites distincts, meme severite -- une seule regle,
    # meme discipline que tcp_options_stripped)
    Rule(
        id="icmp_fragmentation_needed",
        domain="Fragmentation",
        preconditions=(
            "un message ICMP Fragmentation Needed (type 3, code 4 -- DF "
            "positionne sur un datagramme IPv4 trop gros) OU son equivalent "
            "IPv6 ICMPv6 Packet Too Big (type 2) est capture a un point."
        ),
        required_metrics=(
            "Report.icmp_frag_needed",
            "Report.icmpv6_too_big",
            "Pkt.proto",
            "Pkt.icmp_type",
            "Pkt.icmp_code",
            "Pkt.icmpv6_type",
        ),
        time_window="par paquet, agrege en compteur par point sur toute la capture.",
        required_context=(
            "paquet ICMP ou ICMPv6 capture a ce point ; aucune correlation "
            "multi-points necessaire, classification native tshark sur le "
            "seul paquet ICMP(v6). DEUX compteurs Report distincts (IPv4 et "
            "IPv6) mais UNE seule regle : meme signal fonctionnel que "
            "l'equivalent PMTUD noir (pmtud_blackhole ci-dessous) recherche "
            "par son ABSENCE -- ici c'est sa PRESENCE brute qui est "
            "comptee, sans le croisement avec les retransmissions en amont."
        ),
        severity="info",
        confidence=0.9,
        explanation=(
            "Un equipement du chemin signale explicitement qu'un datagramme "
            "est trop grand pour la MTU du saut suivant -- PMTUD en train "
            "de fonctionner normalement (l'emetteur est cense reduire sa "
            "taille de segment en reponse). Severite info : ce message EST "
            "le mecanisme de decouverte de MTU qui fonctionne, pas une "
            "panne -- voir pmtud_blackhole pour le cas ou ce signal est "
            "ABSENT alors qu'il serait attendu."
        ),
        verification_leads=(
            "Si ce signal est frequent sur un point donne, verifier la MTU "
            "reelle du lien menant a ce point (tunnel, VPN...) et envisager "
            "un ajustement de MSS clamping en amont pour eviter le cout "
            "d'un aller-retour PMTUD a chaque nouvelle connexion."
        ),
    ),
    # -- saturation -- analysis.py::_analyse_saturation() +
    # synthesis.py::build_findings() ("-- saturation / policing / bufferbloat --")
    Rule(
        id="saturation",
        domain="Saturation",
        preconditions=(
            "au moins un evenement de perte deja attribue a ce segment "
            "(Report.loss_event_buckets non vide pour la paire (a, b)), avec "
            "un debit calcule au point amont (Report.throughput)."
        ),
        required_metrics=("Report.saturation_verdict", "Report.loss_event_buckets", "Report.throughput"),
        time_window=(
            "fenetres de bucket_seconds (parametre CLI, 1s par defaut) ; "
            "compare les buckets ou une perte survient au reste de la serie "
            "de debit du point amont."
        ),
        required_context=(
            "au moins un bucket de debit calcule au point amont de la "
            'paire ; verdict "NON correlees" (frac_high <= 0.3) '
            "volontairement SANS Finding -- pas assez de signal pour "
            "conclure."
        ),
        correlation_rule=(
            "les buckets temporels ou une perte survient (loss_event_buckets) "
            "sont croises avec la serie complete de debit du point amont "
            "(throughput) -- la fraction de buckets de perte situee "
            "au-dessus du 75e percentile de debit (frac_high) determine le "
            "verdict."
        ),
        severity="anomalie",
        confidence=0.6,
        explanation=(
            "Correle les pertes avec le debit au moment ou elles "
            "surviennent. frac_high >= 0.7 avec une dispersion faible et un "
            "debit proche du maximum observe -> limitation/policing (seuil "
            "configure, anomalie). frac_high >= 0.6 seul -> saturation de "
            "lien/buffer (anomalie). frac_high <= 0.3 -> pertes non liees au "
            "debit, aucun Finding. Entre les deux -> correlation partielle "
            "(a_surveiller)."
        ),
        verification_leads=(
            "Verifier la bande passante contractuelle/configuree sur ce "
            "segment (policing) ou la taille des buffers (saturation) ; "
            "comparer le palier de debit observe a la capacite nominale du "
            "lien."
        ),
        thresholds={
            "frac_high_policing_min": 0.7,
            "rel_stdev_policing_max": 0.15,
            "mean_loss_ratio_policing_min": 0.85,
            "frac_high_saturation_min": 0.6,
            "frac_high_no_correlation_max": 0.3,
        },
    ),
    # -- bufferbloat -- analysis.py::_analyse_bufferbloat() +
    # synthesis.py::build_findings() ("-- saturation / policing / bufferbloat --")
    Rule(
        id="bufferbloat",
        domain="Bufferbloat",
        preconditions=(
            "latence moyenne du quartile de buckets a plus fort debit >= "
            "1.5x celle du quartile a plus faible debit, ET ecart absolu "
            "> 5ms."
        ),
        required_metrics=("Report.bufferbloat_hint", "Report.latency_by_bucket", "Report.throughput"),
        time_window=(
            "fenetres de bucket_seconds (1s par defaut) ; compare le "
            "quartile des buckets a plus faible debit au quartile a plus "
            "fort debit sur le meme segment."
        ),
        required_context=(
            "au moins quatre fenetres temporelles communes entre la serie de "
            "latence et la serie de debit du point amont sur ce segment."
        ),
        correlation_rule=(
            "la serie de latence par bucket (latency_by_bucket) est croisee "
            "avec la serie de debit (throughput) du meme point amont -- la "
            "latence moyenne du quartile de buckets a plus fort debit est "
            "comparee a celle du quartile a plus faible debit."
        ),
        severity="a_surveiller",
        confidence=0.6,
        explanation=(
            "La latence augmente sensiblement quand le debit augmente sur le "
            "meme segment -- signature d'un tampon (buffer) surdimensionne "
            "qui retient les paquets au lieu de les rejeter sous charge "
            "(bufferbloat), degradant la reactivite sans faire chuter le "
            "debit."
        ),
        verification_leads=(
            "Verifier la taille des files d'attente/buffers sur l'equipement "
            "en tete de ce segment ; envisager un AQM (active queue "
            "management, type CoDel/FQ-CoDel) si le lien est sature "
            "regulierement."
        ),
        thresholds={"high_over_low_ratio_min": 1.5, "min_absolute_delta_ms": 5.0, "min_common_buckets": 4.0},
    ),
    # -- RTP -- analysis.py::_analyse_rtp() + netcross_core.parsing.compute_mos
    # + synthesis.py::build_findings() ("-- RTP / qualite voix --")
    Rule(
        id="rtp_quality_mos",
        domain="RTP/Voix",
        preconditions=(
            "un flux RTP identifie (SSRC) avec un MOS calculable (compute_mos a produit une valeur, pas None)."
        ),
        required_metrics=("Report.rtp_streams",),
        time_window="par flux RTP (SSRC), sur toute sa duree.",
        required_context=(
            "flux RTP avec suffisamment d'echantillons de gigue/perte pour "
            "que compute_mos produise une valeur -- voir "
            "Report.rtp_streams[i]['sample_count'] pour la taille de "
            "l'echantillon, deja annotee comme score de confiance ailleurs "
            "dans ce projet (synthesis.py, sample_size)."
        ),
        severity="anomalie",
        confidence=0.6,
        explanation=(
            "MOS (Mean Opinion Score) estime a partir du R-factor, lui-meme "
            "derive de la gigue et du taux de perte du flux RTP (E-model "
            "simplifie G.711, voir _analyse_rtp). MOS < 3.0 -> qualite "
            "degradee perceptible (anomalie). MOS < 3.6 -> qualite limite "
            "(a_surveiller). >= 3.6 -> pas de Finding."
        ),
        verification_leads=(
            "Verifier la gigue et le taux de perte bruts du flux (au-dela du "
            "seul MOS agrege) ; un MOS degrade avec une gigue elevee pointe "
            "vers un probleme de priorisation reseau (QoS), un MOS degrade "
            "avec des pertes pointe vers de la congestion ou un probleme "
            "radio/WiFi en bout de chaine."
        ),
        thresholds={"anomalie_mos_max": 3.0, "a_surveiller_mos_max": 3.6},
    ),
    # -- DHCP -- analysis.py::_analyse_dhcp() + synthesis.py::build_findings()
    # ("-- DHCP --") : deux signatures distinctes, meme severite -> une seule regle
    Rule(
        id="dhcp_issues",
        domain="DHCP",
        preconditions=(
            "au moins un DHCPNAK observe a un point (Report.dhcp_nak_count) "
            "OU au moins un type de message DHCP vu en amont et absent en "
            "aval pour la meme transaction xid (Report.dhcp_missing)."
        ),
        required_metrics=("Report.dhcp_nak_count", "Report.dhcp_missing", "Pkt.dhcp_msg_type", "Pkt.dhcp_xid"),
        time_window=(
            "par transaction DHCP (xid) ; la duree DISCOVER->ACK est mesuree "
            "par ce meme detecteur (Report.dhcp_duration_ms) mais n'entre "
            "dans aucun Finding a ce jour."
        ),
        required_context=(
            "le NAK ne necessite aucun ordre de points ; le message manquant "
            "necessite un ordre de points connu (Report.pairs) pour comparer "
            "amont/aval."
        ),
        severity="anomalie",
        confidence=0.8,
        explanation=(
            "Deux signatures distinctes, toutes deux en anomalie : un "
            "DHCPNAK (demande d'adresse rejetee explicitement par le "
            "serveur) et un message DHCP present en amont mais jamais recu "
            "en aval (mise a risque de l'attribution d'adresse sur ce "
            "segment)."
        ),
        verification_leads=(
            "Pour un NAK : verifier la reservation/l'etendue DHCP cote "
            "serveur pour ce client. Pour un message manquant : verifier le "
            "relai DHCP (option 82/ip helper-address) sur l'equipement entre "
            "les deux points."
        ),
    ),
    # -- SIP -- analysis.py::_analyse_sip() + synthesis.py::build_findings()
    # ("-- SIP --") : deux signatures distinctes, meme severite -> une seule regle
    Rule(
        id="sip_issues",
        domain="SIP",
        preconditions=(
            "au moins un appel SIP se terminant par une reponse finale "
            "4xx/5xx/6xx a l'INVITE (Report.sip_failed_calls) OU au moins un "
            "type de message SIP vu en amont et absent en aval pour le meme "
            "Call-ID (Report.sip_missing)."
        ),
        required_metrics=("Report.sip_failed_calls", "Report.sip_missing", "Pkt.sip_msg_type", "Pkt.sip_call_id"),
        time_window=(
            "par appel SIP (Call-ID) ; la duree d'etablissement INVITE->200 "
            "est mesuree par ce meme detecteur (Report.sip_setup_duration_ms) "
            "mais n'entre dans aucun Finding a ce jour."
        ),
        required_context=(
            "l'appel en echec ne necessite aucun ordre de points (une seule "
            "reponse finale suffit) ; le message manquant necessite un ordre "
            "de points connu (Report.pairs)."
        ),
        severity="anomalie",
        confidence=0.8,
        explanation=(
            "Deux signatures distinctes, toutes deux en anomalie : un appel "
            "qui echoue avec un code final 4xx/5xx/6xx, et un message de "
            "signalisation present en amont mais jamais recu en aval sur un "
            "segment donne."
        ),
        verification_leads=(
            "Pour un appel en echec : lire le code de reponse final "
            "(Report.sip_failed_calls) pour orienter le diagnostic (4xx = "
            "probleme cote appele/authentification, 5xx = probleme serveur, "
            "6xx = refus global). Pour un message manquant : verifier le "
            "trajet SIP/RTP (ALG SIP, NAT, firewall) sur le segment concerne."
        ),
    ),
    # ------------------------------------------------------------------
    # Session 47 -- cinq des six "regles nouvelles" de la section 6.2,
    # verifiees deja implementees avant redaction (voir docstring de
    # module). Meme discipline de traçabilite que les quinze regles
    # ci-dessus : chaque champ verifie directement contre le code source.
    # ------------------------------------------------------------------
    # -- DNS lent -- analysis.py::_analyse_dns() +
    # synthesis.py::build_findings() ("-- DNS --")
    Rule(
        id="dns_slow_resolution",
        domain="DNS",
        preconditions=(
            "au moins une transaction DNS (Pkt.dns_txn_id) avec une requete "
            "ET une reponse observees (a n'importe quel point), reponse "
            "posterieure a la requete."
        ),
        required_metrics=("Report.dns_duration_ms", "Pkt.dns_txn_id", "Pkt.dns_is_response"),
        time_window=(
            "agrege sur TOUTE la capture : une seule moyenne globale toutes "
            "transactions confondues, pas par point ni par paire."
        ),
        required_context=(
            "aucun ordre de points requis pour la duree elle-meme (seule la "
            "detection des messages manquants, Report.dns_missing, hors de "
            "cette regle, en a besoin) ; identifiant de transaction sur 16 "
            "bits seulement (limite documentee de reutilisation sur capture "
            "tres chargee, voir _analyse_dns)."
        ),
        severity="a_surveiller",
        confidence=0.8,
        explanation=(
            "Duree moyenne requete -> reponse DNS superieure a 200ms sur "
            "l'ensemble de la capture -- cause frequente de lenteurs "
            "applicatives percues a tort comme un probleme reseau (la "
            "resolution precede le vrai transfert de donnees)."
        ),
        verification_leads=(
            "Verifier la charge et la localisation du serveur/resolveur DNS "
            "utilise ; comparer a la latence reseau brute vers ce serveur "
            "pour confirmer que le delai vient bien de la resolution et non "
            "du transport."
        ),
        thresholds={"mean_duration_ms_min": 200.0},
    ),
    # -- reponses DNS NXDOMAIN -- analysis.py::_analyse_dns()
    # (Report.dns_nxdomain_count) + synthesis.py::build_findings()
    # ("-- DNS --")
    Rule(
        id="dns_nxdomain",
        domain="DNS",
        preconditions="une reponse DNS porte le RCODE NXDOMAIN (3, RFC 1035 section 4.1.1) -- domaine inexistant.",
        required_metrics=("Report.dns_nxdomain_count", "Pkt.dns_is_response", "Pkt.dns_rcode"),
        time_window="par paquet reponse, agrege en compteur par point sur toute la capture.",
        required_context=(
            "paquet DNS reponse capture a ce point ; aucune correlation "
            "multi-points necessaire, lecture directe du RCODE natif tshark."
        ),
        severity="info",
        confidence=0.9,
        explanation=(
            "Le domaine demande n'existe pas selon le resolveur/serveur "
            "interroge -- pas forcement un probleme reseau (faute de frappe "
            "cote client, domaine decommissionne...), mais un volume "
            "inhabituel peut reveler une configuration DNS erronee "
            "(mauvaise zone, mauvais suffixe de recherche) plutot qu'un "
            "trafic legitime."
        ),
        verification_leads=(
            "Verifier le(s) nom(s) de domaine concerne(s) (necessite une "
            "capture cote client, Report ne conserve pas les noms au-dela "
            "du compteur) et le suffixe de recherche DNS configure si le "
            "volume est eleve et concentre sur un seul point."
        ),
    ),
    # -- reponses DNS SERVFAIL -- analysis.py::_analyse_dns()
    # (Report.dns_servfail_count) + synthesis.py::build_findings()
    # ("-- DNS --")
    Rule(
        id="dns_servfail",
        domain="DNS",
        preconditions=(
            "une reponse DNS porte le RCODE SERVFAIL (2, RFC 1035 section "
            "4.1.1) -- echec de resolution cote serveur/resolveur."
        ),
        required_metrics=("Report.dns_servfail_count", "Pkt.dns_is_response", "Pkt.dns_rcode"),
        time_window="par paquet reponse, agrege en compteur par point sur toute la capture.",
        required_context=(
            "paquet DNS reponse capture a ce point ; aucune correlation "
            "multi-points necessaire, lecture directe du RCODE natif tshark."
        ),
        severity="anomalie",
        confidence=0.9,
        explanation=(
            "Le resolveur/serveur interroge echoue lui-meme a resoudre la "
            "requete (DNSSEC invalide, serveur faisant autorite "
            "injoignable, boucle de delegation...) -- souvent pris a tort "
            "pour un probleme reseau alors que le reseau a correctement "
            "achemine la requete ET la reponse d'erreur."
        ),
        verification_leads=(
            "Verifier les journaux du resolveur/serveur DNS identifie pour "
            "la cause exacte du SERVFAIL (DNSSEC, delegation, timeout vers "
            "un serveur faisant autorite) plutot que le chemin reseau "
            "jusqu'a ce resolveur."
        ),
    ),
    # -- requetes DNS sans aucune reponse -- analysis.py::_analyse_dns()
    # (Report.dns_timeout) + synthesis.py::build_findings() ("-- DNS --")
    Rule(
        id="dns_timeout",
        domain="DNS",
        preconditions=(
            "une requete DNS (identifiee par Pkt.dns_txn_id) est vue a un "
            "point, et AUCUNE reponse portant le meme identifiant n'est "
            "observee, a aucun point, sur toute la capture."
        ),
        required_metrics=("Report.dns_timeout", "Pkt.dns_txn_id", "Pkt.dns_is_response", "Pkt.ts"),
        time_window=(
            "par transaction (identifiant 16 bits), l'absence de reponse "
            "est verifiee sur TOUTE la capture avant de conclure."
        ),
        required_context=(
            "identifiant de transaction DNS sur 16 bits (limite de "
            "reutilisation documentee sur capture tres chargee, voir "
            "_analyse_dns) ; aucun ordre de points requis -- absence "
            "verifiee tous points confondus, contrairement a dns_missing "
            "ci-dessous."
        ),
        severity="anomalie",
        confidence=0.8,
        explanation=(
            "Une requete DNS reste durablement sans reponse visible dans la "
            "capture -- timeout applicatif cote client, ou serveur/"
            "resolveur injoignable. A distinguer de dns_missing ci-dessous "
            "(une reponse existe mais ne remonte pas jusqu'a un point "
            "precis)."
        ),
        verification_leads=(
            "Verifier la disponibilite et la joignabilite du serveur/"
            "resolveur DNS cible ; confirmer que la capture couvre bien la "
            "fenetre de retry applicative avant de conclure a un vrai "
            "timeout plutot qu'a une reponse simplement tardive et hors "
            "capture."
        ),
    ),
    # -- messages DNS perdus entre deux points -- analysis.py::_analyse_dns()
    # (Report.dns_missing) + synthesis.py::build_findings() ("-- DNS --")
    Rule(
        id="dns_missing",
        domain="DNS",
        preconditions=(
            "pour une paire de points adjacents (a, b), un message DNS "
            "(requete ou reponse, identifie par Pkt.dns_txn_id) est vu en a "
            "mais absent en b."
        ),
        required_metrics=("Report.dns_missing", "Pkt.dns_txn_id", "Pkt.dns_is_response"),
        time_window=(
            "par transaction et par type de message, agrege en liste par "
            "paire de points adjacents sur toute la capture."
        ),
        required_context=(
            "necessite un ordre de points connu (Report.pairs) -- meme "
            "structure que sip_issues (Report.sip_missing ci-dessus) mais "
            "par identifiant de transaction DNS plutot que par Call-ID."
        ),
        severity="a_surveiller",
        confidence=0.8,
        explanation=(
            "Un message DNS observe a un point n'est pas revu au point "
            "adjacent attendu -- perte localisee sur ce segment precis, a "
            "distinguer de dns_timeout ci-dessus (ou aucune reponse "
            "n'existe nulle part : ici la reponse existe potentiellement, "
            "elle ne franchit simplement pas ce segment)."
        ),
        verification_leads=(
            "Verifier le filtrage UDP/53 (et TCP/53 pour les reponses "
            "volumineuses) sur l'equipement entre ces deux points ; "
            "confirmer si une perte generale (Report.loss_count) coincide "
            "sur le meme segment plutot qu'un filtrage specifique au trafic "
            "DNS."
        ),
    ),
    # -- PMTUD black hole -- analysis.py::_analyse_pmtud() +
    # synthesis.py::build_findings() ("-- PMTUD (noir) --")
    Rule(
        id="pmtud_blackhole",
        domain="PMTUD",
        preconditions=(
            "un flux TCP vu au point amont (>= 2 segments de donnees, taille "
            "significative) mais JAMAIS vu au point aval ; DF actif sur "
            "toutes les tentatives (IPv4) ou flux IPv6 (pas de condition DF "
            "equivalente) ; aucun signal ICMP(v6) de MTU insuffisant observe "
            "au point amont sur toute la capture."
        ),
        required_metrics=(
            "Report.pmtud_blackhole",
            "Report.icmp_frag_needed",
            "Report.icmpv6_too_big",
            "Pkt.payload_hash",
            "Pkt.df",
            "Pkt.length",
        ),
        time_window="par flux ; le signal ICMP(v6) est recherche sur toute la duree de la capture au point amont.",
        required_context=(
            "correlation stricte par 5-tuple (cle TCP de `flows`, exclue en "
            "mode --nat-tolerant) ; appelee apres le bloc fragmentation/MTU "
            "de analyse() (necessite icmp_frag_needed/icmpv6_too_big deja "
            "peuples)."
        ),
        correlation_rule=(
            "un flux TCP retransmis plusieurs fois au point amont sans "
            "jamais atteindre le point aval est croise avec l'ABSENCE de "
            "message ICMP(v6) de MTU insuffisant au meme point amont, sur "
            "toute la capture (pas une fenetre precise autour de CE segment) "
            "-- l'absence du signal qui devrait normalement accompagner ce "
            "symptome est ce qui distingue un noir PMTUD d'une simple perte."
        ),
        severity="anomalie",
        confidence=0.75,
        explanation=(
            "Un routeur intermediaire ne peut pas transmettre ce segment "
            "(MTU insuffisant, typiquement un tunnel qui ajoute des octets "
            "d'en-tete) et devrait le signaler par ICMP(v6), mais ce message "
            "est filtre ou jamais emis -- l'emetteur ne reduit alors jamais "
            "la taille de ses segments et la connexion stagne indefiniment "
            "(RFC 1191 IPv4 / RFC 8201 IPv6)."
        ),
        verification_leads=(
            "Verifier que l'ICMP(v6) n'est pas bloque par un pare-feu sur le "
            "chemin ; verifier le MTU reel de chaque saut (tunnel/VPN "
            "notamment) et envisager un MSS clamping explicite si "
            "l'equipement intermediaire ne le fait pas deja."
        ),
        thresholds={"min_segment_bytes": 512.0, "min_upstream_attempts": 2.0},
    ),
    # -- NAT/FW silencieux -- analysis.py::_analyse_idle_timeout() +
    # synthesis.py::build_findings() ("-- timeout d'inactivite / coupure
    # NAT-FW silencieuse --")
    Rule(
        id="nat_fw_silent_drop",
        domain="NAT/Pare-feu",
        preconditions=(
            "une connexion TCP deja vue aux DEUX points (a, b) d'un segment ; "
            "le plus grand silence entre deux paquets consecutifs au point "
            "amont depasse le seuil ; le trafic qui reprend en amont apres "
            "ce silence n'est plus jamais revu au point aval."
        ),
        required_metrics=(
            "Report.idle_timeout_dropped",
            "Pkt.proto",
            "Pkt.ts",
            "Pkt.src",
            "Pkt.sport",
            "Pkt.dst",
            "Pkt.dport",
        ),
        time_window="reconstruit sa propre vue par connexion (5-tuple) sur toute la capture, pas par bucket.",
        required_context=(
            "connexion vue en aval AVANT la reprise (distingue ce scenario "
            "d'une simple perte de flux classique, deja couverte par "
            "Report.loss_count) ; limite au TCP (notion de session avec "
            "etablissement/silence/reprise sans equivalent direct en UDP)."
        ),
        severity="anomalie",
        confidence=0.7,
        explanation=(
            "Une session TCP de longue duree traverse un equipement NAT/"
            "pare-feu a etat ; pendant un silence plus long que le seuil, son "
            "entree de table d'etat est purgee ; quand le trafic reprend, "
            "l'equipement ne reconnait plus le flux et le rejette SANS RST "
            "(sinon ce serait un rejet explicite, deja couvert par "
            "tcp_rst_localized), d'ou le qualificatif <<silencieuse>>."
        ),
        verification_leads=(
            "Verifier la duree du timeout d'etat configure sur l'equipement "
            "NAT/pare-feu identifie (rarement publiee, souvent bien en deca "
            "de la recommandation RFC 5382 de 2h04 pour un NAT conforme) ; "
            "envisager un keepalive applicatif plus frequent que ce silence "
            "observe."
        ),
        thresholds={"idle_timeout_seconds": 60.0},
    ),
    # -- anomalies L2, 1/3 : conflit ARP --
    # analysis.py::_analyse_arp_ip_conflict() +
    # synthesis.py::build_findings() ("-- conflit d'adresse IP (ARP) --")
    Rule(
        id="arp_ip_conflict",
        domain="ARP",
        preconditions=(
            "la meme adresse IP source est revendiquee par au moins deux adresses MAC differentes au meme point."
        ),
        required_metrics=("Report.arp_ip_conflict", "Pkt.proto", "Pkt.arp_sender_mac", "Pkt.src"),
        time_window=(
            "agrege sur toute la capture, par point ; aucune fenetre "
            "temporelle (deux revendications tres espacees comptent quand "
            "meme)."
        ),
        required_context=(
            "detection PAR POINT uniquement -- ARP n'est jamais relaye par "
            "un routeur (exclu de `flows`), une comparaison amont/aval "
            "n'aurait pas de sens pour ce protocole."
        ),
        severity="anomalie",
        confidence=0.7,
        explanation=(
            "Deux hotes revendiquent la meme adresse IP sur le meme segment "
            "de diffusion -- symptome classique : connexions intermittentes, "
            "deux postes qui se coupent alternativement, IP flottante "
            "dupliquee, ou erreur de plan d'adressage statique. Ne distingue "
            "PAS un vrai conflit d'un basculement HA/VRRP legitime (meme "
            "signature ARP dans les deux cas)."
        ),
        verification_leads=(
            "Verifier le plan d'adressage statique pour cette IP ; confirmer "
            "l'absence d'un mecanisme de haute disponibilite legitime "
            "(VRRP/keepalived) avant de conclure a une vraie erreur de "
            "configuration."
        ),
        thresholds={"min_distinct_macs": 2.0},
    ),
    # -- anomalies L2, 2/3 : instabilite STP --
    # analysis.py::_analyse_stp_instability() +
    # synthesis.py::build_findings() ("-- instabilite STP --")
    Rule(
        id="stp_instability",
        domain="STP",
        preconditions=(
            "au moins une BPDU TCN (0x80) ou une Configuration BPDU avec le "
            "bit TC actif observee a ce point (Report.stp_topology_change) "
            "OU l'identifiant du pont racine change d'une Configuration BPDU "
            "a la suivante au meme point (Report.stp_root_change)."
        ),
        required_metrics=(
            "Report.stp_topology_change",
            "Report.stp_root_change",
            "Pkt.stp_bpdu_type",
            "Pkt.stp_flags_tc",
            "Pkt.stp_root_id",
        ),
        time_window=(
            "par point, sur toute la capture ; le changement de racine "
            "compare des BPDU consecutives triees par horodatage au meme "
            "point."
        ),
        required_context=(
            "detection PAR POINT uniquement -- STP, comme ARP, n'est jamais "
            "relaye par un routeur ; les deux compteurs sont deux signatures "
            "independantes du meme phenomene, comptees separement mais avec "
            "la meme severite."
        ),
        severity="anomalie",
        confidence=0.8,
        explanation=(
            "Tempete de changements de topologie ou reelections repetees du "
            "pont racine -- deux signatures classiques d'une boucle de "
            "commutation ou d'un lien/port qui flappe. Observe la "
            "CONSEQUENCE visible sur le fil, pas la cause exacte (quel port, "
            "quel commutateur) : cette information vit dans l'etat interne "
            "du commutateur (SNMP/syslog), pas sur le fil."
        ),
        verification_leads=(
            "Verifier les journaux/SNMP des commutateurs pour identifier le "
            "port qui flappe ou la boucle physique ; une seule reelection en "
            "tout debut de capture peut etre benigne (mise sous tension), "
            "des reelections repetees sur toute la duree ne le sont pas."
        ),
    ),
    # -- anomalies L2, 3/3 : changement de VLAN -- analysis.py::analyse()
    # (boucle principale, Report.vlan_change) +
    # synthesis.py::build_findings() ("-- VLAN --")
    Rule(
        id="vlan_change",
        domain="VLAN",
        preconditions=(
            "le meme flux, tagge aux DEUX points adjacents (a, b), porte un ID VLAN different entre les deux."
        ),
        required_metrics=("Report.vlan_change", "Pkt.vlan_id"),
        time_window="par flux, agrege en compteur par paire de points adjacents sur toute la capture.",
        required_context=(
            "paire de points adjacents (a, b) ; le flux doit etre tagge des "
            "DEUX cotes (Pkt.vlan_id renseigne) -- une transition "
            "tag/pas-tag est un signal DIFFERENT (Report.vlan_tag_flip), "
            "calcule mais non expose en Finding a ce jour, comme "
            "Report.rst_count ou Report.pcp_change (802.1p, meme bloc de "
            "code, non expose non plus)."
        ),
        severity="a_surveiller",
        confidence=0.8,
        explanation=(
            "Le meme flux change d'identifiant VLAN en cours de chemin -- "
            "peut etre un retaggage volontaire (segmentation reseau par un "
            "commutateur/routeur intermediaire) ou une erreur de "
            "configuration de trunk/VLAN natif."
        ),
        verification_leads=(
            "Verifier la configuration des ports trunk et l'assignation VLAN "
            "sur les equipements entre les deux points ; confirmer si le "
            "changement est une segmentation volontaire documentee."
        ),
    ),
    # -- options TCP incompatibles, 1/2 : options retirees en chemin --
    # analysis.py::_analyse_tcp_options() + synthesis.py::build_findings()
    # ("-- TCP avance --")
    Rule(
        id="tcp_options_stripped",
        domain="TCP",
        preconditions=(
            "pour le MEME paquet SYN/SYN-ACK (meme 5-tuple + seq) entre deux "
            "points adjacents : l'option Window Scale est presente en amont "
            "et absente en aval (Report.wscale_stripped), OU l'option SACK "
            "Permitted est presente en amont et absente en aval "
            "(Report.sack_stripped)."
        ),
        required_metrics=(
            "Report.wscale_stripped",
            "Report.sack_stripped",
            "Pkt.wscale_shift",
            "Pkt.sack_permitted",
            "Pkt.flags",
        ),
        time_window="par handshake, agrege en compteur par paire de points adjacents sur toute la capture.",
        required_context=(
            "correlation stricte par 5-tuple (comme _analyse_handshake, "
            "desactivee en mode --nat-tolerant) et ordre de points explicite "
            "ou deductible (`pairs`) ; limite aux paquets de handshake (SYN "
            "ou SYN-ACK, Pkt.flags contient 'S')."
        ),
        severity="a_surveiller",
        confidence=0.8,
        explanation=(
            "Un equipement intermediaire retire une option TCP negociee au "
            "handshake. Window Scale retire : le window scaling se "
            "desactive pour TOUTE la connexion des qu'un seul cote ne le "
            "propose plus, plafonnant la fenetre effective a 65535 octets "
            "(limite de debit classique sur un lien a fort produit "
            "debit x latence). SACK Permitted retire : recuperation de "
            "perte moins efficace (renvoi de fenetre entiere plutot que des "
            "seuls segments manquants, voir tcp_retransmission_rto/"
            "_spurious pour le symptome correspondant)."
        ),
        verification_leads=(
            "Identifier l'equipement intermediaire qui reecrit les options "
            "TCP (proxy transparent, pare-feu applicatif, optimiseur WAN) et "
            "verifier s'il peut etre configure pour preserver ces options."
        ),
    ),
    # -- options TCP incompatibles, 2/2 : MSS clamped (meme fonction
    # source que tcp_options_stripped, severite differente, pas nomme par
    # la section 6.2 mais catalogue pour ne pas laisser un signal orphelin
    # de son detecteur deja formalise) --
    # analysis.py::_analyse_tcp_options()
    Rule(
        id="tcp_mss_clamped",
        domain="TCP",
        preconditions=(
            "pour le MEME paquet SYN/SYN-ACK entre deux points adjacents, la "
            "valeur MSS annoncee differe entre le point amont et le point "
            "aval."
        ),
        required_metrics=("Report.mss_clamped", "Pkt.mss_val"),
        time_window="par handshake, agrege en compteur par paire de points adjacents sur toute la capture.",
        required_context=(
            "meme correlation stricte par 5-tuple + ordre de points que "
            "tcp_options_stripped, meme garde --nat-tolerant."
        ),
        severity="info",
        confidence=0.8,
        explanation=(
            "Un equipement intermediaire (VPN, tunnel...) reecrit l'option "
            "MSS. Le plus souvent une adaptation DELIBEREE et benefique -- "
            "evite justement un noir PMTUD (voir pmtud_blackhole) -- d'ou "
            "une severite info et non une anomalie."
        ),
        verification_leads=(
            "Confirmer que la reduction de MSS correspond bien a une "
            "adaptation MTU intentionnelle de l'equipement identifie plutot "
            "qu'a une incoherence de configuration."
        ),
    ),
    # -- decomposition applicatif/reseau (une des trois categories
    # restees entierement sans regle apres la Session 49, voir CLAUDE.md
    # "Prochaine feature" -- traitee en Session 51) --
    # synthesis.py::build_findings() ("-- decomposition reseau / serveur --")
    Rule(
        id="server_processing_dominant",
        domain="Reseau/Serveur",
        preconditions=(
            "le temps de traitement serveur moyen (Report.server_think_time, "
            "tous points confondus) depasse strictement 3 fois la latence "
            "reseau moyenne entre le premier et le dernier point de capture "
            "(Report.latency), ET reste superieur a 20ms en valeur absolue "
            "(seuil bas pour ecarter un ralentissement negligeable meme si "
            "le ratio 3x est atteint)."
        ),
        required_metrics=("Report.server_think_time", "Report.latency", "Report.points"),
        time_window="agrege sur toute la capture, un seul constat global (segment 'global').",
        required_context=(
            "au moins deux points de capture (la latence reseau reference "
            "toujours le PREMIER et le DERNIER point de r.points, pas une "
            "paire adjacente quelconque) ; au moins un tour "
            "requete-reponse HTTP/SIP mesure par _analyse_response_time "
            "pour peupler server_think_time."
        ),
        severity="a_surveiller",
        confidence=0.7,
        explanation=(
            "Le temps de traitement cote serveur domine tres largement le "
            "temps de trajet reseau -- le ralentissement observe par le "
            "client est probablement applicatif (base de donnees, calcul, "
            "file d'attente cote serveur) plutot que du a un probleme de "
            "transport. Seuil (3x, 20ms) delibere et non calibre a un "
            "equipement/protocole precis, meme registre que les autres "
            "regles a confiance 0.7 de ce catalogue (silence NAT/pare-feu, "
            "conflit ARP)."
        ),
        verification_leads=(
            "Comparer le temps de traitement serveur a une periode de "
            "reference connue pour ce service ; verifier la charge "
            "applicative (CPU, requetes base de donnees en attente) sur le "
            "serveur cote destination pendant la fenetre de capture plutot "
            "que de chercher une cause reseau."
        ),
        thresholds={"ratio_serveur_reseau": 3.0, "seuil_serveur_ms": 20.0},
    ),
    # ------------------------------------------------------------------
    # Session 52 -- deuxieme des trois categories laissees ouvertes par
    # la Session 51 ("HTTP", cinq sites de Finding). Meme discipline de
    # tracabilite : chaque champ verifie directement contre le code
    # source (analysis.py::_analyse_http, synthesis.py::build_findings,
    # bloc "-- HTTP --").
    # ------------------------------------------------------------------
    # -- reponses HTTP 4xx -- analysis.py::_analyse_http()
    # (Report.http_client_error_count) + synthesis.py::build_findings()
    # ("-- HTTP --")
    Rule(
        id="http_client_error",
        domain="HTTP",
        preconditions=(
            "une reponse HTTP porte un code de statut dans la plage 400-499 (erreur cote client/application)."
        ),
        required_metrics=("Report.http_client_error_count", "Pkt.http_is_response", "Pkt.http_status_code"),
        time_window="par paquet reponse, agrege en compteur par point sur toute la capture.",
        required_context=(
            "paquet HTTP reponse capture a ce point ; aucune correlation "
            "multi-points necessaire, lecture directe du code de statut "
            "natif tshark (dissection HTTP/1.x uniquement, voir docstring "
            "de module de _analyse_http)."
        ),
        severity="info",
        confidence=0.9,
        explanation=(
            "Le client a recu une erreur imputable a sa propre requete "
            "(ressource introuvable, requete malformee, authentification "
            "manquante...) -- pas forcement un probleme reseau, meme "
            "registre que dns_nxdomain ci-dessus : le reseau a correctement "
            "achemine la requete ET la reponse d'erreur."
        ),
        verification_leads=(
            "Verifier la ou les URI concernees (Report conserve jusqu'a "
            "cinq exemples methode+URI+code par point, voir "
            "http_error_examples) et confirmer cote application si le "
            "volume observe correspond a un comportement client attendu "
            "plutot qu'a une regression."
        ),
    ),
    # -- reponses HTTP 5xx -- analysis.py::_analyse_http()
    # (Report.http_server_error_count) + synthesis.py::build_findings()
    # ("-- HTTP --")
    Rule(
        id="http_server_error",
        domain="HTTP",
        preconditions=(
            "une reponse HTTP porte un code de statut dans la plage 500-599 (echec cote serveur/application)."
        ),
        required_metrics=("Report.http_server_error_count", "Pkt.http_is_response", "Pkt.http_status_code"),
        time_window="par paquet reponse, agrege en compteur par point sur toute la capture.",
        required_context=(
            "paquet HTTP reponse capture a ce point ; aucune correlation "
            "multi-points necessaire, lecture directe du code de statut "
            "natif tshark."
        ),
        severity="anomalie",
        confidence=0.9,
        explanation=(
            "Le serveur/l'application echoue a traiter une requete "
            "pourtant recue -- meme registre que dns_servfail ci-dessus : "
            "souvent pris a tort pour un probleme reseau alors que le "
            "reseau a correctement achemine la requete ET la reponse "
            "d'erreur."
        ),
        verification_leads=(
            "Verifier les journaux applicatifs du serveur identifie pour "
            "la cause exacte (exception non geree, dependance indisponible, "
            "saturation) plutot que le chemin reseau jusqu'a ce serveur ; "
            "Report conserve jusqu'a cinq exemples methode+URI+code par "
            "point (http_error_examples)."
        ),
    ),
    # -- requetes HTTP sans aucune reponse -- analysis.py::_analyse_http()
    # (Report.http_timeout) + synthesis.py::build_findings() ("-- HTTP --")
    Rule(
        id="http_timeout",
        domain="HTTP",
        preconditions=(
            "une requete HTTP est vue a un point pour une transaction "
            "donnee, et AUCUNE reponse correspondante n'est observee, a "
            "aucun point, sur toute la capture."
        ),
        required_metrics=("Report.http_timeout", "Pkt.http_is_request", "Pkt.http_is_response", "Pkt.ts"),
        time_window=("par transaction, l'absence de reponse est verifiee sur TOUTE la capture avant de conclure."),
        required_context=(
            "cle de transaction (connexion TCP 5-tuple non ordonne, URI, "
            "Nieme occurrence de cette URI sur cette connexion) -- PAS un "
            "identifiant de transaction numerique comme Pkt.dns_txn_id "
            "(HTTP/1.x n'en porte pas) : une position ordinale pure se "
            "desynchroniserait des qu'une requete entiere est perdue sur "
            "un segment, voir docstring de _analyse_http pour la "
            "justification complete et la limite assumee (polling repete "
            "de la meme URI sur la meme connexion)."
        ),
        severity="anomalie",
        confidence=0.8,
        explanation=(
            "Une requete HTTP reste durablement sans reponse visible dans "
            "la capture -- timeout applicatif cote client, ou serveur "
            "injoignable/surcharge. A distinguer de http_missing "
            "ci-dessous (une reponse existe mais ne franchit pas un "
            "segment precis) -- meme distinction que dns_timeout/"
            "dns_missing."
        ),
        verification_leads=(
            "Verifier la disponibilite et la joignabilite du serveur "
            "cible ; confirmer que la capture couvre bien la fenetre de "
            "retry applicative avant de conclure a un vrai timeout plutot "
            "qu'a une reponse simplement tardive et hors capture."
        ),
    ),
    # -- messages HTTP perdus entre deux points -- analysis.py::_analyse_http()
    # (Report.http_missing) + synthesis.py::build_findings() ("-- HTTP --")
    Rule(
        id="http_missing",
        domain="HTTP",
        preconditions=(
            "pour une paire de points adjacents (a, b), un message HTTP "
            "(requete ou reponse, identifie par la cle de transaction "
            "conn_id+URI+occurrence) est vu en a mais absent en b."
        ),
        required_metrics=(
            "Report.http_missing",
            "Pkt.http_is_request",
            "Pkt.http_is_response",
            "Pkt.http_uri",
        ),
        time_window=(
            "par transaction et par type de message, agrege en liste par "
            "paire de points adjacents sur toute la capture."
        ),
        required_context=(
            "necessite un ordre de points connu (Report.pairs) -- meme "
            "structure que dns_missing ci-dessus, mais par cle de "
            "transaction HTTP (conn_id+URI+occurrence) plutot que par "
            "identifiant de transaction DNS."
        ),
        severity="a_surveiller",
        confidence=0.8,
        explanation=(
            "Un message HTTP observe a un point n'est pas revu au point "
            "adjacent attendu -- perte localisee sur ce segment precis, a "
            "distinguer de http_timeout ci-dessus (ou aucune reponse "
            "n'existe nulle part)."
        ),
        verification_leads=(
            "Verifier le filtrage TCP sur le port applicatif concerne "
            "entre ces deux points ; confirmer si une perte generale "
            "(Report.loss_count) coincide sur le meme segment plutot "
            "qu'un filtrage specifique au trafic HTTP."
        ),
    ),
    # -- duree moyenne de reponse HTTP elevee -- analysis.py::_analyse_http()
    # (Report.http_response_time_ms) + synthesis.py::build_findings()
    # ("-- HTTP --")
    Rule(
        id="http_slow_response",
        domain="HTTP",
        preconditions=(
            "au moins une transaction HTTP dont la reponse porte un "
            "http.time (duree requete -> reponse) mesure nativement par "
            "tshark."
        ),
        required_metrics=("Report.http_response_time_ms", "Pkt.http_response_time_ms"),
        time_window=(
            "agrege sur TOUTE la capture : une seule moyenne globale toutes "
            "transactions confondues, pas par point ni par paire -- meme "
            "portee que dns_slow_resolution."
        ),
        required_context=(
            "dissection HTTP/1.x native de tshark (http.time, calcule par "
            "transaction, present uniquement sur le paquet de reponse) -- "
            "contrairement a DNS/DHCP/SIP, aucune recomposition manuelle "
            "via des timestamps minimaux ici, verifie empiriquement en "
            "Session 17 (capture HTTP/1.1 reelle sur loopback)."
        ),
        severity="a_surveiller",
        confidence=0.8,
        explanation=(
            "Duree moyenne requete -> reponse HTTP superieure a 500ms sur "
            "l'ensemble de la capture -- latence applicative percue par "
            "l'utilisateur, meme registre que dns_slow_resolution (cause "
            "frequente de lenteurs percues a tort comme un probleme "
            "reseau)."
        ),
        verification_leads=(
            "Comparer a la latence reseau brute vers le serveur concerne "
            "pour confirmer que le delai vient bien du traitement "
            "applicatif et non du transport ; croiser avec "
            "server_processing_dominant si un temps de traitement serveur "
            "est egalement mesure."
        ),
        thresholds={"mean_duration_ms_min": 500.0},
    ),
    # ------------------------------------------------------------------
    # Session 53 -- derniere categorie laissee ouverte par la Session 49
    # ("TLS", certificat, DEUX sites de Finding). Meme discipline de
    # tracabilite : chaque champ verifie directement contre le code
    # source (analysis.py::_analyse_tls_certificate,
    # synthesis.py::build_findings, bloc "-- certificat TLS --"). Ne
    # couvre PAS "negociations TLS incompletes" (§6.2) -- signal
    # different, qui ne produit aucun synthesis.Finding a ce jour, voir
    # docstring de module.
    # ------------------------------------------------------------------
    # -- certificat hors de sa fenetre de validite -- analysis.py::
    # _analyse_tls_certificate() (Report.tls_cert_invalid_dates) +
    # synthesis.py::build_findings() ("-- certificat TLS --")
    Rule(
        id="tls_cert_invalid_dates",
        domain="TLS",
        preconditions=(
            "le certificat feuille presente lors d'un handshake TLS a ce "
            "point est compare a l'horodatage du PAQUET ou il est vu (pas a "
            "l'heure actuelle) : soit deja expire (paquet vu apres "
            "tls_cert_not_after), soit pas encore valide (paquet vu avant "
            "tls_cert_not_before)."
        ),
        required_metrics=(
            "Report.tls_cert_invalid_dates",
            "Pkt.tls_cert_not_before",
            "Pkt.tls_cert_not_after",
            "Pkt.tls_cert_serial",
        ),
        time_window=(
            "par point, agrege en compteur sur toute la capture ; "
            "comparaison faite paquet par paquet contre l'horodatage de CE "
            "paquet, jamais contre l'heure d'analyse -- une capture "
            "ancienne rejouee a froid reste correcte."
        ),
        required_context=(
            "detection PAR POINT uniquement (comme ARP/STP), aucune "
            "correlation entre points necessaire ; une seule paire "
            "(notBefore, notAfter) retenue par connexion et par point (la "
            "derniere observee ecrase la precedente en cas de handshakes "
            "TLS multiples sur la meme connexion) ; ne verifie PAS la "
            "chaine de confiance PKI (CA, revocation), hors de portee "
            "d'une capture reseau passive."
        ),
        severity="anomalie",
        confidence=0.8,
        explanation=(
            "Un certificat presente hors de sa fenetre de validite au "
            "moment de la capture (deja expire, ou pas encore valide) -- "
            "signale un defaut de gestion du cycle de vie du certificat "
            "(renouvellement manque) ou une horloge desynchronisee sur "
            "l'equipement qui le presente. Severite fixe, ne varie pas "
            "avec le volume."
        ),
        verification_leads=(
            "Verifier la date d'expiration et la procedure de "
            "renouvellement automatique du certificat sur l'equipement qui "
            "le presente ; un certificat pas encore valide peut aussi "
            "signaler une horloge serveur desynchronisee plutot qu'un "
            "probleme de certificat lui-meme."
        ),
    ),
    # -- certificat substitue entre deux points -- analysis.py::
    # _analyse_tls_certificate() (Report.tls_cert_mismatch) +
    # synthesis.py::build_findings() ("-- certificat TLS --")
    Rule(
        id="tls_cert_mismatch",
        domain="TLS",
        preconditions=(
            "pour une MEME connexion (5-tuple), le numero de serie du "
            "certificat presente differe entre le point amont (a) et le "
            "point aval (b) d'une paire adjacente -- un serveur ne change "
            "normalement pas de certificat au sein d'une meme connexion "
            "TCP."
        ),
        required_metrics=("Report.tls_cert_mismatch", "Pkt.tls_cert_serial"),
        time_window="par connexion (5-tuple), agrege en compteur par paire de points adjacents sur toute la capture.",
        required_context=(
            "paire de points adjacents (a, b) ; correspondance par 5-tuple "
            "EXACT entre les deux points -- meme registre que "
            "vlan_change/tcp_rst_localized ; ne verifie PAS la chaine de "
            "confiance PKI (CA, revocation), hors de portee d'une capture "
            "reseau passive."
        ),
        severity="anomalie",
        confidence=0.8,
        explanation=(
            "Un certificat different est presente pour la meme connexion "
            "entre deux points d'observation -- signature possible d'une "
            "interception/substitution TLS en cours de chemin (proxy "
            "d'inspection, dispositif MITM qui presente SON PROPRE "
            "certificat au lieu de relayer celui du vrai serveur), ou plus "
            "benin, un load-balancer/reverse-proxy en aval qui termine le "
            "TLS avec un certificat different de celui du serveur reel en "
            "amont (architecture legitime mais bonne a savoir)."
        ),
        verification_leads=(
            "Comparer les numeros de serie/empreintes de certificat "
            "releves aux deux points a l'inventaire de certificats connu ; "
            "verifier la presence attendue d'un dispositif d'inspection "
            "TLS ou d'un reverse-proxy sur ce segment avant de conclure a "
            "une interception non autorisee."
        ),
    ),
    # ------------------------------------------------------------------
    # Session 54 -- decision architecturale tranchee (option (a), voir
    # docstring de module) : "negociations TLS incompletes" (§6.2)
    # rejoint ce catalogue via un detecteur ENTIEREMENT nouveau
    # (analysis.py::_analyse_tls_handshake, pcap_parser.protocols.
    # extract_tls_handshake) -- PAS une reutilisation de
    # netcross_core.tls_diagnostics, qui reste independant. Domaine
    # "TLS" partage avec les deux regles certificat ci-dessus (meme
    # `Finding.category`, concepts differents, voir docstring de
    # module) ; PAR POINT toutes les deux, aucune correlation entre
    # points necessaire.
    # ------------------------------------------------------------------
    # -- ClientHello sans reponse -- analysis.py::_analyse_tls_handshake()
    # (Report.tls_handshake_no_reply) + synthesis.py::build_findings()
    # ("-- negociations TLS incompletes --")
    Rule(
        id="tls_handshake_no_reply",
        domain="TLS",
        preconditions=(
            "un ClientHello est vu pour une connexion (5-tuple) a ce "
            "point, mais aucun ServerHello n'est jamais observe ensuite "
            "pour cette meme connexion, a ce meme point, dans le reste "
            "de la capture -- silence total apres l'ouverture de la "
            "negociation."
        ),
        required_metrics=(
            "Report.tls_handshake_no_reply",
            "Pkt.tls_client_hello",
            "Pkt.tls_server_hello",
        ),
        time_window=(
            "par connexion, agrege en compteur par point sur toute la "
            "capture ; correlation faite sur l'ordre d'arrivee des "
            "paquets au sein d'un meme point, jamais entre points."
        ),
        required_context=(
            "correspondance par identifiant exact -- ici la connexion "
            "(deux extremites ip:port, sens indifferent) -- entre "
            "plusieurs paquets d'un MEME point, meme registre que "
            "dhcp_issues/sip_issues ; ne distingue pas une negociation "
            "reellement bloquee d'une capture arretee avant que la "
            "reponse n'arrive (limite structurelle de toute analyse PAR "
            "POINT sur une capture finie, comme dns_timeout/"
            "syn_no_synack)."
        ),
        severity="anomalie",
        confidence=0.8,
        explanation=(
            "Une negociation TLS s'ouvre (ClientHello envoye) mais "
            "n'obtient jamais de reponse a ce point -- filtrage "
            "(pare-feu, IPS), service TLS injoignable ou en panne, ou "
            "simplement une capture trop courte pour voir la reponse "
            "arriver."
        ),
        verification_leads=(
            "Verifier la disponibilite du service TLS vise (port "
            "ouvert, processus actif) ; verifier l'absence de regle de "
            "filtrage bloquant ce trafic entre ce point et le serveur ; "
            "si la capture est courte, prolonger la fenetre de capture "
            "avant de conclure a un blocage reel."
        ),
    ),
    # -- ServerHello sans donnees applicatives -- analysis.py::
    # _analyse_tls_handshake() (Report.tls_handshake_incomplete) +
    # synthesis.py::build_findings() ("-- negociations TLS incompletes --")
    Rule(
        id="tls_handshake_incomplete",
        domain="TLS",
        preconditions=(
            "un ServerHello EST vu pour une connexion a ce point (la "
            "negociation a demarre des deux cotes), mais aucun "
            "enregistrement application_data n'est jamais observe "
            "ensuite pour cette meme connexion, a ce meme point -- la "
            "negociation demarre puis s'interrompt avant son terme."
        ),
        required_metrics=(
            "Report.tls_handshake_incomplete",
            "Pkt.tls_server_hello",
            "Pkt.tls_application_data",
        ),
        time_window=(
            "par connexion, agrege en compteur par point sur toute la "
            "capture ; correlation faite sur l'ordre d'arrivee des "
            "paquets au sein d'un meme point, jamais entre points."
        ),
        required_context=(
            "meme registre que tls_handshake_no_reply ci-dessus "
            "(correspondance par identifiant exact entre plusieurs "
            "paquets d'un meme point) ; limite specifique "
            "supplementaire : TLS 1.3 deguise en application_data les "
            "messages de handshake qui suivent le ServerHello "
            "(compatibilite des intermediaires), ce qui peut "
            "occasionnellement masquer une negociation TLS 1.3 "
            "reellement interrompue juste apres ce deguisement -- limite "
            "deja documentee de la meme maniere dans "
            "netcross_core.tls_diagnostics."
        ),
        severity="anomalie",
        confidence=0.8,
        explanation=(
            "Une negociation TLS progresse (ServerHello recu) mais "
            "n'aboutit jamais a un echange de donnees applicatives a ce "
            "point -- abandon cote client (certificat refuse, "
            "incompatibilite de version/cipher), ou middlebox qui coupe "
            "la connexion en cours de handshake."
        ),
        verification_leads=(
            "Verifier la validite et la chaine de confiance du "
            "certificat presente (voir aussi tls_cert_invalid_dates/"
            "tls_cert_mismatch ci-dessus) ; verifier la compatibilite "
            "des versions/suites cryptographiques negociees entre "
            "client et serveur ; verifier l'absence d'un equipement "
            "intermediaire (proxy, IPS) qui interromprait la connexion "
            "en cours de handshake."
        ),
    ),
)

_BY_ID: dict[str, Rule] = {r.id: r for r in _RULE_CATALOG}


def get_rule(rule_id: str) -> Rule | None:
    """Regle du catalogue pour cet id, `None` si absente -- jamais de
    KeyError, meme discipline defensive que get() ailleurs dans ce projet
    (_flag_label/_flag_severity/_remediation_for cote wireshark_expert.py)."""
    return _BY_ID.get(rule_id)


def list_rules(domain: str | None = None) -> list[Rule]:
    """Toutes les regles du catalogue, dans l'ordre de _RULE_CATALOG
    (celui du texte de la section 6.2). `domain` (optionnel) filtre sur
    une valeur EXACTE de `Finding.category` (netcross_report.synthesis) --
    voir docstring de module : c'est le meme vocabulaire, pas une nouvelle
    taxonomie, donc `list_rules(domain=finding.category)` fonctionne
    directement depuis un Finding deja construit."""
    logger.debug("list_rules: domain={}", summarize(domain, "domain"))
    if domain is None:
        return list(_RULE_CATALOG)
    return [r for r in _RULE_CATALOG if r.domain == domain]
