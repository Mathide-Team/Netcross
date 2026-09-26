<!-- FICHIER GENERE par scripts/generate_class_diagram.py -- NE PAS EDITER A LA MAIN. -->
<!-- Regenere par le hook pre-commit `class-diagram` ; voir .pre-commit-config.yaml. -->

# netcross — diagramme de classes

> ⚠️ **Fichier généré depuis le code** (`src/`) par `scripts/generate_class_diagram.py` : toute
> modification manuelle sera écrasée. Il est mis à jour automatiquement par le hook pre-commit
> `class-diagram` dès qu'un fichier `src/**/*.py` change ; pour le régénérer à la main :
> `python3 scripts/generate_class_diagram.py` (ou `--check` pour vérifier qu'il est à jour).
>
> Il remplace l'ancienne section 3 de `docs/features-backlog.md`, tenue à la main, qui avait dérivé
> (voir `docs/sessions/session-36.md`, issue #140).

160 modules · 240 classes · 541 fonctions publiques de module.

Conventions : `+` public, `-` privé (préfixe `_`) ; `int?` = `int | None` ; `list~str~` = `list[str]` ;
`<<module>>` regroupe les fonctions publiques d'un module ; `A --> B : champ` = `A` a un champ annoté
avec `B` ; `<<…>>` liste le type de classe (dataclass, `__slots__`…) et les bases hors du bloc.
Les fonctions/méthodes privées (préfixe `_`) et les classes imbriquées ne sont pas représentées.

## Dépendances entre packages

Nombre d'instructions `import` d'un package vers un autre (contrat de couches vérifié par
`import-linter` : `netcross_gtk4 → netcross_report → netcross_core → pcap_parser`).

```mermaid
flowchart TD
    CLI["CLI (src/*.py)"]
    netcross_gtk4["netcross_gtk4"]
    netcross_api["netcross_api"]
    netcross_report["netcross_report"]
    netcross_ai["netcross_ai"]
    netcross_core["netcross_core"]
    pcap_parser["pcap_parser"]
    CLI -->|"17 imports"| netcross_report
    CLI -->|"8 imports"| netcross_ai
    CLI -->|"40 imports"| netcross_core
    CLI -->|"5 imports"| pcap_parser
    netcross_gtk4 -->|"13 imports"| netcross_report
    netcross_gtk4 -->|"54 imports"| netcross_core
    netcross_gtk4 -->|"2 imports"| pcap_parser
    netcross_api -->|"6 imports"| netcross_core
    netcross_report -->|"32 imports"| netcross_core
    netcross_ai -->|"10 imports"| netcross_core
    netcross_core -->|"18 imports"| pcap_parser
```

## Relations inter-modules

Associations de classes détectées via les annotations de champs lorsqu'elles franchissent
une frontière de module (source_module != target_module). Chaque flèche indique la classe
source, le ou les champs concernés, et la classe cible (dans un autre module). Complément
du graphe de dépendances ci-dessus (qui ne compte que des `import`).

```mermaid
flowchart LR
    AnalysisResult["netcross_gtk4.analysis_pipeline.AnalysisResult"]
    AnnotationStore["netcross_gtk4.annotations_view.AnnotationStore"]
    BPFFilter["netcross_core.models.BPFFilter"]
    Baseline["netcross_ai.anomaly.Baseline"]
    CaptureInfo["pcap_parser.capinfos_source.CaptureInfo"]
    ClientReport["netcross_core.client_diff.ClientReport"]
    ContentExtraction["netcross_core.extract.contents.ContentExtraction"]
    CveEntry["netcross_core.security.cve_db.CveEntry"]
    CveSeed["netcross_core.security.cve_seed.CveSeed"]
    DemandeSauvegarde["netcross_gtk4.bpf_panel.DemandeSauvegarde"]
    Detector["netcross_core.plugins.api.Detector"]
    DiffFinding["netcross_core.baseline_diff.DiffFinding"]
    EvidenceLink["netcross_core.expert_model.EvidenceLink"]
    ExpertEvent["netcross_core.expert_model.ExpertEvent"]
    Exporter["netcross_core.plugins.api.Exporter"]
    Finding["netcross_report.synthesis.Finding"]
    FlowView["netcross_core.flow_view.FlowView"]
    Flow["netcross_core.expert_model.Flow"]
    HostAsset["netcross_core.discovery.assets.HostAsset"]
    InterfaceRecord["pcap_parser.capfile.InterfaceRecord"]
    LiveDiffState["netcross_core.live_diff.LiveDiffState"]
    LoadedPlugins["netcross_core.plugins.loader.LoadedPlugins"]
    ModelPack["netcross_ai.model_pack.ModelPack"]
    OsGuess["netcross_core.discovery.os_detect.OsGuess"]
    PacketAnnotation["netcross_core.models.PacketAnnotation"]
    Pkt["netcross_core.models.Pkt"]
    Report["netcross_core.models.Report"]
    SegmentScore["netcross_report.triage.SegmentScore"]
    StreamQuality["netcross_core.extract.media.StreamQuality"]
    _Detector["netcross_core.exploit_signatures._Detector"]
    netcross_core_security_expert_correlation__FlowState["netcross_core.security.expert_correlation._FlowState"]
    AnalysisResult -->|report| Report
    AnnotationStore -->|by_label| PacketAnnotation
    CaptureInfo -->|interfaces| InterfaceRecord
    ClientReport -->|report| Report
    ContentExtraction -->|media| StreamQuality
    CveSeed -->|entries| CveEntry
    DemandeSauvegarde -->|filtre| BPFFilter
    DiffFinding -->|evidence| EvidenceLink
    Finding -->|event| ExpertEvent
    Finding -->|evidence| EvidenceLink
    FlowView -->|events| ExpertEvent
    FlowView -->|flow| Flow
    HostAsset -->|os_guess| OsGuess
    LiveDiffState -->|packets_in_window| Pkt
    LoadedPlugins -->|detectors| Detector
    LoadedPlugins -->|exporters| Exporter
    ModelPack -->|baseline| Baseline
    SegmentScore -->|findings| Finding
    _Detector -->|run| netcross_core_security_expert_correlation__FlowState
```

## `pcap_parser`

| Module | Rôle |
|---|---|
| `pcap_parser` | decodage de captures reseau via tshark -T ek (moteur Wireshark en ligne de commande). |
| `pcap_parser.capfile` | couche 1 bis : cadrage binaire minimal des fichiers pcap / pcapng. |
| `pcap_parser.capinfos_source` | lecture du commentaire de SECTION pcapng (Section Header Block, "capture comment") d'un fichier de capture, via `capinfos -k`. |
| `pcap_parser.capture` | couche 6 (orchestration) : point d'entree public du package. |
| `pcap_parser.ek_fields` | couche 2 : acces bas niveau aux champs d'un paquet EK. |
| `pcap_parser.ek_source` | couche 1 : execution de tshark -T ek et lecture du flux NDJSON qui en resulte, fichier pcap ou interface live. |
| `pcap_parser.packet` | couche 5 : assemblage d'un RawPacket normalise a partir des couches EK d'un paquet, une fois l'encapsulation detectee (tunnels.py) et les protocoles applicatifs extraits (protocols.py). |
| `pcap_parser.protocols` | couche 4 : RTP / DHCP / SIP. |
| `pcap_parser.remote` | sources de capture distantes (issue #166). |
| `pcap_parser.tunnels` | couche 3 : detection de la pile d'encapsulation (VLAN/MPLS/GRE/VXLAN/GTP-U/ERSPAN/CAPWAP) et selection de la couche IP/TCP/UDP/ICMP la plus interne a utiliser pour l'analyse. |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== pcap_parser.capfile =====
    class InterfaceRecord {
        <<dataclass, frozen>>
        +int index
        +int linktype
        +int snaplen
        +str? name
        +int? received
        +int? dropped_by_interface
        +int? dropped_by_os
    }
    class CaptureStructure {
        <<dataclass, frozen>>
        +str fmt
        +str version
        +tuple~InterfaceRecord, ...~ interfaces
    }
    class _SegmentSink {
        +is_open() bool
        +write(raw, is_packet) None
        +write_if_open(raw) None
        +close() None
        +abort() None
    }
    class mod_pcap_parser_capfile["pcap_parser.capfile"] {
        <<module>>
        +detect_format(path) str?
        +format_extension(fmt) str
        +has_packets(path) bool
        +read_structure(path) CaptureStructure?
        +split_by_size(path, out_prefix, max_bytes) list~str~
        +first_timestamp(path) float
    }

    %% ===== pcap_parser.capinfos_source =====
    class CaptureInfo {
        <<dataclass, frozen>>
        +str path
        +str? file_type
        +str? version
        +str? encapsulation
        +str? timestamp_precision
        +int? snaplen
        +int? packet_count
        +int? byte_count
        +int? file_size
        +float? duration_seconds
        +float? start_time
        +float? end_time
        +bool? strict_time_order
        +str? hardware
        +str? operating_system
        +str? application
        +tuple~InterfaceRecord, ...~ interfaces
        +dropped_by_interface() int?
        +dropped_by_os() int?
        +has_drops() bool?
    }
    class mod_pcap_parser_capinfos_source["pcap_parser.capinfos_source"] {
        <<module>>
        +read_capture_comment(path) str?
        +read_capture_info(path) CaptureInfo?
    }

    %% ===== pcap_parser.capture =====
    class CaptureRingBuffer {
        +files() tuple~str, ...~
        +current_path() str?
        +rotate(now) str
        +maybe_rotate(now) str?
    }
    class TcpreplayNotFoundError {
        <<RuntimeError>>
    }
    class TcpreplayError {
        <<RuntimeError>>
    }
    class _SourceDone {
        <<dataclass, frozen>>
        +str label
    }
    class _SourceFailed {
        <<dataclass, frozen>>
        +str label
        +Exception error
    }
    class mod_pcap_parser_capture["pcap_parser.capture"] {
        <<module>>
        +parse_capture(path, raise_on_error) list~RawPacket~
        +parse_captures_parallel(captures, max_workers) tuple~list~RawPacket~, list~dict~~
        +iter_live(interface, bpf_filter, stop_event) Iterator~RawPacket~
        +merge_captures(paths, output_path, dedup) None
        +replay_capture(path, interface, speed, loop) None
        +split_capture(path, output_dir, by, value) list~str~
        +iter_live_multi(interfaces, stop_event, bpf_filter) Iterator~tuple~str, RawPacket~~
        +export_filtered(path_in, path_out, bpf_filter, time_start, time_end, endpoints) None
        +adjust_timestamps(path_in, path_out, offset_seconds, normalize, align_to) None
        +convert_capture(path_in, path_out, fmt) None
        +export_csv(path_in, path_out) None
        +export_json(path_in, path_out) None
    }

    %% ===== pcap_parser.ek_fields =====
    class mod_pcap_parser_ek_fields["pcap_parser.ek_fields"] {
        <<module>>
        +layer(layers, key) dict?
        +innermost(layers, key) dict?
        +all_occurrences(layers, key) list~dict~
        +g(d, name, default) Any
        +as_int(value, base) int?
        +hex_or_dec_to_int(value) int?
        +checksum_is_bad(status_value) bool?
        +as_float(value) float?
        +as_bool(value) bool
        +has_expert_flag(layer, name) bool
        +expert_flag_names(layer) tuple~str, ...~
        +expert_flag_details(layer) tuple~tuple~str, str?, str?, str?~, ...~
        +as_bytes_from_hex_dump(value) bytes
    }

    %% ===== pcap_parser.ek_source =====
    class TsharkNotFoundError {
        <<RuntimeError>>
    }
    class TsharkError {
        <<RuntimeError>>
    }
    class EkRecord {
        <<dataclass>>
        +float ts
        +dict layers
    }
    class mod_pcap_parser_ek_source["pcap_parser.ek_source"] {
        <<module>>
        +redact_args(args) list
        +iter_ek_records(path, interface, bpf_filter, display_filter, extra_prefs, extra_args, lua_scripts, stop_event) Iterator~EkRecord~
    }

    %% ===== pcap_parser.packet =====
    class RawPacket {
        <<dataclass, slots>>
        +float ts
        +int? frame_number
        +str proto
        +str src
        +str dst
        +int? sport
        +int? dport
        +int length
        +int? ttl
        +int? dscp
        +int? ecn
        +int? seq
        +int? ack
        +int? window
        +str? flags
        +int? key_id
        +str? payload_hash
        +bytes payload
        +int? ip_id
        +bool is_fragment
        +bool df
        +bool is_retransmission
        +bool is_fast_retransmission
        +bool is_spurious_retransmission
        +int? mss_val
        +int? wscale_shift
        +bool sack_permitted
        +int? icmp_type
        +int? icmp_code
        +int? icmpv6_type
        +int? icmpv6_code
        +int? arp_opcode
        +str? arp_sender_mac
        +bool arp_is_gratuitous
        +int? stp_bpdu_type
        +bool stp_flags_tc
        +str? stp_root_id
        +str? tls_cert_not_before
        +str? tls_cert_not_after
        +tuple~str, ...~? tls_cert_san
        +str? tls_cert_serial
        +str? tls_cert_issuer
        +str? tls_cert_subject
        +str? tls_cert_sig_hash
        +str? tls_cert_key_type
        +int? tls_cert_key_bits
        +tuple~str, ...~? tls_cert_san_ip
        +int? tls_cert_chain_len
        +bool tls_client_hello
        +bool tls_server_hello
        +bool tls_application_data
        +int? vlan_id
        +int? vlan_prio
        +bool is_rtp
        +int? rtp_seq
        +int? rtp_ts
        +int? rtp_ssrc
        +tuple~str, ...~ encap_tags
        +int? dhcp_xid
        +str? dhcp_msg_type
        +str? dhcp_server_id
        +str? dhcp_vendor_class
        +str? sip_call_id
        +str? sip_msg_type
        +str? sip_cseq
        +str? sip_user_agent
        +str? sip_server
        +int? dns_txn_id
        +bool dns_is_response
        +str? dns_qry_name
        +int? dns_rcode
        +bool http_is_request
        +bool http_is_response
        +str? http_method
        +str? http_uri
        +int? http_status_code
        +float? http_response_time_ms
        +tuple~str, ...~ expert_flags
        +tuple~tuple~str, str?, str?, str?~, ...~ expert_details
        +float payload_entropy
        +str? http_content_type
        +int? http_content_length
        +int? tcp_len
        +tuple~str, ...~ dns_answers
        +str? comment
        +str? ip_checksum
        +bool? ip_checksum_bad
        +str? tcp_checksum
        +bool? tcp_checksum_bad
        +str? udp_checksum
        +bool? udp_checksum_bad
    }
    class mod_pcap_parser_packet["pcap_parser.packet"] {
        <<module>>
        +build_packet(ts_seconds, layers) RawPacket?
    }

    %% ===== pcap_parser.protocols =====
    class mod_pcap_parser_protocols["pcap_parser.protocols"] {
        <<module>>
        +extract_rtp(layers, udp_payload) dict?
        +extract_dhcp(layers) dict?
        +extract_sip(layers, payload) dict?
        +extract_dns(layers) dict?
        +extract_http(layers) dict?
        +extract_tls_certificate(layers) dict?
        +extract_tls_handshake(layers) dict?
        +compute_mos(delay_ms, loss_pct)
    }

    %% ===== pcap_parser.remote =====
    class CaptureSourceError {
        <<ValueError>>
    }
    class CaptureSource {
        <<dataclass, frozen>>
        +str kind
        +str interface
        +tuple~str, ...~ extra_args
        +str display
        +bool uses_stdin
        +is_remote() bool
    }
    class mod_pcap_parser_remote["pcap_parser.remote"] {
        <<module>>
        +is_source_url(text) bool
        +split_live_target(text) tuple~str, str?~
        +parse_source(text, env) CaptureSource
        +source_display(text) str
    }

    %% ===== pcap_parser.tunnels =====
    class mod_pcap_parser_tunnels["pcap_parser.tunnels"] {
        <<module>>
        +is_tunnel(layers) bool
        +detect_encapsulation(layers) tuple~str, ...~
        +select_innermost_layers(layers) dict
    }

    %% ===== relations =====
    CaptureStructure --> InterfaceRecord : interfaces
    CaptureInfo --> InterfaceRecord : interfaces
```

## `netcross_core`

| Module | Rôle |
|---|---|
| `netcross_core` | moteur d'analyse croisee de captures Wireshark multi-points, sans dependance a une interface (CLI, GTK4, PDF...). |
| `netcross_core.alarms` | alarmes et surveillance de seuils en analyse live (§6.16, Session 11). |
| `netcross_core.analysis` | coeur analytique : construit un Report a partir des flux correles (pertes, latence, TTL/topologie, QoS, fragmentation, saturation/bufferbloat, TCP avance, VLAN, decalage d'horloge, RTP, decomposition… |
| `netcross_core.baseline_diff` | compare deux Report (avant/apres un correctif, site A / site B, ou toute paire de scenarios comparables) et produit des constats de regression/amelioration. |
| `netcross_core.baseline_profile` | profil de reference dynamique construit a partir de l'historique SQLite (Job 12/issue #9, section 8.5 de FEATURES.md). |
| `netcross_core.batch` | Mode batch : inventaire d'un dossier de captures et regroupement automatique CONSERVATEUR des captures qui semblent etre plusieurs points de vue d'un meme evenement (issue #277). |
| `netcross_core.bpf_filters` | catalogue de filtres BPF predefinis et filtres sauvegardes par l'utilisateur (Job 47 / issue #167). |
| `netcross_core.causality` | moteur de correlation causale (Session 3 de la section 13.3 de FEATURES.md, Job 4/issue #4). |
| `netcross_core.client_diff` | comparaison "client vs client" : meme capture, memes points, seule la source (l'IP du poste) change. |
| `netcross_core.compliance` | evaluateur de conformite, huitieme et neuvieme objets de contrat de la Session 0 (FEATURES.md section 13.3) : `ReferenceProfile`/`ComplianceResult` (netcross_core.expert_model). |
| `netcross_core.config` | chargement de configuration depuis .netcross.toml (issue #170). |
| `netcross_core.content` | Extraction des objets applicatifs HTTP/1.x sans conservation du corps. |
| `netcross_core.correlate` | correlation des paquets entre points de capture (par 5-tuple strict ou par hash de payload en mode NAT-tolerant) et calcul du debit par fenetre temporelle. |
| `netcross_core.expert_model` | objets de contrat partages entre netcross_core et netcross_report ("Session 0" de FEATURES.md section 13.3 : stabiliser les objets communs avant de batir le moteur d'expertise vise par la comparaison… |
| `netcross_core.expert_rules` | bibliotheque de regles d'expertise reseau DECLARATIVE (FEATURES.md section 6.2), dernier chantier de la Session 2 de la section 13.3 ("moteur d'evenements d'expertise") apres la cloture cote… |
| `netcross_core.exploit_signatures` | detection PASSIVE de signatures d'exploits CVE connus (Log4Shell, Shellshock, Heartbleed, EternalBlue, compression TLS/CRIME) dans la charge utile brute des paquets. |
| `netcross_core.flow_timeline` | vue temporelle detaillee d'un flux (Job 13/issue #10, section 6.4 de FEATURES.md). |
| `netcross_core.flow_view` | vue enrichie d'un flux (FlowView), sixieme objet de contrat de la Session 0 (Job 9/issue #6, section 6.4 et 6.14 de FEATURES.md). |
| `netcross_core.forensic` | index de correlation bidirectionnel evenement ↔ flow ↔ paquet (Job 8/issue #5, §6.3 et §6.14 de FEATURES.md). |
| `netcross_core.forensic_search` | moteur de recherche analytique post-capture transversal (Job 17 / issue #16, section 6.13 de FEATURES.md). |
| `netcross_core.i18n` | internationalisation par GNU gettext (issue #299). |
| `netcross_core.live_diff` | Capture en continu + diff en direct (Job 33, issue #33). |
| `netcross_core.live_report` | issue #274 : export / rapport temps reel du mode ``--live``. |
| `netcross_core.logging_config` | configuration centrale du logging (issue #245). |
| `netcross_core.lua_doc` | banque SQLite locale de l'API Lua Wireshark (issue #387, rattachee a #331). |
| `netcross_core.models` | structures de donnees partagees : un paquet normalise (Pkt) et le resultat d'analyse consolide (Report). |
| `netcross_core.naming` | table locale de correspondance adresse/MAC -> nom logique, type, contexte (Job 18 / issue #16-bis, section 6.15 de FEATURES.md). |
| `netcross_core.parsing` | adaptateur entre pcap_parser (decodage via tshark -T ek) et le modele Pkt de netcross_core. |
| `netcross_core.quic_diagnostics` | extraction du SNI des paquets QUIC Initial (RFC 9000/9001), pour voir le trafic HTTP/3 moderne (Chrome, Teams, Meet, WhatsApp...) que le reste de l'outil ne voit aujourd'hui qu'en UDP brut. |
| `netcross_core.redact` | anonymisation des adresses (IP/MAC) d'une liste de paquets deja chargee, en vue d'un partage externe (ticket support vendeur, rapport transmis a un tiers) sans exposer l'adressage reel du reseau du… |
| `netcross_core.report_text` | mise en forme du Report en sortie texte console et en CSV de detail. |
| `netcross_core.stats` | Exploration statistique interactive (Job 27 / issue #22, section 6.8). |
| `netcross_core.tls_diagnostics` | extrait l'etat des handshakes TLS (ClientHello/ServerHello/Alert/donnees applicatives) a chaque point de capture et localise le segment ou un handshake qui reussissait en amont se met a echouer. |
| `netcross_core.voip` | Analyse VoIP orientee appel. |
| `netcross_core.wireshark_expert` | Session 1 de FEATURES.md section 13.3 ("exploitation de l'expertise Wireshark/TShark") : convertit les signaux d'expertise BRUTS deja produits par le moteur de dissection de tshark (champs… |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.alarms =====
    class AlarmSignal {
        <<dataclass, frozen>>
        +str rule_id
        +str segment
        +str severity
        +float? value
    }
    class AlarmConfig {
        <<dataclass>>
        +str rule_id
        +str? segment
        +float window_seconds
        +float min_persistence_seconds
        +float min_sample_ratio
        +float? trigger_threshold
        +float? clear_threshold
    }
    class AlarmEvent {
        <<dataclass>>
        +str rule_id
        +str segment
        +str state
        +float timestamp
        +str message
    }
    class _SegmentState {
        <<dataclass>>
        +list~tuple~float, bool~~ samples
        +float? active_since
        +bool alarmed
    }
    class AlarmEngine {
        +events() list~AlarmEvent~
        +active_alarms() list~AlarmEvent~
        +feed(timestamp, signals) list~AlarmEvent~
    }

    %% ===== netcross_core.analysis =====
    class mod_netcross_core_analysis["netcross_core.analysis"] {
        <<module>>
        +analyse(flows, points_order, all_packets, bucket_seconds, nat_tolerant, rtp_clock_rate, topn, idle_timeout_seconds, exclude_duplicates, duplicate_counts)
    }

    %% ===== netcross_core.baseline_diff =====
    class DiffFinding {
        <<dataclass>>
        +str severity
        +str category
        +str segment
        +str message
        +float? before
        +float? after
        +int? sample_size
        +list~EvidenceLink~ evidence
    }
    class mod_netcross_core_baseline_diff["netcross_core.baseline_diff"] {
        <<module>>
        +diff_reports(baseline, current, loss_min_pp, latency_min_ms) list~DiffFinding~
        +print_diff_report(findings) None
        +write_diff_csv(findings, path) None
    }

    %% ===== netcross_core.baseline_profile =====
    class BaselineProfile {
        <<dataclass>>
        +str metric
        +int count
        +float mean
        +float median
        +dict~str, float~ percentiles
        +float variance
        +float std
        +float min
        +float max
        +list~float~ values
    }
    class mod_netcross_core_baseline_profile["netcross_core.baseline_profile"] {
        <<module>>
        +build_baseline_profile(metric, values) BaselineProfile
        +load_baseline_from_db(db_path, metric, label, limit) BaselineProfile?
        +load_all_baselines(db_path, label, limit) list~BaselineProfile~
    }

    %% ===== netcross_core.batch =====
    class CaptureInventory {
        <<dataclass>>
        +str label
        +str path
        +int packet_count
        +float? start
        +float? end
        +set~str~ ips
        +dict~tuple~str, str~, float~ pairs
        +set~str~ protocols
        +str? error
        +duration() float
        +to_dict() dict
        +from_dict(data)$ CaptureInventory
    }
    class PairEvaluation {
        <<dataclass>>
        +str a
        +str b
        +float overlap_ratio
        +float? overlap_start
        +float? overlap_end
        +list~str~ common_ips
        +list~tuple~str, str~~ common_pairs
        +list~str~ common_protocols
        +float? clock_offset
        +bool offset_applied
        +list~str~ failed
        +compatible() bool
        +score() int
    }
    class CaptureGroup {
        <<dataclass>>
        +list~CaptureInventory~ members
        +list~PairEvaluation~ evaluations
        +labels() list~str~
    }
    class IsolatedCapture {
        <<dataclass>>
        +CaptureInventory capture
        +str reason
    }
    class BatchPlan {
        <<dataclass>>
        +int total
        +list~CaptureGroup~ groups
        +list~IsolatedCapture~ isolated
        +list~CaptureInventory~ failures
        +bool grouping_enabled
        +grouped_count() int
        +check_invariant() None
    }
    class mod_netcross_core_batch["netcross_core.batch"] {
        <<module>>
        +inventory_from_packets(label, path, packets) CaptureInventory
        +evaluate_pair(a, b, min_overlap, min_common_ips, group_window) PairEvaluation
        +justify(ev) str
        +plan_batch(inventories, group, min_overlap, min_common_ips, group_window) BatchPlan
        +format_batch_index(plan, folder, group_reports, capture_reports, synthesis) str
    }

    %% ===== netcross_core.bpf_filters =====
    class mod_netcross_core_bpf_filters["netcross_core.bpf_filters"] {
        <<module>>
        +default_bpf_filters_path() Path
        +save_bpf_filters(filters, path) Path
        +load_bpf_filters(path) list~BPFFilter~
        +available_bpf_filters(path) list~BPFFilter~
        +upsert_bpf_filter(new, path) list~BPFFilter~
    }

    %% ===== netcross_core.causality =====
    class mod_netcross_core_causality["netcross_core.causality"] {
        <<module>>
        +correlate_event_causes(events) list~ExpertEvent~
        +correlate_diagnosis_causes(diagnoses) list~Diagnosis~
    }

    %% ===== netcross_core.client_diff =====
    class ClientSignature {
        <<dataclass>>
        +Counter dhcp_vendor_classes
        +Counter sip_user_agents
    }
    class ClientReport {
        <<dataclass>>
        +str client
        +tuple~str, ...~ ips
        +int packet_count
        +Report report
        +ClientSignature signature
    }
    class ClientComparisonResult {
        <<dataclass>>
        +str reference
        +dict~str, ClientReport~ clients
        +dict~str, list~ diffs
    }
    class mod_netcross_core_client_diff["netcross_core.client_diff"] {
        <<module>>
        +group_packets_by_client(all_packets, client_group)
        +build_client_report(client, ips, packets, points_order, bucket_seconds, nat_tolerant, nat_window_ms, rtp_clock_rate)
        +compare_clients(all_packets, client_group, reference, points_order, bucket_seconds, nat_tolerant, nat_window_ms, rtp_clock_rate, loss_min_pp, latency_min_ms)
        +print_client_comparison(result) None
        +write_client_diff_csv(result, path) None
    }

    %% ===== netcross_core.compliance =====
    class mod_netcross_core_compliance["netcross_core.compliance"] {
        <<module>>
        +evaluate_compliance(report, references) list~ComplianceResult~
    }

    %% ===== netcross_core.config =====
    class AnalysisConfig {
        <<dataclass>>
        +list~str~ points_order
        +float bucket_seconds
        +int rtp_clock_rate
    }
    class OutputConfig {
        <<dataclass>>
        +str format
        +str output_path
        +str json_report
        +str security_report
    }
    class SecurityConfig {
        <<dataclass>>
        +bool enable
    }
    class ParallelConfig {
        <<dataclass>>
        +int workers
    }
    class NotifyConfig {
        <<dataclass>>
        +str webhook
        +str slack_webhook
        +str email_to
        +str smtp_host
        +int smtp_port
        +str smtp_user
        +str smtp_password
        +str smtp_from
        +bool smtp_starttls
        +float silence_hours
        +str state_path
    }
    class NetcrossConfig {
        <<dataclass>>
        +AnalysisConfig analysis
        +OutputConfig output
        +SecurityConfig security
        +ParallelConfig parallel
        +NotifyConfig notify
        +str? source_path
    }
    class mod_netcross_core_config["netcross_core.config"] {
        <<module>>
        +load_config(config_path) NetcrossConfig
    }

    %% ===== netcross_core.content =====
    class HttpObject {
        <<dataclass, frozen>>
        +str point
        +str src
        +int? sport
        +str dst
        +int? dport
        +str? method
        +str? uri
        +int? status_code
        +str? content_type
        +int? content_length
        +float? response_time_ms
        +int? request_frame
        +int? response_frame
        +str? response_payload_hash
        +volume_bytes() int
        +flow() tuple
    }
    class mod_netcross_core_content["netcross_core.content"] {
        <<module>>
        +extract_http_objects(packets, privacy_mode, max_objects) list~HttpObject~
        +objects_to_dicts(objects) list~dict~
    }

    %% ===== netcross_core.correlate =====
    class mod_netcross_core_correlate["netcross_core.correlate"] {
        <<module>>
        +flow_key(pk, nat_tolerant, nat_window_ms)
        +correlate(all_packets, nat_tolerant, nat_window_ms, exclude_duplicates)
        +build_flows(flows) list~Flow~
        +build_conversations(flow_list) list~Conversation~
        +compute_throughput(all_packets, bucket_seconds)
        +compute_topn_series(all_packets, bucket_seconds, dimension, top_n)
    }

    %% ===== netcross_core.expert_model =====
    class PacketEvidence {
        <<dataclass>>
        +str point
        +int frame_number
    }
    class EvidenceLink {
        <<dataclass>>
        +str point
        +str text
        +PacketEvidence? packet
    }
    class Flow {
        <<dataclass>>
        +tuple key
        +list~str~ points
        +dict~str, int~ packet_count
        +dict~str, int~ byte_count
        +dict~str, float~ first_ts
        +dict~str, float~ last_ts
        +tuple~str, str~? endpoints
    }
    class Conversation {
        <<dataclass>>
        +tuple~str, str~ endpoints
        +list~tuple~ flow_keys
        +int packet_count
        +int byte_count
    }
    class ExpertEvent {
        <<dataclass>>
        +str category
        +str severity
        +str segment
        +str message
        +list~EvidenceLink~ evidence
        +str? cause
        +str? impact
        +str source
        +float? confidence
        +float? first_seen
        +float? last_seen
        +str? layer
        +str? protocol
        +list~tuple~ flow_keys
        +list~PacketEvidence~ packet_evidence
        +str? remediation
        +str? rule_id
    }
    class Diagnosis {
        <<dataclass>>
        +str segment
        +list~ExpertEvent~ events
        +str? cause
        +str? impact
    }
    class ReferenceProfile {
        <<dataclass>>
        +str id
        +str metric
        +str operator
        +float threshold
        +str unit
        +str source
        +str provenance
        +str? version
        +str? context
        +float? percentile
        +str confidence
        +float? deviation_margin
    }
    class ComplianceResult {
        <<dataclass>>
        +ReferenceProfile reference
        +float? observed
        +str status
    }

    %% ===== netcross_core.expert_rules =====
    class Rule {
        <<dataclass>>
        +str id
        +str domain
        +str preconditions
        +tuple~str, ...~ required_metrics
        +str time_window
        +str required_context
        +str severity
        +float confidence
        +str explanation
        +str verification_leads
        +dict~str, float~ thresholds
        +str? correlation_rule
    }
    class mod_netcross_core_expert_rules["netcross_core.expert_rules"] {
        <<module>>
        +get_rule(rule_id) Rule?
        +list_rules(domain) list~Rule~
    }

    %% ===== netcross_core.exploit_signatures =====
    class SignatureError {
        <<ValueError>>
    }
    class PacketLike {
        <<Protocol>>
        +float ts
        +int? frame_number
        +str proto
        +str src
        +str dst
        +int? sport
        +int? dport
        +bytes payload
        +str? payload_hash
    }
    class Signature {
        <<dataclass, frozen>>
        +str id
        +str name
        +tuple~str, ...~ cves
        +str severity
        +str description
        +tuple~str, ...~ targets
        +re.Pattern~str~? regex
        +bytes? hex_bytes
        +tuple~str, ...~ normalizers
        +str? detector
        +dict~str, Any~ params
        +tuple~str, ...~ protocols
        +tuple~int, ...~ ports
        +tuple~str, ...~ references
    }
    class Detection {
        <<dataclass, frozen>>
        +str signature_id
        +str name
        +tuple~str, ...~ cves
        +str severity
        +str target
        +float ts
        +int? frame_number
        +str proto
        +str src
        +int? sport
        +str dst
        +int? dport
        +str? payload_hash
        +str evidence
        +str point
    }
    class netcross_core_exploit_signatures__FlowState["netcross_core.exploit_signatures._FlowState"] {
        <<dataclass, slots>>
        +bool tls_ccs_seen
        +bool smb_mid64_tree_connect
        +int http2_rst_count
    }
    class _Detector {
        <<dataclass, frozen>>
        +Callable~(bytes, _FlowState, dict~str, Any~), str?~ run
        +Callable~(dict~str, Any~), None~ validate
    }
    class _HttpRequest {
        <<dataclass, frozen>>
        +str uri
        +tuple~tuple~str, str~, ...~ headers
        +str body
    }
    class _PayloadView {
        +text(target, normalizers) str?
    }
    class ExploitScanner {
        +scan_packet(pkt, point) list~Detection~
        +scan_packets(packets, point) list~Detection~
    }
    class mod_netcross_core_exploit_signatures["netcross_core.exploit_signatures"] {
        <<module>>
        +available_detectors() tuple~str, ...~
        +parse_signatures(data) list~Signature~
        +load_signatures(paths) list~Signature~
        +detect_exploits(packets, signatures, point) list~Detection~
        +detections_to_dicts(detections) list~dict~str, Any~~
    }

    %% ===== netcross_core.flow_timeline =====
    class PacketTiming {
        <<dataclass>>
        +float ts
        +str point
        +float delta_ms
        +int cumulative_bytes
    }
    class ThroughputWindow {
        <<dataclass>>
        +float start_ts
        +float end_ts
        +int bytes
        +float bps
    }
    class FlowTimeline {
        <<dataclass>>
        +list~PacketTiming~ packet_timings
        +list~ThroughputWindow~ throughput_windows
        +dict~str, float~ inter_arrival_stats
        +list~str~ phases
        +float? rtt_estimate_ms
        +to_dict() dict
    }
    class mod_netcross_core_flow_timeline["netcross_core.flow_timeline"] {
        <<module>>
        +build_flow_timeline(packets, window_s) FlowTimeline
        +build_flow_timelines(packets, window_s, min_packets) dict
    }

    %% ===== netcross_core.flow_view =====
    class TcpSummary {
        <<dataclass>>
        +int retransmissions
        +int fast_retransmissions
        +int spurious_retransmissions
        +bool syn_seen
        +bool fin_seen
        +bool rst_seen
        +int? mss
        +int? wscale
        +bool sack_permitted
    }
    class Transaction {
        <<dataclass>>
        +str kind
        +float? request_ts
        +float? response_ts
        +float? response_time_ms
        +str detail
    }
    class FlowView {
        <<dataclass>>
        +Flow flow
        +float duration_s
        +int packet_count
        +int byte_count
        +float throughput_bps
        +dict~str, float~ first_ts_by_point
        +dict~str, float~ inter_point_latency_ms
        +TcpSummary tcp
        +list~Transaction~ transactions
        +list~ExpertEvent~ events
        +list~tuple~float, str, str~~ timeline
    }
    class mod_netcross_core_flow_view["netcross_core.flow_view"] {
        <<module>>
        +build_flow_view(flow, packets_by_point, events) FlowView
    }

    %% ===== netcross_core.forensic =====
    class ForensicIndex {
        +event_to_flows(event) list~Flow~
        +event_to_packets(event) list~PacketEvidence~
        +packet_to_flow(point, frame_number) Flow?
        +flow_to_events(flow) list~ExpertEvent~
        +flow_to_packets(flow) list~Pkt~
    }
    class _OpenGap {
        <<dataclass, slots>>
        +int start
        +int length
        +float prev_ts
        +int? reveal_frame
        +float reveal_ts
        +float epoch_end_ts
    }
    class mod_netcross_core_forensic["netcross_core.forensic"] {
        <<module>>
        +detect_cross_capture_duplicates(packets, threshold_ms) dict~tuple~str, str~, int~
        +annotations_sidecar_path(capture_path) str
        +read_annotations(capture_path) list~PacketAnnotation~
        +write_annotations(capture_path, annotations) None
        +annotations_by_tag(annotations) dict~str, list~PacketAnnotation~~
        +detect_sequence_gaps(packets) list~SequenceGap~
        +validate_checksums(packets) list~ChecksumError~
    }

    %% ===== netcross_core.forensic_search =====
    class ForensicSearchQuery {
        <<dataclass, frozen>>
        +str? text
        +str? point
        +str? protocol
        +str? address
        +int? port
        +float? time_start
        +float? time_end
        +str? field
        +str? field_value
    }
    class ForensicSearchResult {
        <<dataclass, frozen>>
        +str kind
        +str? point
        +int? frame_number
        +float? ts
        +tuple~str, ...~ matched_fields
        +str snippet
    }
    class _SearchDoc {
        <<dataclass>>
        +str kind
        +str? point
        +int? frame_number
        +float? ts
        +str? src
        +str? dst
        +int? sport
        +int? dport
        +str? protocol
        +dict~str, str~ fields
        +str text
    }
    class ForensicSearchIndex {
        +search(query) list~ForensicSearchResult~
    }

    %% ===== netcross_core.i18n =====
    class mod_netcross_core_i18n["netcross_core.i18n"] {
        <<module>>
        +locale_dirs() list~Path~
        +requested_languages(language) list~str~?
        +setup(language) gettext.NullTranslations
        +active_language() str?
        +available_languages(localedir) list~str~
        +ngettext(singular, plural, n) str
        +N_(message) str
    }

    %% ===== netcross_core.live_diff =====
    class LiveDiffConfig {
        <<dataclass, frozen>>
        +float eval_interval_seconds
        +float window_seconds
        +int max_packets_per_window
        +int min_packets_for_diff
    }
    class LiveDiffState {
        <<dataclass>>
        +bool running
        +list~Pkt~ packets_in_window
        +float last_eval_ts
        +int last_diff_count
        +int total_evaluations
    }
    class LiveDiffEngine {
        +start(interface, bpf_filter) None
        +start_multi(interfaces, bpf_filter) None
        +stop(timeout) None
    }
    class mod_netcross_core_live_diff["netcross_core.live_diff"] {
        <<module>>
        +finding_to_alarm_signal(finding, segment) AlarmSignal
    }

    %% ===== netcross_core.live_report =====
    class _Point {
        <<dataclass>>
        +int packets
        +int bytes
        +int retransmissions
        +float? first_ts
        +float? last_ts
        +str status
        +str? error
        +int tick_packets
        +int tick_bytes
        +float? ewma_pps
        +bool silent
    }
    class LiveAggregator {
        <<dataclass>>
        +dict~str, _Point~ points
        +Counter protocols
        +Counter conversations
        +set hosts
        +float started_at
        -list~dict~ _events
        -int _host_overflow
        -threading.Lock _lock
        -int _seq
        -float? _last_tick
        +register(label) None
        +add(pkt) None
        +set_status(label, status, error) None
        +tick(now, final) tuple~dict, dict~
    }
    class LiveReportWriter {
        +publish(snapshot, journal) None
    }
    class LiveReporter {
        +add(pkt) None
        +start() None
        +stop() None
    }

    %% ===== netcross_core.logging_config =====
    class mod_netcross_core_logging_config["netcross_core.logging_config"] {
        <<module>>
        +level_from_env() str
        +is_debug_level(level) bool
        +configure_logging(level, log_file, force) None
        +enable_debug(level, log_file) None
        +current_level() str
        +is_debug_enabled() bool
        +add_debug_argument(parser) None
        +apply_debug_argument(args) None
        +get_logger(name)
    }

    %% ===== netcross_core.lua_doc =====
    class Parametre {
        <<dataclass, frozen, slots>>
        +str nom
        +str type
        +bool optionnel
        +str description
    }
    class Methode {
        <<dataclass, frozen, slots>>
        +str classe
        +str nom
        +str genre
        +str signature
        +str description
        +str depuis_version
        +list~Parametre~ parametres
        +list~str~ retours
        +list~str~ erreurs
        +list~str~ exemples
    }
    class Attribut {
        <<dataclass, frozen, slots>>
        +str classe
        +str nom
        +str nom_complet
        +str mode
        +str description
        +str depuis_version
    }
    class FicheClasse {
        <<dataclass, frozen, slots>>
        +str nom
        +str module
        +str description
        +list~str~ exemples
        +list~Methode~ methodes
        +list~Attribut~ attributs
    }
    class ResultatRecherche {
        <<dataclass, frozen, slots>>
        +str classe
        +str nom
        +str signature
        +str description
        +str genre
        +int ref_id
        +est_attribut() bool
    }
    class mod_netcross_core_lua_doc["netcross_core.lua_doc"] {
        <<module>>
        +connect(db_path) sqlite3.Connection
        +load_json(conn, data) dict~str, int~
        +load_json_file(conn, json_path) dict~str, int~
        +json_candidates() list~Path~
        +find_json() Path?
        +ensure_db(db_path, json_path) sqlite3.Connection
        +get_meta(conn) dict~str, str~
        +list_classes(conn) list~str~
        +search(conn, terme, limit) list~ResultatRecherche~
        +get_class(conn, nom) FicheClasse?
        +get_methode(conn, methode_id) Methode?
        +get_attribut(conn, attribut_id) Attribut?
    }

    %% ===== netcross_core.models =====
    class Banner {
        <<dataclass, frozen, slots>>
        +str protocol
        +str service
        +str? version
        +str raw
        +str role
        +banner() str
    }
    class Pkt {
        <<dataclass, slots>>
        +str point
        +float ts
        +int? frame_number
        +str proto
        +str src
        +str dst
        +int? sport
        +int? dport
        +int length
        +int? ttl
        +int? dscp
        +int? ecn
        +int? seq
        +int? ack
        +int? window
        +str? flags
        +int? key_id
        +str? payload_hash
        +int? ip_id
        +bool is_fragment
        +bool df
        +bool is_retransmission
        +bool is_fast_retransmission
        +bool is_spurious_retransmission
        +int? mss_val
        +int? wscale_shift
        +bool sack_permitted
        +int? icmp_type
        +int? icmp_code
        +int? icmpv6_type
        +int? icmpv6_code
        +int? arp_opcode
        +str? arp_sender_mac
        +bool arp_is_gratuitous
        +int? stp_bpdu_type
        +bool stp_flags_tc
        +str? stp_root_id
        +str? tls_cert_not_before
        +str? tls_cert_not_after
        +tuple~str, ...~? tls_cert_san
        +str? tls_cert_serial
        +str? tls_cert_issuer
        +str? tls_cert_subject
        +str? tls_cert_sig_hash
        +str? tls_cert_key_type
        +int? tls_cert_key_bits
        +tuple~str, ...~? tls_cert_san_ip
        +int? tls_cert_chain_len
        +bool tls_client_hello
        +bool tls_server_hello
        +bool tls_application_data
        +int? vlan_id
        +int? vlan_prio
        +bool is_rtp
        +int? rtp_seq
        +int? rtp_ts
        +int? rtp_ssrc
        +tuple~str, ...~ encap_tags
        +int? dhcp_xid
        +str? dhcp_msg_type
        +str? dhcp_server_id
        +str? dhcp_vendor_class
        +str? sip_call_id
        +str? sip_msg_type
        +str? sip_cseq
        +str? sip_user_agent
        +str? sip_server
        +int? dns_txn_id
        +bool dns_is_response
        +str? dns_qry_name
        +int? dns_rcode
        +bool http_is_request
        +bool http_is_response
        +str? http_method
        +str? http_uri
        +int? http_status_code
        +float? http_response_time_ms
        +tuple~str, ...~ expert_flags
        +tuple~tuple~str, str?, str?, str?~, ...~ expert_details
        +str? http_content_type
        +int? http_content_length
        +bool is_duplicate
        +float payload_entropy
        +int payload_len
        +str? comment
        +tuple~Banner, ...~ service_banners
        +int? tcp_len
        +tuple~str, ...~ dns_answers
        +str? ip_checksum
        +bool? ip_checksum_bad
        +str? tcp_checksum
        +bool? tcp_checksum_bad
        +str? udp_checksum
        +bool? udp_checksum_bad
        +str? tls_ja4
        +str? tls_ja4_readable
        +str? ssh_hassh
        +str? ssh_hassh_role
        +str? ssh_hassh_readable
    }
    class SequenceGap {
        <<dataclass, slots>>
        +str point
        +str src
        +int sport
        +str dst
        +int dport
        +int start_seq
        +int end_seq
        +int missing_bytes
        +float ts
        +int? frame_number
        +str cause
        +str evidence
    }
    class ChecksumError {
        <<dataclass, slots>>
        +str point
        +int? frame_number
        +str protocol
        +str checksum
    }
    class Report {
        <<dataclass>>
        +list~str~ points
        +list~tuple~str, str~~ pairs
        +float bucket_seconds
        +int rtp_clock_rate
        +dict~str, int~ seen_count
        +dict~str, int~ loss_count
        +dict~str, int~ off_path_count
        +dict~tuple~str, str~, list~float~~ latency
        +dict~tuple~str, str~, int~ qos_change
        +dict~str, int~ retrans
        +dict~str, int~ retrans_fast
        +dict~str, int~ retrans_rto
        +dict~str, int~ retrans_spurious
        +dict~tuple~str, str~, int~ mss_clamped
        +dict~tuple~str, str~, list~str~~ mss_clamped_examples
        +dict~tuple~str, str~, list~int?~~ mss_clamped_frames
        +dict~tuple~str, str~, int~ wscale_stripped
        +dict~tuple~str, str~, int~ sack_stripped
        +dict~tuple~str, str~, list~int~~ hop_delta
        +dict~tuple~str, str~, int~ hop_delta_outliers
        +dict~str, int~ ttl_unstable
        +dict~tuple~str, str~, int~ qos_l2_remark
        +dict~tuple~str, str~, int~ qos_l3_remark
        +dict~str, int~ frag_count
        +dict~tuple~str, str~, int~ frag_new
        +dict~str, int~ icmp_frag_needed
        +dict~str, int~ icmpv6_too_big
        +dict~tuple~str, str~, int~ pmtud_blackhole
        +dict~tuple~str, str~, list~str~~ pmtud_blackhole_examples
        +dict~tuple~str, str~, list~int?~~ pmtud_blackhole_frames
        +dict~tuple~str, str~, int~ idle_timeout_dropped
        +dict~tuple~str, str~, list~str~~ idle_timeout_examples
        +dict~tuple~str, str~, list~int?~~ idle_timeout_frames
        +dict~str, int~ arp_ip_conflict
        +dict~str, list~str~~ arp_ip_conflict_examples
        +dict~str, list~int?~~ arp_ip_conflict_frames
        +dict~str, int~ stp_topology_change
        +dict~str, int~ stp_root_change
        +dict~str, list~str~~ stp_root_change_examples
        +dict~str, list~int?~~ stp_root_change_frames
        +dict~str, int~ tls_cert_invalid_dates
        +dict~str, list~str~~ tls_cert_invalid_dates_examples
        +dict~str, list~int?~~ tls_cert_invalid_dates_frames
        +dict~tuple~str, str~, int~ tls_cert_mismatch
        +dict~tuple~str, str~, list~str~~ tls_cert_mismatch_examples
        +dict~tuple~str, str~, list~int?~~ tls_cert_mismatch_frames
        +dict~str, int~ tls_handshake_no_reply
        +dict~str, list~str~~ tls_handshake_no_reply_examples
        +dict~str, list~int?~~ tls_handshake_no_reply_frames
        +dict~str, int~ tls_handshake_incomplete
        +dict~str, list~str~~ tls_handshake_incomplete_examples
        +dict~str, list~int?~~ tls_handshake_incomplete_frames
        +dict~str, dict~int, int~~ throughput
        +dict~str, dict~str, dict~str, dict~int, int~~~~ topn_timeseries
        +dict~tuple~str, str~, list~int~~ loss_event_buckets
        +dict~tuple~str, str~, dict~int, list~float~~~ latency_by_bucket
        +dict~tuple~str, str~, str~ saturation_verdict
        +dict~tuple~str, str~, tuple~float, float~~ bufferbloat_hint
        +dict~str, int~ zero_window
        +dict~str, int~ dup_ack
        +dict~str, int~ out_of_order
        +dict~str, int~ lost_segment
        +dict~str, int~ window_update
        +dict~str, int~ rst_count
        +dict~str, int~ rst_localized
        +dict~str, int~ syn_no_synack
        +dict~str, int~ syn_reply_missing
        +list~SequenceGap~ sequence_gaps
        +dict~str, dict~str, int~~ expert_malformed
        +list~dict~ expert_malformed_flows
        +dict~str, dict~str, int~~ exploit_suspicion
        +list~dict~ exploit_suspicion_flows
        +dict~tuple~str, str~, list~float~~ clock_offset_samples
        +dict~tuple~str, str~, tuple~float, float, int~~ clock_offset_estimate
        +dict~str, set~int~~ vlan_seen
        +dict~tuple~str, str~, int~ vlan_change
        +dict~tuple~str, str~, dict~str, int~~ vlan_tag_flip
        +dict~tuple~str, str~, int~ pcp_change
        +dict~str, set~str~~ encap_seen
        +dict~tuple~str, str~, int~ encap_change
        +dict~tuple~str, str~, list~str~~ encap_change_examples
        +dict~tuple~str, str~, int~ encap_frag_correlated
        +list~dict~ rtp_streams
        +list~dict~ voip_calls
        +dict~str, int~ voip_quality_distribution
        +dict~str, list~float~~ server_think_time
        +dict~str, dict~str, int~~ dhcp_msg_count
        +dict~str, int~ dhcp_nak_count
        +dict~str, set~str~~ dhcp_server_seen
        +dict~tuple~str, str~, list~str~~ dhcp_missing
        +list~float~ dhcp_duration_ms
        +dict~str, dict~str, int~~ sip_msg_count
        +dict~str, set~str~~ sip_agents_seen
        +dict~tuple~str, str~, list~str~~ sip_missing
        +list~float~ sip_setup_duration_ms
        +list~str~ sip_failed_calls
        +dict~str, int~ dns_query_count
        +dict~str, int~ dns_response_count
        +dict~str, int~ dns_nxdomain_count
        +dict~str, int~ dns_servfail_count
        +dict~tuple~str, str~, list~str~~ dns_missing
        +dict~str, list~str~~ dns_timeout
        +dict~str, list~int?~~ dns_timeout_frames
        +list~float~ dns_duration_ms
        +dict~str, int~ http_request_count
        +dict~str, int~ http_response_count
        +dict~str, dict~str, int~~ http_status_count
        +dict~str, int~ http_client_error_count
        +dict~str, int~ http_server_error_count
        +dict~str, list~str~~ http_error_examples
        +dict~str, list~int?~~ http_error_frames
        +dict~tuple~str, str~, list~str~~ http_missing
        +dict~str, list~str~~ http_timeout
        +dict~str, list~int?~~ http_timeout_frames
        +list~float~ http_response_time_ms
        +dict~tuple~str, str~, int~ duplicate_count
        +bool duplicates_excluded
        +bool truncated
        +str truncation_note
        +list~dict~ http_objects
        +list~dict~ extracted_files
        +list~dict~ application_transactions
        +list~dict~ service_fingerprints
        +list~dict~ security_findings
        +list~dict~ exfiltration_alerts
        +dict~str, dict~str, int~~ protocol_mismatches
        +list~dict~ protocol_mismatch_details
        +list~dict~ dga_alerts
        +list~dict~ fast_flux_alerts
        +list~dict~ lateral_movement_events
        +list~dict~ plugin_runs
        +list~dict~ flow_anomalies
        +list~dict~ asset_inventory
        +int asset_baseline_size
        +list~tuple~str, str, dict~~ topology_edges
        +list~tuple~str, str, str~~ topology_ambiguous
        +list~str~ topology_isolated
        +list~str~ topology_branch_points
        +list~str~ topology_merge_points
        +list~str~ topology_order_conflicts
        +bool topology_used_for_order
        +list~str~ capture_comments
        +list~str~ packet_comments
        +list~dict~ capture_infos
        +list~ChecksumError~ checksum_errors
    }
    class PacketAnnotation {
        <<dataclass, slots>>
        +int frame_number
        +str tag
        +str comment
        +str? color
    }
    class BPFFilter {
        <<dataclass, frozen>>
        +str name
        +str expression
        +str description
    }

    %% ===== netcross_core.naming =====
    class NameEntry {
        <<dataclass, frozen>>
        +str name
        +str? address
        +str? mac
        +str type
        +str? site
        +str? role
        +str? comment
        +matches(address, mac) bool
    }
    class NameTable {
        +add(entry) None
        +resolve(address) NameEntry?
        +resolve_mac(mac) NameEntry?
        +display(address) str
        +to_list() list~dict~
        +from_list(items)$ NameTable
        +load(path)$ NameTable
        +save(path) None
    }

    %% ===== netcross_core.parsing =====
    class mod_netcross_core_parsing["netcross_core.parsing"] {
        <<module>>
        +parse_capture(label, path, raise_on_error) list~Pkt~
        +parse_captures_parallel(captures, max_workers) tuple~list~Pkt~, list~dict~~
        +read_capture_comments(captures) list~str~
        +read_capture_infos(captures) list~dict~
        +parse_live(label, interface, bpf_filter, stop_event)
        +parse_live_multi(interfaces, stop_event, bpf_filter)
        +parse_rtp(payload)
        +parse_sip(payload)
        +detect_encapsulation(layers)
    }

    %% ===== netcross_core.quic_diagnostics =====
    class QuicEvent {
        <<dataclass>>
        +str point
        +float ts
        +str src
        +str dst
        +int sport
        +int dport
        +bytes dcid
        +bool decryptable
        +str? sni
        +str? tls_version
    }
    class mod_netcross_core_quic_diagnostics["netcross_core.quic_diagnostics"] {
        <<module>>
        +derive_initial_secrets(dcid) tuple~bytes, bytes~
        +derive_packet_protection_keys(secret) tuple~bytes, bytes, bytes~
        +parse_quic_capture(label, path) list~QuicEvent~
        +diagnose_quic(events, points_order)
        +print_quic_diagnostics(findings) None
    }

    %% ===== netcross_core.redact =====
    class AddressRedactor {
        +redact(packets) None
        +entries()
        +mapping() dict~str, str~
    }
    class mod_netcross_core_redact["netcross_core.redact"] {
        <<module>>
        +redact_packets(packets) AddressRedactor
        +write_redaction_map_csv(redactor, path) None
    }

    %% ===== netcross_core.report_text =====
    class mod_netcross_core_report_text["netcross_core.report_text"] {
        <<module>>
        +print_report(r)
        +print_sequence_gaps(r)
        +print_annotations(annotations)
        +write_detail_csv(path, flows, points, names)
    }

    %% ===== netcross_core.stats =====
    class StatRow {
        <<dataclass, frozen>>
        +str label
        +str group_by
        +int packets
        +int bytes
        +float duration_ms
        +float throughput_bps
        +float? latency_ms
        +int events
        +list~tuple~ flow_keys
        +duration_s() float
    }
    class StatsQuery {
        <<dataclass, frozen>>
        +str group_by
        +str sort_by
        +int? top_n
        +float? time_start
        +float? time_end
        +str? segment
    }
    class mod_netcross_core_stats["netcross_core.stats"] {
        <<module>>
        +compute_stats(flows, report, all_packets, query, events_by_segment) list~StatRow~
        +export_csv(rows) str
        +export_json(rows) list~dict~
    }

    %% ===== netcross_core.tls_diagnostics =====
    class TlsEvent {
        <<dataclass>>
        +str point
        +float ts
        +str src
        +int sport
        +str dst
        +int dport
        +str record_type
        +str? handshake_type
        +str? sni
        +str? tls_version
        +str? cipher
        +str? alert_level
        +str? alert_description
        +int? record_length
        +bool truncated
    }
    class HandshakeStatus {
        <<dataclass>>
        +str point
        +str flow_id
        +bool client_hello_seen
        +str? sni
        +bool server_hello_seen
        +str? tls_version
        +str? cipher
        +str? fatal_alert
        +str? warning_alert
        +bool application_data_seen
        +float? first_ts
        +float? last_ts
        +verdict() str
    }
    class TlsFinding {
        <<dataclass>>
        +str severity
        +str category
        +str segment
        +str message
    }
    class mod_netcross_core_tls_diagnostics["netcross_core.tls_diagnostics"] {
        <<module>>
        +parse_client_hello(body) dict
        +parse_server_hello(body) dict
        +parse_alert(body) dict
        +parse_tls_capture(label, path) list~TlsEvent~
        +build_handshake_status(events) dict~str, dict~str, HandshakeStatus~~
        +diagnose_tls(status_by_point, points_order) list~TlsFinding~
        +print_tls_diagnostics(findings) None
    }

    %% ===== netcross_core.voip =====
    class Call {
        <<dataclass>>
        +str call_id
        +tuple~str, ...~ participants
        +list~dict~ signaling
        +float? setup_duration_ms
        +float? duration_ms
        +list~dict~ rtp_streams
        +list~dict~ events
        +str quality
        +str correlation_method
        +to_dict() dict
    }
    class mod_netcross_core_voip["netcross_core.voip"] {
        <<module>>
        +build_calls(all_packets, rtp_streams) tuple~list~Call~, dict~str, int~~
    }

    %% ===== netcross_core.wireshark_expert =====
    class mod_netcross_core_wireshark_expert["netcross_core.wireshark_expert"] {
        <<module>>
        +build_wireshark_expert_events(all_packets) list~ExpertEvent~
    }

    %% ===== relations =====
    DiffFinding --> EvidenceLink : evidence
    CaptureGroup --> CaptureInventory : members
    CaptureGroup --> PairEvaluation : evaluations
    IsolatedCapture --> CaptureInventory : capture
    BatchPlan --> CaptureGroup : groups
    BatchPlan --> CaptureInventory : failures
    BatchPlan --> IsolatedCapture : isolated
    ClientReport --> ClientSignature : signature
    ClientReport --> Report : report
    ClientComparisonResult --> ClientReport : clients
    NetcrossConfig --> AnalysisConfig : analysis
    NetcrossConfig --> NotifyConfig : notify
    NetcrossConfig --> OutputConfig : output
    NetcrossConfig --> ParallelConfig : parallel
    NetcrossConfig --> SecurityConfig : security
    EvidenceLink --> PacketEvidence : packet
    ExpertEvent --> EvidenceLink : evidence
    ExpertEvent --> PacketEvidence : packet_evidence
    Diagnosis --> ExpertEvent : events
    ComplianceResult --> ReferenceProfile : reference
    _Detector --> netcross_core_exploit_signatures__FlowState : run
    FlowTimeline --> PacketTiming : packet_timings
    FlowTimeline --> ThroughputWindow : throughput_windows
    FlowView --> ExpertEvent : events
    FlowView --> Flow : flow
    FlowView --> TcpSummary : tcp
    FlowView --> Transaction : transactions
    LiveDiffState --> Pkt : packets_in_window
    LiveAggregator --> _Point : points
    Methode --> Parametre : parametres
    FicheClasse --> Attribut : attributs
    FicheClasse --> Methode : methodes
    Pkt --> Banner : service_banners
    Report --> ChecksumError : checksum_errors
    Report --> SequenceGap : sequence_gaps
```

## `netcross_core.application`

| Module | Rôle |
|---|---|
| `netcross_core.application` | modele transactionnel applicatif (Job 23, §6.9/§6.10). |
| `netcross_core.application.banners` | extraction passive des bannieres de versions logicielles et construction de `Report.service_fingerprints` (CVE-1, issue #135, parent #133). |
| `netcross_core.application.classify` | classification automatique des transactions applicatives (Job 23, §6.9). |
| `netcross_core.application.dns` | construction de transactions DNS a partir des paquets (Job 23, §6.9). |
| `netcross_core.application.http` | construction de transactions HTTP a partir des paquets (Job 23, §6.10). |
| `netcross_core.application.models` | structures de donnees du modele transactionnel applicatif (Job 23, §6.9/§6.10). |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.application.banners =====
    class mod_netcross_core_application_banners["netcross_core.application.banners"] {
        <<module>>
        +extract_banners(proto, sport, dport, payload) tuple~Banner, ...~
        +build_service_fingerprints(packets) list~dict~
    }

    %% ===== netcross_core.application.classify =====
    class TransactionThresholds {
        <<dataclass, slots>>
        +float dns_slow_ms
        +float http_slow_ms
        +float server_dominant_ratio
    }
    class mod_netcross_core_application_classify["netcross_core.application.classify"] {
        <<module>>
        +classify_transaction(txn, thresholds) TransactionClassification
    }

    %% ===== netcross_core.application.dns =====
    class mod_netcross_core_application_dns["netcross_core.application.dns"] {
        <<module>>
        +build_dns_transactions(packets) list~ApplicationTransaction~
    }

    %% ===== netcross_core.application.http =====
    class mod_netcross_core_application_http["netcross_core.application.http"] {
        <<module>>
        +build_http_transactions(packets, network_signals) list~ApplicationTransaction~
    }

    %% ===== netcross_core.application.models =====
    class TransactionClassification {
        <<str, Enum>>
        +NORMAL
        +MISSING_RESPONSE
        +NETWORK_SLOW
        +SERVER_SLOW
        +APPLICATION_SLOW
    }
    class ApplicationTransaction {
        <<dataclass, slots>>
        +str protocol
        +str point
        +str client
        +str server
        +float? request_ts
        +float? response_ts
        +float? total_time_ms
        +float? network_time_ms
        +float? server_time_ms
        +str request_summary
        +str response_summary
        +list~str~ network_signals
        +TransactionClassification classification
        +to_dict() dict
    }

    %% ===== relations =====
    ApplicationTransaction --> TransactionClassification : classification
```

## `netcross_core.discovery`

| Module | Rôle |
|---|---|
| `netcross_core.discovery` | decouverte et cartographie passive des actifs reseau (SCENARIO-5, issue #151, parent #141). |
| `netcross_core.discovery.assets` | inventaire passif des actifs reseau (SCENARIO-5, issue #151, parent #141). |
| `netcross_core.discovery.os_detect` | identification passive de systeme d'exploitation par TTL et options TCP (empreinte type p0f), SCENARIO-5 (issue #151, parent #141). |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.discovery.assets =====
    class ExposedService {
        <<dataclass>>
        +int port
        +str transport
        +str? service
        +str? version
    }
    class HostAsset {
        <<dataclass>>
        +str ip
        +str? mac
        +float first_seen
        +float last_seen
        +int packet_count
        +set~str~ points
        +set~int~ vlan_ids
        +dict~tuple~int, str~, ExposedService~ ports
        +OsGuess? os_guess
        +sorted_ports() list~ExposedService~
    }
    class AssetInventory {
        <<dataclass>>
        +dict~str, HostAsset~ hosts
        +tuple~str, ...~ new_hosts
        +int baseline_size
        +sorted_hosts() list~HostAsset~
        +to_records() list~dict~
    }
    class mod_netcross_core_discovery_assets["netcross_core.discovery.assets"] {
        <<module>>
        +load_baseline_hosts(path) set~str~
        +build_asset_inventory(all_packets, baseline_hosts) AssetInventory
    }

    %% ===== netcross_core.discovery.os_detect =====
    class OsGuess {
        <<dataclass, frozen, slots>>
        +str family
        +int guessed_initial_ttl
        +int observed_ttl
        +int hop_estimate
        +str confidence
        +str evidence
    }
    class mod_netcross_core_discovery_os_detect["netcross_core.discovery.os_detect"] {
        <<module>>
        +guess_initial_ttl(observed_ttl) int
        +guess_os_from_ttl(observed_ttl) OsGuess
        +refine_with_tcp_options(guess, wscale_shift, sack_permitted, mss_val) OsGuess
    }

    %% ===== relations =====
    HostAsset --> ExposedService : ports
    HostAsset --> OsGuess : os_guess
    AssetInventory --> HostAsset : hosts
```

## `netcross_core.extract`

| Module | Rôle |
|---|---|
| `netcross_core.extract` | extraction et reconstruction de fichiers (issue #150). |
| `netcross_core.extract.carver` | issue #150 (SCENARIO-4, parent #141) : extraction et reconstruction de fichiers depuis les traces réseau. |
| `netcross_core.extract.contents` | issue #278 : extraction des contenus (audio, video, documents) a titre d'analyse qualitative, avec rappel de l'usage raisonne. |
| `netcross_core.extract.media` | issue #278 : flux RTP audio/video. |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.extract.carver =====
    class ExtractedFile {
        <<dataclass>>
        +str point
        +str proto_source
        +str src
        +str dst
        +float ts
        +str? uri
        +str? content_type
        +int? size
        +str? hash_md5
        +str? hash_sha256
        +str type_detected
        +int? frame_number
    }
    class ExtractionResult {
        <<dataclass>>
        +list~ExtractedFile~ files
        +has_files() bool
        +files_by_type() dict~str, list~ExtractedFile~~
    }
    class mod_netcross_core_extract_carver["netcross_core.extract.carver"] {
        <<module>>
        +detect_file_type(data) str?
        +detect_extracted_files(packets, extract_dir) ExtractionResult
    }

    %% ===== netcross_core.extract.contents =====
    class ExtractedDocument {
        <<dataclass>>
        +str point
        +str protocol
        +str path
        +int size
        +str sha256
        +str? detected_type
        +to_dict() dict
    }
    class ContentExtraction {
        <<dataclass>>
        +str? out_dir
        +tuple~str, ...~ kinds
        +list~StreamQuality~ media
        +list~ExtractedDocument~ documents
        +list~str~ errors
        +to_dict() dict
    }
    class mod_netcross_core_extract_contents["netcross_core.extract.contents"] {
        <<module>>
        +parse_kinds(spec) tuple~str, ...~
        +prepare_out_dir(path) Path
        +inventory_documents(point, protocol, directory) list~ExtractedDocument~
        +export_documents(captures, out_dir, protocols, tshark_bin, timeout) tuple~list~ExtractedDocument~, list~str~~
        +datagrams_from_raw(label, raw_packets) Iterable~tuple~
        +analyse_media(datagrams) tuple~list~RtpStream~, list~StreamQuality~~
        +run_extraction(captures, out_dir, kinds, read_capture, tshark_bin) ContentExtraction
        +write_manifest(result, out) None
        +format_extraction(result) list~str~
    }

    %% ===== netcross_core.extract.media =====
    class _RtpPacket {
        <<dataclass>>
        +float arrival
        +int seq
        +int ts
        +int pt
        +bool marker
        +bytes payload
    }
    class RtpStream {
        <<dataclass>>
        +str point
        +str src
        +int sport
        +str dst
        +int dport
        +int ssrc
        +int pt
        +str? codec
        +int? clock_rate
        +str kind
        +bool encrypted
        +list~_RtpPacket~ packets
        +label() str
        +file_stem() str
    }
    class StreamQuality {
        <<dataclass>>
        +str label
        +str kind
        +str? codec
        +int received
        +int expected
        +int lost
        +float loss_pct
        +int duplicates
        +int reordered
        +int max_burst
        +float? jitter_ms
        +float duration_s
        +float? mos
        +float? r_factor
        +int? frames
        +int? damaged_frames
        +int? degradation
        +str verdict
        +str? exported
        +str? note
        +to_dict() dict
    }
    class mod_netcross_core_extract_media["netcross_core.extract.media"] {
        <<module>>
        +parse_rtp_header(data) tuple~int, int, int, int, bool, bytes~?
        +parse_sdp(payload) _SdpMap
        +collect_streams(datagrams) list~RtpStream~
        +verdict(degradation) str
        +analyse_stream(st) StreamQuality
        +decode_g711(codec, payload) bytes
        +write_wav(st, path) None
        +depacketize_h264(ordered) bytes
        +export_stream(st, out_dir) Path
    }

    %% ===== relations =====
    ExtractionResult --> ExtractedFile : files
    ContentExtraction --> ExtractedDocument : documents
    ContentExtraction --> StreamQuality : media
    RtpStream --> _RtpPacket : packets
```

## `netcross_core.fingerprint`

| Module | Rôle |
|---|---|
| `netcross_core.fingerprint` | empreintes JA4 (TLS) et HASSH (SSH), issue #143 (FLOW-2, parent #141). |
| `netcross_core.fingerprint.known` | base de correspondances empreinte -> nom d'outil (issue #143, critere d'acceptation "base de fingerprints connus chargeable"). |
| `netcross_core.fingerprint.report` | consolidation des empreintes JA4/ HASSH vues par paquet en entrees pretes pour `Report.service_fingerprints` (issue #143, integration demandee avec CVE-1 #135). |
| `netcross_core.fingerprint.ssh_hassh` | empreinte HASSH d'une negociation SSH (issue #143, FLOW-2). |
| `netcross_core.fingerprint.tls_ja4` | empreinte JA4 d'un ClientHello TLS (issue #143, FLOW-2). |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.fingerprint.known =====
    class mod_netcross_core_fingerprint_known["netcross_core.fingerprint.known"] {
        <<module>>
        +load_known_fingerprints(path) dict~str, dict~
        +identify_tool(fingerprint_type, fingerprint, known) str?
    }

    %% ===== netcross_core.fingerprint.report =====
    class mod_netcross_core_fingerprint_report["netcross_core.fingerprint.report"] {
        <<module>>
        +build_fingerprint_records(packets, known) list~dict~
        +compute_pkt_fingerprints(proto, sport, dport, payload) dict
    }

    %% ===== netcross_core.fingerprint.ssh_hassh =====
    class mod_netcross_core_fingerprint_ssh_hassh["netcross_core.fingerprint.ssh_hassh"] {
        <<module>>
        +parse_kexinit(payload) dict?
        +compute_hassh(kexinit, role) str
        +readable_kexinit(kexinit, role) str
        +identify(payload, sport, dport) tuple~str, str, str~?
    }

    %% ===== netcross_core.fingerprint.tls_ja4 =====
    class mod_netcross_core_fingerprint_tls_ja4["netcross_core.fingerprint.tls_ja4"] {
        <<module>>
        +parse_client_hello(payload) dict?
        +compute_ja4(client_hello, transport) str
        +readable_client_hello(client_hello) str
        +identify(payload) tuple~str, str~?
    }
```

## `netcross_core.netflow`

| Module | Rôle |
|---|---|
| `netcross_core.netflow` | ingestion NetFlow/sFlow comme source de donnees alternative aux captures pcap (Job 32, issue #32). |
| `netcross_core.netflow.adapter` | conversion FlowRecord -> Pkt. |
| `netcross_core.netflow.models` | structure de donnees partagee pour un flux agrege NetFlow/sFlow (FlowRecord), distincte de Pkt. |
| `netcross_core.netflow.netflow_v5` | parseur NetFlow v5 (RFC 1568 / format Cisco historique, le plus repandu et le plus simple des protocoles vises par cet ADR -- voir docs/adr/netflow-sflow-architecture.md, Phase 1 du plan… |
| `netcross_core.netflow.summary` | Resume d'un export NetFlow (issue #362) : volumes, protocoles, principaux emetteurs, conversations et ports de destination. |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.netflow.adapter =====
    class mod_netcross_core_netflow_adapter["netcross_core.netflow.adapter"] {
        <<module>>
        +flow_record_to_pkt(flow, point) Pkt
        +flow_records_to_pkts(flows, point) list~Pkt~
    }

    %% ===== netcross_core.netflow.models =====
    class FlowRecord {
        <<dataclass, slots>>
        +str exporter
        +int version
        +str src_addr
        +str dst_addr
        +int? src_port
        +int? dst_port
        +int protocol
        +int packets
        +int octets
        +float start_ts
        +float end_ts
        +int? tcp_flags
        +int? tos
        +int? src_as
        +int? dst_as
        +int? src_mask
        +int? dst_mask
        +int? input_snmp
        +int? output_snmp
        +str? next_hop
        +int? sampling_interval
        +int? engine_type
        +int? engine_id
        +int? flow_sequence
    }

    %% ===== netcross_core.netflow.netflow_v5 =====
    class NetflowV5Error {
        <<ValueError>>
    }
    class mod_netcross_core_netflow_netflow_v5["netcross_core.netflow.netflow_v5"] {
        <<module>>
        +parse_netflow_v5_packet(data, exporter) list~FlowRecord~
        +iter_netflow_v5_file(path, exporter) Iterator~FlowRecord~
    }

    %% ===== netcross_core.netflow.summary =====
    class mod_netcross_core_netflow_summary["netcross_core.netflow.summary"] {
        <<module>>
        +protocol_name(number) str
        +summarize_flow_records(records, top) dict
        +format_flow_summary(summary) list~str~
    }
```

## `netcross_core.notify`

| Module | Rôle |
|---|---|
| `netcross_core.notify` | notifications sortantes sur seuil de gravite (webhook, Slack, courriel), issue #280. |
| `netcross_core.notify.dispatch` | repartition, garde-fous et tracabilite des notifications (issue #280). |
| `netcross_core.notify.summary` | resume d'analyse a notifier (issue #280). |
| `netcross_core.notify.transports` | canaux de notification (issue #280). |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.notify.dispatch =====
    class DeliveryResult {
        <<dataclass, frozen, slots>>
        +str channel
        +str status
        +str? reason
        +line() str
        +to_dict() dict~str, Any~
    }
    class mod_netcross_core_notify_dispatch["netcross_core.notify.dispatch"] {
        <<module>>
        +is_silenced(fingerprint, state_path, silence_seconds, now) float?
        +send_notifications(summary, notifiers, state_path, silence_seconds, now) list~DeliveryResult~
        +notifiers_from_config(cfg, webhook, slack, email_to, env) tuple~list~Notifier~, list~DeliveryResult~~
        +run_notifications(summary_factory, threshold, cfg, webhook, slack, email_to, state_path, silence_hours, env) list~DeliveryResult~
    }

    %% ===== netcross_core.notify.summary =====
    class NotificationSummary {
        <<dataclass, slots>>
        +int score
        +str? level
        +str threshold
        +dict~str, int~ by_severity
        +int total
        +list~dict~str, str~~ top
        +str? report_path
        +str fingerprint
        +str detail
        +bool anonymized
        +str title
        +to_dict() dict~str, Any~
        +to_text() str
    }
    class mod_netcross_core_notify_summary["netcross_core.notify.summary"] {
        <<module>>
        +severity_rank(severity) int
        +meets_threshold(severity, threshold) bool
        +finding_key(finding) str
        +findings_fingerprint(findings) str
        +build_summary(findings, score, level, threshold, report_path, detail) NotificationSummary
    }

    %% ===== netcross_core.notify.transports =====
    class NotifyError {
        <<Exception>>
    }
    class Notifier {
        <<Protocol>>
        +str name
        +send(summary) bool
    }
    class WebhookNotifier {
        <<dataclass, slots>>
        +str url
        +float timeout
        +str name
        +send(summary) bool
    }
    class SlackNotifier {
        <<dataclass, slots>>
        +str url
        +float timeout
        +str name
        +bool degraded
        +send(summary) bool
    }
    class EmailNotifier {
        <<dataclass, slots>>
        +str host
        +tuple~str, ...~ recipients
        +str sender
        +int port
        +str? username
        +str? password
        +bool starttls
        +float timeout
        +str name
        +build_message(summary) EmailMessage
        +send(summary) bool
    }
    class mod_netcross_core_notify_transports["netcross_core.notify.transports"] {
        <<module>>
        +validate_http_url(url) str
        +slack_blocks(summary) list~dict~str, Any~~
    }
```

## `netcross_core.plugins`

| Module | Rôle |
|---|---|
| `netcross_core.plugins` | detecteurs et sorties tierces (issue #284). |
| `netcross_core.plugins.api` | contrat des plugins (issue #284). |
| `netcross_core.plugins.loader` | decouverte et chargement EXPLICITE des plugins (issue #284). |
| `netcross_core.plugins.runner` | execution isolee des plugins (issue #284). |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.plugins.api =====
    class PluginAccessError {
        <<AttributeError>>
    }
    class InvalidFindingError {
        <<ValueError>>
    }
    class ReadOnlyView {
        <<__slots__>>
    }
    class _Packets {
        <<__slots__>>
    }
    class DetectorContext {
        <<dataclass, frozen, slots>>
        +Any packets
        +ReadOnlyView report
        +tuple~Mapping~str, Any~, ...~ findings
        +build(packets, report)$ DetectorContext
    }
    class Detector {
        <<Protocol>>
        +str name
        +analyse(contexte) list~dict~
    }
    class Exporter {
        <<Protocol>>
        +str name
        +export(report, chemin) None
    }
    class mod_netcross_core_plugins_api["netcross_core.plugins.api"] {
        <<module>>
        +freeze(value) Any
        +validate_finding(raw) dict~str, Any~
    }

    %% ===== netcross_core.plugins.loader =====
    class PluginLoadError {
        <<Exception>>
    }
    class PluginInfo {
        <<dataclass, frozen, slots>>
        +str name
        +str kind
        +str origin
        +str target
    }
    class LoadedPlugins {
        <<dataclass, slots>>
        +list~Detector~ detectors
        +dict~str, Exporter~ exporters
        +list~dict~str, str~~ errors
    }
    class mod_netcross_core_plugins_loader["netcross_core.plugins.loader"] {
        <<module>>
        +forbidden_imports(source) list~str~
        +discover_installed() list~PluginInfo~
        +load_path_module(path) dict~str, list~Any~~
        +load_plugins(authorized, plugin_paths) LoadedPlugins
        +list_plugins(authorized, plugin_paths) list~dict~str, Any~~
    }

    %% ===== netcross_core.plugins.runner =====
    class mod_netcross_core_plugins_runner["netcross_core.plugins.runner"] {
        <<module>>
        +run_line(run) str
        +load_error_runs(errors) list~dict~str, Any~~
        +run_detectors(detectors, packets, report) list~dict~str, Any~~
        +run_exporters(exporters, targets, report) list~dict~str, Any~~
    }

    %% ===== relations =====
    DetectorContext --> ReadOnlyView : report
    LoadedPlugins --> Detector : detectors
    LoadedPlugins --> Exporter : exporters
```

## `netcross_core.security`

| Module | Rôle |
|---|---|
| `netcross_core.security` | detection passive de vulnerabilites (CVE) sur traces reseau (issue #133, sous-tache CVE-4 / issue #138). |
| `netcross_core.security.address_scope` | Portee d'une adresse (interne / externe) pour les detecteurs de securite. |
| `netcross_core.security.beaconing` | issue #147 (SCENARIO-1, parent #141) : detection de beaconing C2 (communications periodiques d'un hote interne vers une destination externe : check-in regulier, petites requetes). |
| `netcross_core.security.cpe_match` | conversion d'une banniere de service ("Apache/2.4.41") en identifiant CPE 2.3 et comparaison de versions avec les ranges NVD (versionStart/EndIncluding/Excluding). |
| `netcross_core.security.cve_db` | base SQLite locale des CVE, peuplee par scripts/import_nvd.py depuis le flux NVD (voir ce script pour le format JSON attendu, API NVD 2.0). |
| `netcross_core.security.cve_seed` | Base CVE minimale embarquee (issue #353). |
| `netcross_core.security.dga` | issue #152 (SCENARIO-6, parent #141) : detection de domaines generes algorithmiquement (DGA). |
| `netcross_core.security.dns_tunnel` | issue #144 (FLOW-3, parent #141) : detection de tunneling DNS (exfiltration, C2, VPN over DNS). |
| `netcross_core.security.exfiltration` | issue #148 (SCENARIO-2, parent #141) : detection d'exfiltration de donnees (transferts sortants anormaux). |
| `netcross_core.security.expert_correlation` | issue #137 (CVE-3) : exploitation des alertes Expert Info de tshark pour DETECTER des tentatives d'exploitation (fuzzing, depassement de tampon, deni de service) a partir de paquets malformes et de… |
| `netcross_core.security.fast_flux` | issue #152 (SCENARIO-6, parent #141) : detection d'infrastructures a flux rapide (fast flux) utilisees par les botnets et C2. |
| `netcross_core.security.findings` | alimentation de `Report.service_fingerprints` et `Report.security_findings` a partir des modules de detection CVE-1 a CVE-4 (issue #139, CVE-5, parent #133). |
| `netcross_core.security.flow_stats` | issue #145 (FLOW-4, parent #141) : analyse statistique des flux pour detecter les comportements anormaux. |
| `netcross_core.security.lateral_movement` | issue #149 (SCENARIO-3, parent #141) : detection de mouvements latéraux internes (scans réseau, propagation, brute force, protocoles inhabituels, nouvelles connexions). |
| `netcross_core.security.protocol_mismatch` | issue #142 (FLOW-1, parent #141) : detection des flux cachés où un protocole utilise un port non standard (SSH sur 443, DNS sur 443, HTTP sur 22, etc.). |
| `netcross_core.security.tls_audit` | issue #153 (SCENARIO-7, parent #141) : audit des certificats TLS presentes par les serveurs (expires, auto-signes, algorithmes faibles, validite excessive, noms suspects, chaine incomplete). |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.security =====
    class CveMatch {
        <<dataclass, frozen, slots>>
        +str cve_id
        +float? cvss_score
        +str? cvss_severity
        +str description
        +str matched_cpe
        +str banner
    }
    class mod_netcross_core_security["netcross_core.security"] {
        <<module>>
        +correlate_banner(conn, banner) list~CveMatch~
        +correlate_versions(conn, banners) dict~str, list~CveMatch~~
    }

    %% ===== netcross_core.security.address_scope =====
    class mod_netcross_core_security_address_scope["netcross_core.security.address_scope"] {
        <<module>>
        +is_test_net(address) bool
        +is_external(address, treat_test_net_as_external) bool
    }

    %% ===== netcross_core.security.beaconing =====
    class BeaconingThresholds {
        <<dataclass, frozen>>
        +int min_checkins
        +float max_interval_cv
        +float min_interval_seconds
        +float burst_gap_seconds
        +int min_payload_bytes
        +int small_payload_bytes
        +float max_size_cv
        +float asymmetry_ratio
        +tuple~int, int~ office_hours_utc
        +float off_hours_ratio
        +bool external_only
        +bool treat_test_net_as_external
        +frozenset~int~ ignored_ports
    }
    class BeaconingResult {
        <<dataclass>>
        +list~dict~ suspicions
    }
    class mod_netcross_core_security_beaconing["netcross_core.security.beaconing"] {
        <<module>>
        +detect_beaconing(packets, thresholds) BeaconingResult
    }

    %% ===== netcross_core.security.cpe_match =====
    class ParsedBanner {
        <<dataclass, frozen, slots>>
        +str raw
        +str product_key
        +str vendor
        +str product
        +str version
        +cpe23() str
    }
    class mod_netcross_core_security_cpe_match["netcross_core.security.cpe_match"] {
        <<module>>
        +vendor_candidates(vendor, product) tuple~str, ...~
        +build_cpe23(vendor, product, version) str
        +parse_banner(banner) ParsedBanner?
        +parse_all_banners(banner) list~ParsedBanner~
        +compare_versions(a, b) int
        +version_in_range(version, exact, start_including, start_excluding, end_including, end_excluding) bool
    }

    %% ===== netcross_core.security.cve_db =====
    class AffectedProduct {
        <<dataclass, frozen, slots>>
        +str vendor
        +str product
        +str? version
        +str? version_start_including
        +str? version_start_excluding
        +str? version_end_including
        +str? version_end_excluding
        +matches(vendor, product, version) bool
    }
    class CveEntry {
        <<dataclass, frozen, slots>>
        +str cve_id
        +str description
        +float? cvss_score
        +str? cvss_severity
        +str? published
        +list~AffectedProduct~ affected
        +matching_cpe(version) str?
    }
    class mod_netcross_core_security_cve_db["netcross_core.security.cve_db"] {
        <<module>>
        +connect_cve_db(db_path) sqlite3.Connection
        +init_db(db_path) sqlite3.Connection
        +close_db(conn) None
        +upsert_cve(conn, entry) None
        +get_cve(conn, cve_id) CveEntry?
        +query_by_product(conn, vendor, product) list~CveEntry~
        +count_cves(conn) int
    }

    %% ===== netcross_core.security.cve_seed =====
    class CveSeed {
        <<dataclass, frozen, slots>>
        +tuple~CveEntry, ...~ entries
        +str source
        +str generated
    }
    class mod_netcross_core_security_cve_seed["netcross_core.security.cve_seed"] {
        <<module>>
        +load_seed(path) CveSeed
        +open_seed_db(path) tuple~sqlite3.Connection, CveSeed~
    }

    %% ===== netcross_core.security.dga =====
    class DgaThresholds {
        <<dataclass>>
        +float score_threshold
        +int min_subdomain_len
        +float entropy_min_bits
        +float consonant_ratio_min
        +float rare_bigram_ratio_min
        +int suspicious_length
        +float nxdomain_ratio_min
        +int max_unique_queries_per_domain
    }
    class DgaAlert {
        <<dataclass>>
        +str domain
        +float score
        +str reason
        +tuple~str, ...~ points
        +float entropy
        +float consonant_ratio
        +float rare_bigram_ratio
        +int length
        +float nxdomain_ratio
        +point() str?
    }
    class DgaResult {
        <<dataclass>>
        +list~DgaAlert~ alerts
        +list~dict~ domain_scores
        +suspicious() bool
    }
    class mod_netcross_core_security_dga["netcross_core.security.dga"] {
        <<module>>
        +detect_dga(packets, thresholds) DgaResult
    }

    %% ===== netcross_core.security.dns_tunnel =====
    class DnsTunnelThresholds {
        <<dataclass, frozen>>
        +int max_label_len
        +int max_name_len
        +int long_name_min_queries
        +float entropy_min_bits
        +int entropy_min_unique
        +int entropy_min_subdomain_len
        +int large_response_bytes
        +int large_response_min_count
        +float dominance_ratio
        +int dominance_min_queries
        +int regular_min_queries
        +float regular_max_cv
        +float volume_ratio
        +int volume_min_packets
    }
    class DnsTunnelResult {
        <<dataclass>>
        +list~dict~ suspicions
        +list~dict~ domain_entropy
    }
    class _DomainState {
        <<dataclass>>
        +list~tuple~float, int?, str~~ queries
        +list~int?~ large_responses
    }
    class mod_netcross_core_security_dns_tunnel["netcross_core.security.dns_tunnel"] {
        <<module>>
        +shannon_entropy(text) float
        +split_domain(name) tuple~str, str~
        +detect_dns_tunneling(packets, thresholds) DnsTunnelResult
    }

    %% ===== netcross_core.security.exfiltration =====
    class ExfiltrationThresholds {
        <<dataclass, frozen>>
        +int min_volume_bytes
        +float min_asymmetric_ratio
        +int business_hours_start
        +int business_hours_end
        +int min_packets_for_volume
        +int min_bytes_for_protocol
        +int? min_upload_for_ratio
        +float off_hours_min_fraction
        +bool external_only
        +bool treat_test_net_as_external
        +ratio_floor() int
    }
    class ExfiltrationAlert {
        <<dataclass>>
        +str src
        +str dst
        +str point
        +list~str~ signals
        +int volume_bytes
        +int upload_bytes
        +int download_bytes
        +float ratio
        +set~str~ protocols
        +list~int?~ frames
        +float? first_ts
        +float? last_ts
        +float off_hours_fraction
        +is_strong() bool
        +score() int
        +to_dict() dict
    }
    class ExfiltrationResult {
        <<dataclass>>
        +list~dict~ alerts
        +list~dict~ flow_stats
    }
    class mod_netcross_core_security_exfiltration["netcross_core.security.exfiltration"] {
        <<module>>
        +compute_score(signals) int
        +severity_for(score) str
        +detect_exfiltration(packets, thresholds, known_destinations) ExfiltrationResult
        +dns_tunnel_sources(packets, dns_suspicions) set~tuple~str, str~~
        +correlate_exfiltration(alerts, beacon_suspicions, dns_sources) list~dict~
    }

    %% ===== netcross_core.security.expert_correlation =====
    class CorrelationThresholds {
        <<dataclass, frozen>>
        +int fuzzing_min_malformed
        +float overflow_window_s
        +int dos_min_events
        +float dos_window_s
    }
    class AppAnomaly {
        <<dataclass, frozen>>
        +str protocol
        +bool malformed
    }
    class CorrelationResult {
        <<dataclass>>
        +dict~str, dict~str, int~~ malformed_by_point
        +list~dict~ malformed_flows
        +list~dict~ suspicions
    }
    class netcross_core_security_expert_correlation__FlowState["netcross_core.security.expert_correlation._FlowState"] {
        <<dataclass>>
        +list~tuple~float, int?, str~~ malformed
        +list~float~ tcp_anomalies
    }
    class mod_netcross_core_security_expert_correlation["netcross_core.security.expert_correlation"] {
        <<module>>
        +app_anomaly(pk) AppAnomaly?
        +has_tcp_sequence_anomaly(pk) bool
        +flow_id(pk) str
        +correlate_expert_alerts(packets, thresholds) CorrelationResult
        +apply_expert_correlation(r, all_packets, thresholds) None
    }

    %% ===== netcross_core.security.fast_flux =====
    class FastFluxThresholds {
        <<dataclass>>
        +int min_ips
        +float window_seconds
        +int min_responses
        +float nxdomain_ratio_min
        +int nxdomain_min_responses
    }
    class FastFluxAlert {
        <<dataclass>>
        +str domain
        +str alert_type
        +float score
        +str reason
        +tuple~str, ...~ points
        +list~str~ ips
        +float nxdomain_ratio
        +point() str?
    }
    class FastFluxResult {
        <<dataclass>>
        +list~FastFluxAlert~ alerts
        +suspicious() bool
    }
    class mod_netcross_core_security_fast_flux["netcross_core.security.fast_flux"] {
        <<module>>
        +detect_fast_flux(packets, thresholds) FastFluxResult
    }

    %% ===== netcross_core.security.findings =====
    class mod_netcross_core_security_findings["netcross_core.security.findings"] {
        <<module>>
        +scan_capture_exploits(label, path, signatures) list~Detection~
        +exploit_findings(detections) list~dict~str, Any~~
        +anomaly_findings(suspicions) list~dict~str, Any~~
        +dns_tunnel_findings(suspicions) list~dict~str, Any~~
        +beaconing_findings(suspicions) list~dict~str, Any~~
        +exfiltration_findings(alerts) list~dict~str, Any~~
        +tls_audit_findings(audit) list~dict~str, Any~~
        +lateral_movement_findings(events) list~dict~str, Any~~
        +flow_stats_findings(flows) list~dict~str, Any~~
        +new_host_findings(assets) list~dict~str, Any~~
        +cve_findings(fingerprints, conn) list~dict~str, Any~~
        +dga_findings(alerts) list~dict~str, Any~~
        +fast_flux_findings(alerts) list~dict~str, Any~~
        +sequence_gap_findings(gaps) list~dict~str, Any~~
        +cross_capture_duplicate_findings(duplicate_count) list~dict~str, Any~~
        +extracted_file_findings(extraction) list~dict~str, Any~~
        +apply_security_findings(report, all_packets, detections, cve_conn, tls_policy, known_destinations, known_hosts, treat_test_net_as_external) None
    }

    %% ===== netcross_core.security.flow_stats =====
    class FlowStatsThresholds {
        <<dataclass, frozen>>
        +int small_packet_threshold
        +int large_packet_threshold
        +float high_byte_entropy_ratio
        +int min_payload_for_entropy
        +int min_flow_payload_bytes
        +int splt_max_packets
    }
    class FlowStat {
        <<dataclass>>
        +str src
        +str dst
        +int packet_count
        +int byte_count
        +list~tuple~int, float~~ splt
        +Counter size_distribution
        +int upload_bytes
        +int download_bytes
        +list~float~ inter_arrivals
        +str classification
        +float entropy
        +float byte_entropy
        +float byte_entropy_ratio
        +int payload_bytes
        +float median_size
        +float upload_ratio
        +float regularity_cv
        +list~str~ points
        +to_dict() dict
    }
    class FlowStatsResult {
        <<dataclass>>
        +list~FlowStat~ flows
        +to_dict() dict
    }
    class mod_netcross_core_security_flow_stats["netcross_core.security.flow_stats"] {
        <<module>>
        +analyze_flow_stats(packets, thresholds) FlowStatsResult
    }

    %% ===== netcross_core.security.lateral_movement =====
    class LateralMovementThresholds {
        <<dataclass>>
        +int port_scan_min_ports
        +int port_scan_min_hosts
        +bool scan_syn_only
        +int host_scan_min_hosts
        +int host_scan_consecutive_min
        +int brute_force_min_attempts
        +int brute_force_min_hosts
        +float brute_force_window_seconds
        +frozenset~tuple~str, str~~ new_connection_baseline_pairs
    }
    class LateralMovementEvent {
        <<dataclass>>
        +str point
        +str source
        +str event_type
        +str details
        +float score
        +list~str~ targets
        +tuple~str, ...~ points
        +points_list() list~str~
    }
    class LateralMovementResult {
        <<dataclass>>
        +list~LateralMovementEvent~ events
        +bool suspicious
        +events_by_type() dict~str, list~LateralMovementEvent~~
    }
    class mod_netcross_core_security_lateral_movement["netcross_core.security.lateral_movement"] {
        <<module>>
        +detect_port_scans(packets, thresholds) list~LateralMovementEvent~
        +detect_host_scans(packets, thresholds) list~LateralMovementEvent~
        +detect_brute_force(packets, thresholds) list~LateralMovementEvent~
        +detect_unusual_protocols(packets, thresholds) list~LateralMovementEvent~
        +detect_new_connections(packets, thresholds) list~LateralMovementEvent~
        +detect_lateral_movement(packets, thresholds) LateralMovementResult
    }

    %% ===== netcross_core.security.protocol_mismatch =====
    class mod_netcross_core_security_protocol_mismatch["netcross_core.security.protocol_mismatch"] {
        <<module>>
        +detect_protocol_mismatch(pkt) tuple~str, str~?
        +detect_protocol_mismatches(packets) list~dict~str, Any~~
        +count_protocol_mismatches(packets) dict~str, dict~str, int~~
        +protocol_mismatch_findings(mismatches) list~dict~str, Any~~
    }

    %% ===== netcross_core.security.tls_audit =====
    class TlsAuditPolicy {
        <<dataclass, frozen>>
        +int? max_validity_days
        +int min_rsa_bits
        +int min_dsa_bits
        +int min_ec_bits
        +frozenset~str~ broken_hashes
        +frozenset~str~ deprecated_hashes
        +int max_name_len
        +int random_min_label_len
        +float random_min_entropy_bits
        +Mapping~str, str~ severities
        +frozenset~str~ disabled
        +severity(code) str
        +enabled(code) bool
    }
    class TlsIssue {
        <<dataclass, frozen>>
        +str code
        +str severity
        +str detail
    }
    class TlsAuditResult {
        <<dataclass>>
        +list~dict~ certificates
        +list~dict~ servers
    }
    class mod_netcross_core_security_tls_audit["netcross_core.security.tls_audit"] {
        <<module>>
        +parse_cert_date(value) datetime?
        +audit_certificate(pk, policy) list~TlsIssue~
        +audit_tls_certificates(packets, policy) TlsAuditResult
    }

    %% ===== relations =====
    CveEntry --> AffectedProduct : affected
    CveSeed --> CveEntry : entries
    DgaResult --> DgaAlert : alerts
    FastFluxResult --> FastFluxAlert : alerts
    FlowStatsResult --> FlowStat : flows
    LateralMovementResult --> LateralMovementEvent : events
```

## `netcross_core.support`

| Module | Rôle |
|---|---|
| `netcross_core.support` | remontee de tickets anonymisee (issue #269). |
| `netcross_core.support.scrubber` | anonymisation de TEXTE LIBRE (issue #269). |
| `netcross_core.support.ticket` | remontee de tickets anonymisee (issue #269). |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.support.scrubber =====
    class ScrubReport {
        <<dataclass>>
        +dict~str, int~ par_categorie
        +int total
        +int valeurs_distinctes
        +tuple~str, ...~ limites
        +statut() str
        +to_dict() dict
    }
    class TextScrubber {
        +mapping_csv_rows() list~tuple~str, str, str~~
        +scrub(text) tuple~str?, ScrubReport~
        +scrub_lines(lines) tuple~list~str~, ScrubReport~
    }

    %% ===== netcross_core.support.ticket =====
    class ConsentRequiredError {
        <<RuntimeError>>
    }
    class Consent {
        <<dataclass, frozen>>
        +bool granted
        +tuple~str, ...~ scopes
        +str? granted_at
        +str source
        +allows(scope) bool
        +to_dict() dict
    }
    class SupportTicket {
        <<dataclass>>
        +str ticket_id
        +str kind
        +str created_at
        +Consent consent
        +dict~str, str?~ markers
        +dict~str, str?~ environment
        +dict? crash
        +list~str~ errors
        +list~str~ log_lines
        +dict anonymization
        +list~dict~ self_check
        +to_dict() dict
        +to_json(indent) str
    }
    class mod_netcross_core_support_ticket["netcross_core.support.ticket"] {
        <<module>>
        +collect_environment() dict~str, str?~
        +format_exception(exc) tuple~str, str, list~str~~
        +build_ticket(consent, kind, exception, errors, log_lines, markers, scrubber) SupportTicket
        +write_ticket(ticket, path) str
        +write_support_map_csv(scrubber, path) str
        +install_crash_handler(path, consent, markers) None
    }

    %% ===== relations =====
    SupportTicket --> Consent : consent
```

## `netcross_core.tshark_stats`

| Module | Rôle |
|---|---|
| `netcross_core.tshark_stats` | adaptateurs de statistiques ``tshark -z`` (Job 19 / issue #20, section 6.19 de features-backlog.md). |
| `netcross_core.tshark_stats.conversations` | adaptateur ``tshark -z conv,<proto>``. |
| `netcross_core.tshark_stats.dns` | adaptateur ``tshark -z dns,tree``. |
| `netcross_core.tshark_stats.endpoints` | adaptateur ``tshark -z endpoints,<proto>``. |
| `netcross_core.tshark_stats.http` | adaptateur ``tshark -z http,stat``. |
| `netcross_core.tshark_stats.io_stat` | adaptateur ``tshark -z io,stat``. |
| `netcross_core.tshark_stats.models` | modele commun des statistiques tshark (Job 19 / issue #20, section 6.19 de features-backlog.md). |
| `netcross_core.tshark_stats.parse_utils` | utilitaires de parsing tolerants pour les sorties texte ``tshark -z``. |
| `netcross_core.tshark_stats.protocol_hierarchy` | adaptateur ``tshark -z io,phs``. |
| `netcross_core.tshark_stats.response_time` | adaptateur ``tshark -z <proto>,rtt``. |
| `netcross_core.tshark_stats.runner` | invocation de ``tshark -z``. |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_core.tshark_stats =====
    class mod_netcross_core_tshark_stats["netcross_core.tshark_stats"] {
        <<module>>
        +collect_conversations(capture_path, protocol) list~ConversationStat~
        +collect_endpoints(capture_path, protocol) list~EndpointStat~
        +collect_protocol_hierarchy(capture_path) list~ProtocolHierarchyStat~
        +collect_io_stat(capture_path, interval, name) MetricSeries
    }

    %% ===== netcross_core.tshark_stats.conversations =====
    class mod_netcross_core_tshark_stats_conversations["netcross_core.tshark_stats.conversations"] {
        <<module>>
        +parse_conversations(text, protocol) list~ConversationStat~
    }

    %% ===== netcross_core.tshark_stats.dns =====
    class mod_netcross_core_tshark_stats_dns["netcross_core.tshark_stats.dns"] {
        <<module>>
        +parse_dns_stat(text, application) list~ApplicationStat~
    }

    %% ===== netcross_core.tshark_stats.endpoints =====
    class mod_netcross_core_tshark_stats_endpoints["netcross_core.tshark_stats.endpoints"] {
        <<module>>
        +parse_endpoints(text, protocol) list~EndpointStat~
    }

    %% ===== netcross_core.tshark_stats.http =====
    class mod_netcross_core_tshark_stats_http["netcross_core.tshark_stats.http"] {
        <<module>>
        +parse_http_stat(text, application) list~ApplicationStat~
    }

    %% ===== netcross_core.tshark_stats.io_stat =====
    class mod_netcross_core_tshark_stats_io_stat["netcross_core.tshark_stats.io_stat"] {
        <<module>>
        +parse_io_stat(text, name) MetricSeries
    }

    %% ===== netcross_core.tshark_stats.models =====
    class MetricPoint {
        <<dataclass, frozen, slots>>
        +float? start
        +float? end
        +dict~str, float~ values
    }
    class netcross_core_tshark_stats_models_MetricSeries["netcross_core.tshark_stats.models.MetricSeries"] {
        <<dataclass, frozen, slots>>
        +str name
        +tuple~MetricPoint, ...~ points
        +dict~str, str~ labels
    }
    class _BaseStat {
        <<dataclass, frozen, slots>>
        +dict~str, str~ raw_fields
    }
    class ConversationStat {
        <<dataclass, frozen, slots>>
        +str protocol
        +str endpoint_a
        +str endpoint_b
        +int? packets_total
        +int? bytes_total
        +int? packets_ab
        +int? bytes_ab
        +int? packets_ba
        +int? bytes_ba
        +float? rel_start
        +float? duration
        +float? bits_per_second
    }
    class EndpointStat {
        <<dataclass, frozen, slots>>
        +str protocol
        +str address
        +int? packets_total
        +int? bytes_total
        +int? packets_out
        +int? bytes_out
        +int? packets_in
        +int? bytes_in
        +float? bits_per_second
    }
    class ProtocolHierarchyStat {
        <<dataclass, frozen, slots>>
        +str protocol
        +int depth
        +int? frame_count
        +int? byte_count
        +float? percent_packets
        +float? percent_bytes
    }
    class ApplicationStat {
        <<dataclass, frozen, slots>>
        +str application
        +dict~str, str~ labels
        +dict~str, float~ metrics
    }
    class ResponseTimeStat {
        <<dataclass, frozen, slots>>
        +str application
        +int? count
        +float? min_ms
        +float? max_ms
        +float? mean_ms
        +float? median_ms
    }

    %% ===== netcross_core.tshark_stats.parse_utils =====
    class mod_netcross_core_tshark_stats_parse_utils["netcross_core.tshark_stats.parse_utils"] {
        <<module>>
        +is_separator(line) bool
        +is_filter_line(line) bool
        +is_title_or_section(line) bool
        +split_fields(line) list~str~
        +parse_int(s) int?
        +parse_float(s) float?
        +normalize_header(s) str
        +find_column(headers, keywords) int?
        +data_rows(text) list~str~
        +header_lines(text) list~str~
        +reconstruct_headers(text) list~str~
        +raw_fields_from(headers, fields) dict~str, str~
    }

    %% ===== netcross_core.tshark_stats.protocol_hierarchy =====
    class mod_netcross_core_tshark_stats_protocol_hierarchy["netcross_core.tshark_stats.protocol_hierarchy"] {
        <<module>>
        +parse_protocol_hierarchy(text) list~ProtocolHierarchyStat~
    }

    %% ===== netcross_core.tshark_stats.response_time =====
    class mod_netcross_core_tshark_stats_response_time["netcross_core.tshark_stats.response_time"] {
        <<module>>
        +parse_response_time(text, application) ResponseTimeStat?
    }

    %% ===== netcross_core.tshark_stats.runner =====
    class TsharkUnavailableError {
        <<RuntimeError>>
    }
    class mod_netcross_core_tshark_stats_runner["netcross_core.tshark_stats.runner"] {
        <<module>>
        +run_tshark_stat(capture_path, z_arg, tshark_bin, timeout, extra_args) str
    }

    %% ===== relations =====
    netcross_core_tshark_stats_models_MetricSeries --> MetricPoint : points
    _BaseStat <|-- ConversationStat
    _BaseStat <|-- EndpointStat
    _BaseStat <|-- ProtocolHierarchyStat
    _BaseStat <|-- ApplicationStat
    _BaseStat <|-- ResponseTimeStat
```

## `netcross_ai`

| Module | Rôle |
|---|---|
| `netcross_ai` | module IA/ML **optionnel et local** (issue #146, FLOW-5). |
| `netcross_ai.anomaly` | Detection d'anomalies de flux par rapport a une baseline (Isolation Forest). |
| `netcross_ai.features` | Vecteur de caracteristiques d'un flux, calcule a partir des statistiques FLOW-4 (``Report.flow_anomalies`` / ``security.flow_stats``) : taille, SPLT, entropie, ratio montant/descendant, regularite… |
| `netcross_ai.flow_classifier` | Classification de flux avec score de confiance (foret aleatoire). |
| `netcross_ai.model_pack` | Paquets de modeles partageables (issue #271). |
| `netcross_ai.optional` | Detection de disponibilite des dependances ML et repli gracieux. |
| `netcross_ai.outbox` | Boite d'envoi hors connexion des paquets de modeles (issue #271). |
| `netcross_ai.pipeline` | Orchestration des trois usages pour la CLI (``--ai-*``) et mise en forme. |
| `netcross_ai.report_writer` | Redaction du resume executif en francais, des correlations et des recommandations a partir d'un ``Report``. |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_ai.anomaly =====
    class BaselineError {
        <<ValueError>>
    }
    class Baseline {
        <<dataclass>>
        +list~list~float~~ vectors
        +str label
        +str created_at
        +from_flows(flows, label)$ Baseline
        +merge(other) Baseline
        +to_dict() dict
        +save(path) None
        +from_dict(data, source)$ Baseline
        +load(path)$ Baseline
    }
    class FlowAnomaly {
        <<dataclass>>
        +str flow
        +float score
        +bool is_anomaly
        +str classification
        +list~str~ reasons
        +to_dict() dict
    }
    class mod_netcross_ai_anomaly["netcross_ai.anomaly"] {
        <<module>>
        +detect_anomalies(baseline, flows, contamination) list~FlowAnomaly~
    }

    %% ===== netcross_ai.features =====
    class mod_netcross_ai_features["netcross_ai.features"] {
        <<module>>
        +flow_features(flow) list~float~
        +flow_key(flow) str
    }

    %% ===== netcross_ai.flow_classifier =====
    class TrainingSetError {
        <<ValueError>>
    }
    class FlowPrediction {
        <<dataclass>>
        +str flow
        +str label
        +float confidence
        +str rule_classification
        +to_dict() dict
    }
    class FlowClassifier {
        +predict(flows) list~FlowPrediction~
    }
    class mod_netcross_ai_flow_classifier["netcross_ai.flow_classifier"] {
        <<module>>
        +export_training_set(flows, path) int
        +load_training_set(path) list~tuple~dict or list~float~, str~~
        +is_feature_vector(value) bool
        +sample_vector(sample) list~float~
    }

    %% ===== netcross_ai.model_pack =====
    class ModelPackError {
        <<ValueError>>
    }
    class ModelPack {
        <<dataclass>>
        +str name
        +str description
        +str created
        +Baseline? baseline
        +list~tuple~list~float~, str~~ training
        +label_counts() dict~str, int~
        +summary() dict
    }
    class mod_netcross_ai_model_pack["netcross_ai.model_pack"] {
        <<module>>
        +check_name(name) str
        +ticket_body(pack) str
        +build_pack(out_path, name, consent, baseline, training, description, seed) ModelPack
        +read_pack(path) ModelPack
        +import_pack(path, baseline_path, training_path) dict
    }

    %% ===== netcross_ai.optional =====
    class AIUnavailableError {
        <<RuntimeError>>
    }
    class mod_netcross_ai_optional["netcross_ai.optional"] {
        <<module>>
        +ml_available() bool
        +require_ml(feature) None
    }

    %% ===== netcross_ai.outbox =====
    class Submission {
        <<dataclass>>
        +str name
        +Path archive
        +str url
        +str body
        +bool body_in_url
    }
    class mod_netcross_ai_outbox["netcross_ai.outbox"] {
        <<module>>
        +queue_pack(pack_path, outbox) Path
        +pending(outbox) list~ModelPack~
        +submission(name, outbox, repo) Submission
        +mark_sent(name, outbox) Path
        +is_online(host, port, timeout) bool
    }

    %% ===== netcross_ai.pipeline =====
    class AIOptions {
        <<dataclass>>
        +str? baseline_path
        +str? baseline_save
        +str baseline_label
        +str? training_path
        +str? training_export
        +str? summary_engine
        +str? endpoint
    }
    class mod_netcross_ai_pipeline["netcross_ai.pipeline"] {
        <<module>>
        +run_ai(report, flows, options) dict
        +format_ai(result, top) str
    }

    %% ===== netcross_ai.report_writer =====
    class WriterConfigError {
        <<ValueError>>
    }
    class Summary {
        <<dataclass>>
        +str engine
        +str text
        +list~str~ correlations
        +list~str~ recommendations
        +str fallback_reason
        +to_dict() dict
    }
    class mod_netcross_ai_report_writer["netcross_ai.report_writer"] {
        <<module>>
        +collect_facts(report, ai) dict
        +template_summary(report, ai) Summary
        +parse_engine(spec, endpoint) tuple~str, str, str~
        +check_local_endpoint(url) None
        +build_prompt(facts) str
        +llm_generate(kind, model, url, prompt, timeout) str
        +write_summary(report, ai, engine, endpoint) Summary
    }

    %% ===== relations =====
    ModelPack --> Baseline : baseline
```

## `netcross_report`

| Module | Rôle |
|---|---|
| `netcross_report` | synthese, triage, et generation de rapports (PDF, JSON) a partir d'un Report netcross_core. |
| `netcross_report.charts` | graphiques matplotlib exportes en PNG pour le PDF. |
| `netcross_report.comm_map` | cartographie des communications observees (Job 15/issue #15, FEATURES.md section 6.6). |
| `netcross_report.expert_events` | construit les vues `ExpertEvent`/ `Diagnosis` (Session 36, cinquieme et sixieme objets de contrat de la Session 0, FEATURES.md section 13.3) a partir d'une liste de `Finding`/ `DiffFinding` deja… |
| `netcross_report.history` | persiste un resume de chaque run (analyse ou diff) dans une base SQLite locale, pour observer une tendance dans le temps (score de sante, nombre de constats par severite) sur des runs successifs --… |
| `netcross_report.json_report` | serialise un Report/DiffFinding en JSON structure, pour l'integration externe (dashboard, ticketing, pipeline CI qui veut parser un resultat sans dependre du format texte console). |
| `netcross_report.live_html` | issue #274 : page de presentation du rapport temps reel (voir netcross_core.live_report). |
| `netcross_report.metric_charts` | API generique de graphiques : tout module d'analyse peut produire un graphique a partir d'une MetricSeries sans reimplementer son propre code matplotlib. |
| `netcross_report.path_metrics` | metriques de qualite par segment du chemin observe (Job 16/issue #12, FEATURES.md section 6.7). |
| `netcross_report.pdf` | assemble le rapport PDF final (synthese, graphiques, tableaux de detail) a partir d'un Report netcross_core, avec reportlab. |
| `netcross_report.rule_engine` | premier PILOTE du moteur d'EXECUTION evoque comme premier chantier ouvert par CLAUDE.md/`Prochaine feature` depuis la Session 54 (bibliotheque de regles §6.2 complete, 41 regles) : faire evaluer une… |
| `netcross_report.security_html` | rendu HTML du rapport de securite (issue #218, troisieme sortie apres le texte et le JSON). |
| `netcross_report.security_report` | rapport de securite consolide et tableau de bord (CVE-5, issue #139, parent #133). |
| `netcross_report.sequence_view` | diagramme de sequence multi-hotes (Job 14/issue #11, FEATURES.md section 6.5). |
| `netcross_report.session_objects` | construction et rendu CONSOLE des objets de contrat de la Session 0 (Job 4/issue #13). |
| `netcross_report.siem_export` | export des constats de securite pour integration SIEM : CEF (issue #170), LEEF 2.0 et STIX 2.1 (issue #279). |
| `netcross_report.stix_export` | export STIX 2.1 des constats de securite (issue #279, sous-issue de #170). |
| `netcross_report.synthesis` | transforme un Report en une liste de constats (Finding) via des regles et seuils explicites. |
| `netcross_report.triage` | agrege les Finding (ou DiffFinding) produits par ailleurs pour repondre a une question que synthesis.py ne pose pas : "par ou je commence a regarder ?" |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_report.charts =====
    class mod_netcross_report_charts["netcross_report.charts"] {
        <<module>>
        +chart_topology(r, path)
        +chart_throughput(r, path)
        +chart_latency(r, path)
        +chart_loss(r, path)
        +chart_topn_timeseries(r, point, dimension, path)
        +generate_topn_charts(r, tmpdir, point)
        +chart_severity_summary(findings, path, scheme)
        +chart_path_quality(metrics, path)
        +chart_sequence_diagram(view, path)
        +chart_comm_map(cmap, path)
        +generate_all_charts(r, findings, tmpdir)
    }

    %% ===== netcross_report.comm_map =====
    class CommNode {
        <<dataclass>>
        +str host
        +int packets
        +int bytes
        +set protocols
        +int anomalies
    }
    class CommEdge {
        <<dataclass>>
        +str src
        +str dst
        +int packets
        +int bytes
        +set protocols
        +int anomalies
        +int flows
        +label() str
    }
    class CommMap {
        <<dataclass>>
        +list nodes
        +list edges
        +list protocols
        +int total_edges
        +int total_hosts
    }
    class mod_netcross_report_comm_map["netcross_report.comm_map"] {
        <<module>>
        +available_protocols(flows) list~str~
        +build_comm_map(flows, protocols, top_n, only_anomalies) CommMap
        +format_comm_map(cmap, top_n) str
    }

    %% ===== netcross_report.expert_events =====
    class mod_netcross_report_expert_events["netcross_report.expert_events"] {
        <<module>>
        +build_expert_events(findings) list~ExpertEvent~
        +build_diagnoses(events) list~Diagnosis~
    }

    %% ===== netcross_report.history =====
    class HistoryEntry {
        <<dataclass, frozen>>
        +int id
        +str recorded_at
        +str run_type
        +str? label
        +list~str~ or dict~str, list~str~~ points
        +int health_score
        +str health_label
        +int total_findings
        +dict~str, int~ finding_counts
        +dict meta
    }
    class HistoryDatabaseError {
        <<ValueError>>
    }
    class mod_netcross_report_history["netcross_report.history"] {
        <<module>>
        +record_run(r, db_path, findings, tls_findings, quic_findings, meta, label) int
        +record_diff_run(findings, baseline, current, db_path, meta, label) int
        +list_history(db_path, limit, label, run_type) list~HistoryEntry~
        +print_history(entries) None
    }

    %% ===== netcross_report.json_report =====
    class mod_netcross_report_json_report["netcross_report.json_report"] {
        <<module>>
        +generate_json_report(r, output_path, title, meta, findings, tls_findings, quic_findings, flows, conversations, expert_events, diagnoses, compliance, wireshark_expert_events, rule_engine_findings, names, security_report) str
        +generate_json_diff(findings, baseline, current, output_path, title, meta, tls_findings_baseline, tls_findings_current, quic_findings_baseline, quic_findings_current, flows, conversations, expert_events, diagnoses, compliance, wireshark_expert_events, names) str
    }

    %% ===== netcross_report.live_html =====
    class mod_netcross_report_live_html["netcross_report.live_html"] {
        <<module>>
        +render_live_html(snapshot, journal, interval) str
    }

    %% ===== netcross_report.metric_charts =====
    class Threshold {
        <<dataclass, slots>>
        +float value
        +str label
        +str color
        +str linestyle
        +float linewidth
    }
    class ComplianceZone {
        <<dataclass, slots>>
        +float? y_min
        +float? y_max
        +str label
        +str color
        +float alpha
    }
    class netcross_report_metric_charts_MetricSeries["netcross_report.metric_charts.MetricSeries"] {
        <<dataclass, slots>>
        +str name
        +list~float~ values
        +str unit
        +list~float~? timestamps
        +list~str~? labels
        +str source
        +dict~str, object~ context
        +list~Threshold~ thresholds
        +list~ComplianceZone~ zones
        +validate() None
    }
    class mod_netcross_report_metric_charts["netcross_report.metric_charts"] {
        <<module>>
        +render_line(series, path) str?
        +render_area(series, path) str?
        +render_bars(series, path) str?
        +render_histogram(series, path) str?
        +render_scatter(series, path) str?
        +render_metric_chart(series, path, kind) str?
    }

    %% ===== netcross_report.path_metrics =====
    class SegmentMetrics {
        <<dataclass>>
        +str upstream
        +str downstream
        +int samples
        +float? delay_avg_ms
        +float? delay_p50_ms
        +float? delay_p95_ms
        +float? delay_p99_ms
        +float? jitter_ms
        +int loss_count
        +float? loss_pct
        +float? throughput_bps
        +int dscp_changes
        +int frag_new
        +int pmtud_blackhole
        +int retrans
        +int? hops
        +int hop_outliers
        +label() str
        +measured() bool
    }
    class mod_netcross_report_path_metrics["netcross_report.path_metrics"] {
        <<module>>
        +build_path_metrics(report) list~SegmentMetrics~
        +rank_path_segments(metrics) list~SegmentMetrics~
        +degradation_summary(metrics) str
    }

    %% ===== netcross_report.pdf =====
    class mod_netcross_report_pdf["netcross_report.pdf"] {
        <<module>>
        +path_section_story(metrics, styles, chart_path)
        +sequence_section_story(views, styles, chart_paths)
        +expert_section_story(session_objects, styles, top_n)
        +security_section_story(security_report, styles)
        +generate_pdf(r, output_path, title, meta, findings, tls_findings, quic_findings, session_objects, sequence_views, security_report)
        +generate_diff_pdf(findings, baseline, current, output_path, title, meta, tls_findings_baseline, tls_findings_current, quic_findings_baseline, quic_findings_current)
    }

    %% ===== netcross_report.rule_engine =====
    class mod_netcross_report_rule_engine["netcross_report.rule_engine"] {
        <<module>>
        +evaluate(rule_id, report) list~Finding~
        +available_rule_ids() list~str~
    }

    %% ===== netcross_report.security_html =====
    class mod_netcross_report_security_html["netcross_report.security_html"] {
        <<module>>
        +render_security_html(sr, title, meta, generated_at) str
        +generate_security_html(sr, output_path, title, meta) str
    }

    %% ===== netcross_report.security_report =====
    class SecurityItem {
        <<dataclass, slots>>
        +str category
        +str severity
        +str detail
        +str? cve_id
        +float? cvss
        +str? service
        +str? version
        +str? host
        +int? port
        +str? point
        +list~str~ points
        +str source
        +str? plugin
        +str? detector
    }
    class DetectorGroup {
        <<dataclass, slots>>
        +str? detector
        +str label
        +str severity
        +list items
    }
    class ServiceEntry {
        <<dataclass, slots>>
        +str service
        +str? version
        +str? host
        +int? port
        +list~str~ points
        +str? severity
        +list~str~ cve_ids
        +str? fingerprint
        +str? fingerprint_readable
        +vulnerable() bool
    }
    class SecurityDashboard {
        <<dataclass, slots>>
        +int services_total
        +int services_vulnerable
        +int exploits
        +int anomalies
        +int anomalies_netcross
        +int anomalies_expert_info
        +int cves
        +int assets_total
        +int assets_new
        +int assets_baseline_size
        +dict~str, int~ by_severity
        +int score
        +str? level
    }
    class netcross_report_security_report_SecurityReport["netcross_report.security_report.SecurityReport"] {
        <<dataclass, slots>>
        +list~ServiceEntry~ services
        +list~SecurityItem~ exploits
        +list~SecurityItem~ anomalies
        +list~SecurityItem~ cves
        +SecurityDashboard dashboard
        +list~dict~ notifications
        +list~dict~ plugins
        +list~dict~ assets
    }
    class mod_netcross_report_security_report["netcross_report.security_report"] {
        <<module>>
        +detector_label(detector) str
        +is_expert_info(item) bool
        +group_by_detector(items) list~DetectorGroup~
        +severity_from_cvss(cvss) str
        +build_security_report(report) SecurityReport
        +asset_os_label(asset) str
        +asset_ports_label(asset) str
        +format_security_report(sr) list~str~
        +print_security_report(sr) None
        +security_report_to_dict(sr) dict
    }

    %% ===== netcross_report.sequence_view =====
    class SequenceStep {
        <<dataclass>>
        +float ts
        +float rel_ms
        +float delta_ms
        +str src
        +str dst
        +str point
        +int length
        +str proto
        +int? sport
        +int? dport
        +str flags
        +int? frame_number
        +bool is_retransmission
        +label() str
    }
    class SequenceView {
        <<dataclass>>
        +str title
        +list~SequenceStep~ steps
        +list~str~ hosts
        +list~str~ points
        +int truncated
        +int total_steps
    }
    class mod_netcross_report_sequence_view["netcross_report.sequence_view"] {
        <<module>>
        +build_sequence_view(packets_by_point, title, max_steps) SequenceView
        +flow_title(flow) str
        +top_flow_views(flows, flow_objects, max_flows, max_steps)
    }

    %% ===== netcross_report.session_objects =====
    class SessionObjects {
        <<dataclass>>
        +list flows
        +list conversations
        +list expert_events
        +list diagnoses
        +list compliance
        +list? wireshark_expert_events
        +json_kwargs() dict
    }
    class mod_netcross_report_session_objects["netcross_report.session_objects"] {
        <<module>>
        +build_session_objects(report, findings, flows, all_packets, wireshark_expert_events) SessionObjects
        +format_session_objects(objs, top_n) list~str~
        +print_session_objects(objs, top_n) None
    }

    %% ===== netcross_report.siem_export =====
    class SiemRecord {
        <<dataclass, frozen, slots>>
        +int sig_id
        +str category
        +str severity
        +int severity_num
        +str detail
        +str? point
        +int timestamp_ms
        +Mapping~str, Any~ finding
    }
    class mod_netcross_report_siem_export["netcross_report.siem_export"] {
        <<module>>
        +to_cef(records) list~str~
        +export_cef(report) list~str~
        +to_leef(records) list~str~
        +export_leef(report) list~str~
        +write_cef(report, output_path) str
        +write_leef(report, output_path) str
        +write_siem(report, output_path, fmt, observed_from, observed_until) str
    }

    %% ===== netcross_report.stix_export =====
    class _Builder {
        +add(obj) str
        +skip(reason) None
        +sdo(stix_type, content, confidence) dict~str, Any~
        +ip(value) str?
        +software(name, version) str
        +traffic(dst_ref, dst_port, src_ref, protocol) str?
        +observed(refs, point) str
    }
    class mod_netcross_report_stix_export["netcross_report.stix_export"] {
        <<module>>
        +format_timestamp(when) str
        +identity_object() dict~str, Any~
        +exploit_pattern(f) str?
        +to_stix_bundle(report, observed_from, observed_until) dict~str, Any~
        +export_stix(report, observed_from, observed_until) str
        +write_stix(report, output_path, observed_from, observed_until) str
    }

    %% ===== netcross_report.synthesis =====
    class Finding {
        <<dataclass>>
        +str severity
        +str category
        +str segment
        +str message
        +int? sample_size
        +list~EvidenceLink~ evidence
        +ExpertEvent? event
        +str? rule_id
    }
    class mod_netcross_report_synthesis["netcross_report.synthesis"] {
        <<module>>
        +build_findings(r) list~Finding~
    }

    %% ===== netcross_report.triage =====
    class SegmentScore {
        <<dataclass>>
        +str segment
        +float score
        +list~str~ categories
        +list~Finding~ findings
        +bool low_confidence
        +convergent() bool
    }
    class mod_netcross_report_triage["netcross_report.triage"] {
        <<module>>
        +rank_segments(findings, severity_weights, convergence_bonus, min_score) list~SegmentScore~
        +print_triage(ranked, top_n) None
        +health_score(ranked, scale) int
        +health_label(score) str
        +format_health_line(score) str
    }

    %% ===== relations =====
    netcross_report_metric_charts_MetricSeries --> ComplianceZone : zones
    netcross_report_metric_charts_MetricSeries --> Threshold : thresholds
    netcross_report_security_report_SecurityReport --> SecurityDashboard : dashboard
    netcross_report_security_report_SecurityReport --> SecurityItem : anomalies, cves, exploits
    netcross_report_security_report_SecurityReport --> ServiceEntry : services
    SequenceView --> SequenceStep : steps
    SegmentScore --> Finding : findings
```

## `netcross_api`

| Module | Rôle |
|---|---|
| `netcross_api` | service REST FastAPI pour exposer les analyses Netcross (issue #209). |
| `netcross_api.app` | application FastAPI pour exposer les analyses Netcross (issues #209, #354, #356). |
| `netcross_api.models` | modèles Pydantic pour les requêtes/réponses API (issue #209). |
| `netcross_api.store` | analyses de l'API : statut, document JSON, persistance. |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_api.app =====
    class AnalysisError {
        <<Exception>>
    }
    class mod_netcross_api_app["netcross_api.app"] {
        <<module>>
        +health() HealthResponse
        +upload_capture(file, label, wait, _auth) JSONResponse
        +segment_losses(report) list~SegmentLoss~
        +upload_multi_capture(files, labels, points_order, wait, _auth) JSONResponse
        +get_analysis(analysis_id, _auth) JSONResponse
        +get_security_report(analysis_id, _auth) SecurityReport
        +list_analyses(_auth) dict
        +get_analysis_status(analysis_id, _auth) AnalysisStatus
    }

    %% ===== netcross_api.models =====
    class HealthResponse {
        <<BaseModel>>
        +str status
        +str version
    }
    class AnalysisSummary {
        <<BaseModel>>
        +str analysis_id
        +str status
        +int point_count
        +int packet_count
        +int security_finding_count
    }
    class AnalysisAccepted {
        <<BaseModel>>
        +str analysis_id
        +str status
        +str status_url
    }
    class AnalysisStatus {
        <<BaseModel>>
        +str analysis_id
        +str status
        +str? error
        +dict? summary
    }
    class SecurityFinding {
        <<BaseModel>>
        +str severity
        +str category
        +str detail
        +str? point
    }
    class netcross_api_models_SecurityReport["netcross_api.models.SecurityReport"] {
        <<BaseModel>>
        +str analysis_id
        +list~SecurityFinding~ findings
        +list~dict~ service_fingerprints
        +list~dict~ lateral_movement_events
        +list~dict~ dga_alerts
        +list~dict~ fast_flux_alerts
    }
    class ErrorResponse {
        <<BaseModel>>
        +str detail
    }
    class SegmentLoss {
        <<BaseModel>>
        +str segment
        +str upstream
        +str downstream
        +int loss_count
        +float? loss_pct
        +int seen_downstream
        +int off_path_count
        +int latency_samples
        +float? latency_avg_ms
    }
    class MultiAnalysisSummary {
        <<BaseModel>>
        +str analysis_id
        +str status
        +int point_count
        +int packet_count
        +int security_finding_count
        +list~str~ points
        +str order_source
        +list~SegmentLoss~ segments
    }

    %% ===== netcross_api.store =====
    class AnalysesStore {
        +persistent() bool
        +create_pending(metadata) str
        +complete(analysis_id, document, summary) None
        +fail(analysis_id, error) None
        +get(analysis_id) dict?
        +get_status(analysis_id) str?
        +list_ids() list~str~
        +clear() None
    }
    class mod_netcross_api_store["netcross_api.store"] {
        <<module>>
        +jsonable(value) Any
        +report_document(report) dict~str, Any~
    }

    %% ===== relations =====
    netcross_api_models_SecurityReport --> SecurityFinding : findings
    MultiAnalysisSummary --> SegmentLoss : segments
```

## `netcross_gtk4`

| Module | Rôle |
|---|---|
| `netcross_gtk4` | — |
| `netcross_gtk4.analysis_pipeline` | pipeline d'analyse extrait de MainWindow (issue #246, #285 -- lot supplémentaire). |
| `netcross_gtk4.annotations_panel` | panneau GTK des annotations (issue #363). |
| `netcross_gtk4.annotations_view` | logique de presentation pour l'etiquetage/signets sur paquets (Job 40 / issue #160, section "Metadonnees et annotation"). |
| `netcross_gtk4.app` | interface GTK4 pour netcross_core / netcross_report. |
| `netcross_gtk4.bpf_panel` | Decisions du panneau de filtres BPF de la capture live, sorties de ``netcross_gtk4/app.py`` (issue #285, quatrieme lot). |
| `netcross_gtk4.capture_list` | Enumeration, ordre et retrait des lignes des panneaux de captures, sortis de ``netcross_gtk4/app.py`` (issue #285, cinquieme lot). |
| `netcross_gtk4.dashboard_context` | contexte d'analyse partage pour le dashboard analytique interactif (issue #18, section 6.17). |
| `netcross_gtk4.diff_pipeline` | pipeline de comparaison baseline/courant extrait de MainWindow._run_diff_thread (issue #246, #285 -- lot supplémentaire). |
| `netcross_gtk4.duplicate_view` | Presentation helpers for cross-capture duplicate detection (Job 41). |
| `netcross_gtk4.live_capture_points` | points de capture en direct de la GUI (Job 48, issue #168) : une ligne du panneau de capture live peut porter PLUSIEURS interfaces d'une meme machine ("eth0, eth1"), chacune devenant son propre point… |
| `netcross_gtk4.panel_state` | decisions de visibilite, de sensibilite et de selection des panneaux de la GUI (issue #285, troisieme lot). |
| `netcross_gtk4.row_labels` | libelles et cles de tri des lignes affichees par la GUI (issue #285, premier lot d'extraction de `app.py`). |
| `netcross_gtk4.run_outcome` | etat de resultat et decisions d'affichage a la fin d'une analyse ou d'une comparaison (issue #285, deuxieme lot). |
| `netcross_gtk4.security_view` | section Securite de la GUI (issue #357). |
| `netcross_gtk4.stats_view` | logique de presentation pour la vue d'exploration statistique (Job 27 / issue #22, section 6.8). |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== netcross_gtk4.analysis_pipeline =====
    class AnalysisOptions {
        <<dataclass>>
        +float bucket_ms
        +int rtp_rate
        +bool nat_tolerant
        +bool parallel
        +bool auto_topology
        +bool triage
        +int triage_topn
        +bool tls
        +bool quic
        +bool security
        +bool redact
        +int topn
        +bool detect_duplicates
        +bool exclude_duplicates
        +float duplicate_threshold_ms
    }
    class AnalysisResult {
        <<dataclass>>
        +str mode
        +Report? report
        +list flows
        +list? findings
        +str text
        +list? tls_findings
        +list? quic_findings
        +list wireshark_expert_events
        +Any security_report
    }
    class mod_netcross_gtk4_analysis_pipeline["netcross_gtk4.analysis_pipeline"] {
        <<module>>
        +load_packets(captures, parallel, on_progress) list
        +run_analysis_pipeline(captures, options, on_progress) AnalysisResult
        +run_security_analysis(report, all_packets, captures, log)
    }

    %% ===== netcross_gtk4.annotations_panel =====
    class AnnotationsPanel {
        <<Gtk.Box>>
        +load(captures) None
        +clear() None
        +selected_point() str?
        +prefill(point, frame_number) None
        +submit() bool
        +remove(point, frame_number, tag) None
        +toggle_tag(tag, active) None
        +refresh() None
        +visible_rows()
        +context_actions(target) list~tuple~str, Callable~(), None~~~
    }

    %% ===== netcross_gtk4.annotations_view =====
    class AnnotationStore {
        <<dataclass>>
        +list~tuple~str, str~~ captures
        +dict~str, list~PacketAnnotation~~ by_label
        +dict~str, str~ errors
        +load(captures)$ AnnotationStore
        +labels() list~str~
        +writable_labels() list~str~
        +add(label, frame_number, tag, comment) None
        +remove(label, frame_number, tag) None
        +tags() list~str~
        +rows(selected_tags) list~tuple~str, PacketAnnotation~~
    }
    class mod_netcross_gtk4_annotations_view["netcross_gtk4.annotations_view"] {
        <<module>>
        +available_tags(annotations) list~str~
        +filter_by_tags(annotations, selected_tags) list~PacketAnnotation~
        +format_annotation_row(annotation) str
        +add_annotation(annotations, frame_number, tag, comment, color) list~PacketAnnotation~
        +remove_annotation(annotations, frame_number, tag) list~PacketAnnotation~
        +parse_frame_number(text) int
    }

    %% ===== netcross_gtk4.app =====
    class CaptureRow {
        <<Gtk.Box>>
        +label()
    }
    class LiveCaptureRow {
        <<Gtk.Box>>
        +set_filters(filters)
        +label()
        +interface()
        +bpf_filter()
    }
    class CaptureListPanel {
        <<Gtk.Box>>
        +add_row(path, default_label)
        +rows()
        +captures()
    }
    class LiveCaptureListPanel {
        <<Gtk.Box>>
        +add_row(default_label, interface, bpf_filter)
        +rows()
        +captures()
    }
    class MainWindow {
        <<Gtk.ApplicationWindow>>
        +add_capture_row(path, default_label)
        +on_run_analysis(_btn)
        +on_export_csv(_btn)
        +on_export_pdf(_btn)
        +export_pdf_to(path)
        +on_export_json(_btn)
        +export_json_to(path)
        +on_export_security(suffix)
        +export_security_to(path)
    }
    class NetcrossApp {
        <<Gtk.Application>>
        +do_activate()
    }
    class mod_netcross_gtk4_app["netcross_gtk4.app"] {
        <<module>>
        +main()
    }

    %% ===== netcross_gtk4.bpf_panel =====
    class DemandeSauvegarde {
        <<dataclass, frozen>>
        +BPFFilter? filtre
        +str message
        +acceptee() bool
    }
    class mod_netcross_gtk4_bpf_panel["netcross_gtk4.bpf_panel"] {
        <<module>>
        +filtre_a_l_indice(index, filtres)
        +infobulle_du_menu(index, filtres, indice_hint)
        +selection_apres_choix(index, filtres)
        +doit_desolidariser_le_menu(index, filtres, texte_du_champ)
        +valider_sauvegarde(expression, nom, description, sauvegarde_possible)
        +indice_du_filtre_nomme(nom, filtres)
        +noms_du_menu(filtres, titre)
        +indice_apres_deplacement(index, nombre_de_lignes, vers_le_haut)
    }

    %% ===== netcross_gtk4.capture_list =====
    class _RowSource {
        <<Protocol>>
        +get_row_at_index(index) Any
    }
    class mod_netcross_gtk4_capture_list["netcross_gtk4.capture_list"] {
        <<module>>
        +nombre_de_lignes(listbox) int
        +lignes(listbox) list~Any~
        +nom_de_point(nom, index) str
        +nom_par_defaut_fichier(chemin) str
        +nom_par_defaut_live(lignes_existantes) str
        +captures_fichiers(contenus) list~tuple~str, str~~
        +captures_live(contenus) list~tuple~str, str, str?~~
        +deplacer_ligne(row, vers_le_haut) bool
        +retirer_ligne(row, on_change) bool
    }

    %% ===== netcross_gtk4.dashboard_context =====
    class DashboardSelection {
        <<dataclass>>
        +str? point
        +str? endpoint
        +str? protocol
        +tuple? flow_key
        +tuple~str, str~? pair
        +int? bucket
        +int? event_id
    }
    class DashboardSnapshot {
        <<dataclass, frozen>>
        +list~dict~ timeline_rows
        +list~dict~ segment_rows
        +list~dict~ flow_rows
        +list~dict~ endpoint_rows
        +list~dict~ protocol_rows
        +list~dict~ event_rows
        +str selection_summary
    }
    class mod_netcross_gtk4_dashboard_context["netcross_gtk4.dashboard_context"] {
        <<module>>
        +clear_selection(selection) DashboardSelection
        +select_flow(selection, flow) DashboardSelection
        +select_endpoint(selection, endpoint) DashboardSelection
        +select_protocol(selection, protocol) DashboardSelection
        +select_point(selection, point) DashboardSelection
        +select_bucket(selection, bucket) DashboardSelection
        +select_event(selection, event_id, events) DashboardSelection
        +build_dashboard_snapshot(report, flows, findings, tls_findings, quic_findings, wireshark_expert_events, selection) DashboardSnapshot
    }

    %% ===== netcross_gtk4.diff_pipeline =====
    class DiffOptions {
        <<dataclass>>
        +float bucket_ms
        +int rtp_rate
        +bool nat_tolerant
        +bool parallel
        +bool auto_topology
        +float loss_min_pp
        +float latency_min_ms
        +bool redact
        +bool tls
        +bool quic
    }
    class DiffResult {
        <<dataclass>>
        +str mode
        +list findings
        +Any baseline_report
        +Any current_report
        +str text
        +list? tls_findings_baseline
        +list? tls_findings_current
        +list? quic_findings_baseline
        +list? quic_findings_current
    }
    class mod_netcross_gtk4_diff_pipeline["netcross_gtk4.diff_pipeline"] {
        <<module>>
        +run_diff_pipeline(baseline_captures, current_captures, options, on_progress) DiffResult
    }

    %% ===== netcross_gtk4.duplicate_view =====
    class mod_netcross_gtk4_duplicate_view["netcross_gtk4.duplicate_view"] {
        <<module>>
        +format_duplicate_indicator(report) str
    }

    %% ===== netcross_gtk4.live_capture_points =====
    class mod_netcross_gtk4_live_capture_points["netcross_gtk4.live_capture_points"] {
        <<module>>
        +split_interfaces(text) list~str~
        +expand_live_points(rows) list~tuple~str, str, str?~~
        +duplicate_labels(points) list~str~
        +invalid_sources(points) list~str~
    }

    %% ===== netcross_gtk4.panel_state =====
    class PanelVisibility {
        <<dataclass, frozen>>
        +bool single_panel
        +bool live_panel
        +bool live_extra
        +bool diff_panels
        +bool single_options
        +bool diff_options
        +bool tls_sensitive
        +bool quic_sensitive
        +bool parallel_sensitive
        +bool duplicate_detect_sensitive
        +bool duplicate_threshold_sensitive
        +bool duplicate_exclude_sensitive
        +bool force_tls_off
        +bool force_quic_off
        +bool force_duplicate_detect_off
        +bool force_duplicate_exclude_off
    }
    class RunButtonState {
        <<dataclass, frozen>>
        +bool enabled
        +str? raison
        +str label
    }
    class UnknownViewTypeError {
        <<ValueError>>
    }
    class mod_netcross_gtk4_panel_state["netcross_gtk4.panel_state"] {
        <<module>>
        +panel_visibility(diff_mode, live_mode, detect_duplicates_active) PanelVisibility
        +run_button_state(live_capturing, diff_mode, live_mode, single_rows, baseline_rows, current_rows, live_points, label_actuel) RunButtonState
        +selected_protocol(index, n_items, lire) str?
        +comm_map_filters(protocole, top_n, only_anomalies) dict~str, Any~
        +apply_dashboard_selection(kind, selection, key, flow_par_cle, evenements) Any
    }

    %% ===== netcross_gtk4.row_labels =====
    class mod_netcross_gtk4_row_labels["netcross_gtk4.row_labels"] {
        <<module>>
        +timeline_row_label(row) str
        +timeline_row_key(row)
        +segment_row_label(row) str
        +segment_row_key(row)
        +flow_row_label(row) str
        +flow_row_key(row)
        +endpoint_row_label(row) str
        +endpoint_row_key(row)
        +proto_row_label(row) str
        +proto_row_key(row)
        +event_row_label(row) str
        +event_row_key(row)
    }

    %% ===== netcross_gtk4.run_outcome =====
    class RunOutcome {
        <<dataclass, frozen>>
        +str mode
        +Any report
        +Any flows
        +Any flow_objects
        +Any findings
        +Any tls_findings
        +Any quic_findings
        +Any wireshark_expert_events
        +Any security_report
        +Any diff_findings
        +Any baseline_report
        +Any current_report
        +Any diff_tls_findings_baseline
        +Any diff_tls_findings_current
        +Any diff_quic_findings_baseline
        +Any diff_quic_findings_current
        +str work_status
        +str status
        +str duplicate_indicator
        +str result_text
        +etat() dict~str, Any~
    }
    class mod_netcross_gtk4_run_outcome["netcross_gtk4.run_outcome"] {
        <<module>>
        +build_flow_objects(flows) Any
        +analysis_outcome(mode, report, flows, findings, text, tls_findings, quic_findings, wireshark_expert_events, security_report) RunOutcome
        +diff_status_text(findings) str
        +diff_outcome(findings, baseline_report, current_report, text, tls_findings_baseline, tls_findings_current, quic_findings_baseline, quic_findings_current) RunOutcome
    }

    %% ===== netcross_gtk4.security_view =====
    class mod_netcross_gtk4_security_view["netcross_gtk4.security_view"] {
        <<module>>
        +security_view_text(sr) str
        +export_security_report(sr, path) str
    }

    %% ===== netcross_gtk4.stats_view =====
    class mod_netcross_gtk4_stats_view["netcross_gtk4.stats_view"] {
        <<module>>
        +sort_options() list~tuple~str, str~~
        +group_options() list~tuple~str, str~~
        +format_bytes(n) str
        +format_bps(bps) str
        +format_row(row) str
        +format_rows(rows) list~str~
        +flows_for_row(row, all_flows) list~Flow~
        +format_flow_summary(flow) str
        +build_query(group_by, sort_by, top_n, time_start, time_end, segment) StatsQuery
        +run_stats(flows, report, query, events_by_segment) list~StatRow~
        +build_events_by_segment(findings, flows) dict~str, list~Any~~
    }
```

## CLI (`src/*.py`)

| Module | Rôle |
|---|---|
| `cross_capture_analyzer_cli` | cross_capture_analyzer_cli.py -- interface en ligne de commande pour netcross_core. |
| `cross_capture_batch_cli` | Mode batch (issue #277) : expertise de toutes les captures d'un dossier, et analyse croisee automatique des captures qui semblent etre plusieurs points de vue d'un meme evenement. |
| `cross_capture_diff_cli` | cross_capture_diff_cli.py -- compare deux jeux de captures (avant/apres un correctif, site A / site B...) et remonte les regressions et ameliorations entre les deux runs. |
| `cross_history_cli` | cross_history_cli.py -- interroge une base d'historique SQLite deja alimentee par cross_capture_analyzer_cli.py/cross_capture_diff_cli.py (--history-db), sans relancer d'analyse ni de comparaison. |
| `netcross_ai_models_cli` | paquets de modeles IA partageables et boite d'envoi hors connexion (issue #271). |
| `netcross_lua_doc_cli` | consultation hors ligne de l'API Lua Wireshark (issue #388, rattachee a #331). |

### Diagramme

```mermaid
classDiagram
    direction LR

    %% ===== cross_capture_analyzer_cli =====
    class mod_cross_capture_analyzer_cli["cross_capture_analyzer_cli"] {
        <<module>>
        +main()
    }

    %% ===== cross_capture_batch_cli =====
    class mod_cross_capture_batch_cli["cross_capture_batch_cli"] {
        <<module>>
        +list_captures(folder, recursive) tuple~list~str~, list~str~~
        +make_labels(paths) dict~str, str~
        +build_inventory(label, path) CaptureInventory
        +load_cached_inventory(output, label, path) CaptureInventory?
        +save_cached_inventory(output, inv) None
        +collect_inventories(paths, labels, output, jobs, skip_existing) list~CaptureInventory~
        +analyse_and_write(members, out_path, security) dict
        +run_analyses(plan, output, security, skip_existing)
        +build_synthesis(plan, summaries, errors, ignored, security) list~str~
        +main(argv)
    }

    %% ===== cross_capture_diff_cli =====
    class mod_cross_capture_diff_cli["cross_capture_diff_cli"] {
        <<module>>
        +main()
    }

    %% ===== cross_history_cli =====
    class mod_cross_history_cli["cross_history_cli"] {
        <<module>>
        +main()
    }

    %% ===== netcross_ai_models_cli =====
    class mod_netcross_ai_models_cli["netcross_ai_models_cli"] {
        <<module>>
        +build_parser() argparse.ArgumentParser
        +main(argv) int
    }

    %% ===== netcross_lua_doc_cli =====
    class mod_netcross_lua_doc_cli["netcross_lua_doc_cli"] {
        <<module>>
        +render_methode(m, indent) list~str~
        +render_attribut(a, indent) list~str~
        +render_fiche(f, version) list~str~
        +render_resultats(conn, terme, res, full) list~str~
        +build_parser() argparse.ArgumentParser
        +main(argv) int
    }
```
