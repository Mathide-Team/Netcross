"""Redaction du resume executif en francais, des correlations et des
recommandations a partir d'un ``Report``.

Deux moteurs :

- ``template`` (defaut) : texte deterministe construit a partir des faits,
  aucune dependance, aucun modele -- toujours disponible ;
- ``ollama:MODELE`` / ``llamacpp`` : modele de langage **local** (ex. Llama 3
  8B quantise). Le point d'acces doit etre une adresse de boucle locale
  (127.0.0.1, ::1, localhost) : aucune donnee de capture ne quitte la
  machine. En cas d'echec du modele, repli sur le gabarit (signale).

Dans les deux cas le modele ne recoit que les **faits** extraits ci-dessous
(constats, services, classes de flux, anomalies), jamais les paquets.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

SEVERITY_ORDER = ("critique", "elevee", "moyenne", "faible")
DEFAULT_ENDPOINTS = {"ollama": "http://127.0.0.1:11434", "llamacpp": "http://127.0.0.1:8080"}
MAX_FACT_FINDINGS = 40
LLM_TIMEOUT_S = 180


class WriterConfigError(ValueError):
    """Moteur ou point d'acces invalide (ex. adresse non locale)."""


@dataclass
class Summary:
    engine: str
    text: str
    correlations: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    fallback_reason: str = ""

    def to_dict(self) -> dict:
        logger.debug("to_dict: retour dict")
        return {
            "engine": self.engine,
            "text": self.text,
            "correlations": self.correlations,
            "recommendations": self.recommendations,
            "fallback_reason": self.fallback_reason,
        }


# -- faits --------------------------------------------------------------------


def _sev(f: dict) -> str:
    s = str(f.get("severity", "faible")).lower().replace("é", "e")
    logger.debug("_sev: retour conditionnel")
    return s if s in SEVERITY_ORDER else "faible"


def collect_facts(report: Any, ai: dict | None = None) -> dict:
    """Dictionnaire compact et JSON-serialisable des faits du rapport."""
    logger.debug("collect_facts: report={} ai={}", summarize(report, "report"), summarize(ai, "ai"))
    findings = sorted(getattr(report, "security_findings", []) or [], key=lambda f: SEVERITY_ORDER.index(_sev(f)))
    flows = getattr(report, "flow_anomalies", []) or []
    ai = ai or {}
    logger.debug("collect_facts: retour dict")
    return {
        "constats_par_severite": dict(Counter(_sev(f) for f in findings)),
        "constats": [
            {
                k: f[k]
                for k in ("severity", "category", "detail", "host", "service", "version", "cve_id", "cvss")
                if k in f
            }
            for f in findings[:MAX_FACT_FINDINGS]
        ],
        "services": [
            {k: s.get(k) for k in ("service", "version", "host", "port")}
            for s in (getattr(report, "service_fingerprints", []) or [])[:MAX_FACT_FINDINGS]
        ],
        "flux_par_classe": dict(Counter(str(f.get("classification", "normal")) for f in flows)),
        "domaines_dga": [a.get("domain") for a in (getattr(report, "dga_alerts", []) or [])[:10]],
        "mouvements_lateraux": [
            {"source": e.get("source"), "type": e.get("type")}
            for e in (getattr(report, "lateral_movement_events", []) or [])[:10]
        ],
        "anomalies_ia": [a for a in ai.get("anomalies", []) if a.get("is_anomaly")][:10],
        "classes_ia": dict(Counter(p.get("label") for p in ai.get("classification", []))),
    }


# -- gabarit deterministe ----------------------------------------------------


def _correlations(report: Any, ai: dict | None) -> list[str]:
    logger.debug("_correlations: report={} ai={}", summarize(report, "report"), summarize(ai, "ai"))
    by_host: dict[str, set[str]] = defaultdict(set)
    for f in getattr(report, "security_findings", []) or []:
        if f.get("host"):
            label = str(f.get("category", "constat"))
            by_host[str(f["host"])].add("CVE " + str(f["cve_id"]) if f.get("cve_id") else label)
    for e in getattr(report, "lateral_movement_events", []) or []:
        if e.get("source"):
            by_host[str(e["source"])].add(f"mouvement lateral ({e.get('type', '?')})")
    for a in (ai or {}).get("anomalies", []):
        if a.get("is_anomaly"):
            src = str(a.get("flow", "")).split(" -> ")[0]
            by_host[src].add("flux atypique (IA)")
    out = []
    for host, signals in sorted(by_host.items(), key=lambda kv: -len(kv[1])):
        if len(signals) < 2:
            continue
        has_cve = any(s.startswith("CVE ") for s in signals)
        note = " : exploitation d'une vulnerabilite connue probable" if has_cve and "exploit" in signals else ""
        out.append(f"{host} cumule {len(signals)} signaux ({', '.join(sorted(signals))}){note}.")
    logger.debug("_correlations: retour element")
    return out[:10]


def _recommendations(report: Any, ai: dict | None) -> list[str]:
    logger.debug("_recommendations: report={} ai={}", summarize(report, "report"), summarize(ai, "ai"))
    recs: list[str] = []
    seen: set[str] = set()

    def add(text: str) -> None:
        if text not in seen:
            seen.add(text)
            recs.append(text)

    findings = sorted(getattr(report, "security_findings", []) or [], key=lambda f: SEVERITY_ORDER.index(_sev(f)))
    for f in findings:
        where = f" sur {f['host']}" if f.get("host") else ""
        if f.get("cve_id"):
            svc = " ".join(str(f[k]) for k in ("service", "version") if f.get(k)) or "le service concerne"
            cvss = f", CVSS {f['cvss']}" if f.get("cvss") is not None else ""
            add(f"Mettre a jour {svc}{where} ({f['cve_id']}{cvss}).")
        elif f.get("category") == "exploit":
            add(f"Isoler et examiner{where or ' la machine ciblee'} : signature d'exploitation observee.")
    classes = Counter(str(f.get("classification")) for f in getattr(report, "flow_anomalies", []) or [])
    if classes.get("obfusque"):
        add(
            f"Inspecter les {classes['obfusque']} flux a charge utile de forte entropie "
            "(chiffrement, obfuscation ou tunnel possible)."
        )
    for p in (ai or {}).get("classification", []):
        if p.get("label") in ("tunnel", "c2", "exfiltration") and p.get("confidence", 0) >= 0.6:
            add(f"Verifier le flux {p['flow']} classe « {p['label']} » (confiance {p['confidence']:.0%}).")
    if getattr(report, "dga_alerts", None):
        add("Bloquer ou surveiller au resolveur les domaines de type DGA releves.")
    if getattr(report, "lateral_movement_events", None):
        add("Controler la segmentation et les comptes utilises par les sources de mouvements lateraux.")
    if any(a.get("is_anomaly") for a in (ai or {}).get("anomalies", [])):
        add("Examiner les flux signales atypiques par rapport a la baseline (detail dans la section IA).")
    logger.debug("_recommendations: retour element")
    return recs[:15]


def template_summary(report: Any, ai: dict | None = None) -> Summary:
    logger.debug("template_summary: report={} ai={}", summarize(report, "report"), summarize(ai, "ai"))
    facts = collect_facts(report, ai)
    sev = facts["constats_par_severite"]
    total = sum(sev.values())
    lines = []
    if total:
        detail = ", ".join(f"{sev[s]} {s}" for s in SEVERITY_ORDER if sev.get(s))
        lines.append(f"L'analyse releve {total} constat(s) de securite ({detail}).")
        top = facts["constats"][0]
        lines.append(f"Le plus grave : {top.get('detail', top.get('category', '?'))}.")
    else:
        lines.append("Aucun constat de securite n'a ete releve sur cette capture.")
    flows = facts["flux_par_classe"]
    if flows:
        unusual = {k: v for k, v in flows.items() if k != "normal"}
        text = ", ".join(f"{v} {k}" for k, v in sorted(unusual.items())) or "aucun atypique"
        lines.append(f"{sum(flows.values())} flux analyses statistiquement ({text}).")
    if facts["anomalies_ia"]:
        lines.append(f"{len(facts['anomalies_ia'])} flux s'ecartent nettement de la baseline de trafic normal.")
    if facts["services"]:
        lines.append(f"{len(facts['services'])} service(s) identifie(s) passivement.")
    logger.debug("template_summary: retour Summary(...)")
    return Summary("template", " ".join(lines), _correlations(report, ai), _recommendations(report, ai))


# -- modele local ---------------------------------------------------------------


def parse_engine(spec: str, endpoint: str | None = None) -> tuple[str, str, str]:
    """``template`` | ``ollama:MODELE`` | ``llamacpp`` -> (moteur, modele, url)."""
    logger.debug("parse_engine: spec={} endpoint={}", summarize(spec, "spec"), summarize(endpoint, "endpoint"))
    kind, _, model = spec.partition(":")
    if kind == "template":
        logger.debug("parse_engine: retour tuple")
        return "template", "", ""
    if kind not in DEFAULT_ENDPOINTS:
        logger.debug("parse_engine: refus, WriterConfigError")
        raise WriterConfigError(f"moteur inconnu {spec!r} : template, ollama:MODELE ou llamacpp.")
    if kind == "ollama" and not model:
        logger.debug("parse_engine: refus, WriterConfigError")
        raise WriterConfigError("ollama : preciser le modele (ex. ollama:llama3:8b-instruct-q4_K_M).")
    url = (endpoint or DEFAULT_ENDPOINTS[kind]).rstrip("/")
    check_local_endpoint(url)
    logger.debug("parse_engine: retour tuple")
    return kind, model, url


def check_local_endpoint(url: str) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme not in ("http", "https") or not host:
        raise WriterConfigError(f"point d'acces invalide : {url!r}.")
    try:
        local = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        logger.exception("échec dans check_local_endpoint")
        local = False
    if not local:
        raise WriterConfigError(
            f"point d'acces {host} refuse : le modele doit tourner sur cette machine "
            "(127.0.0.1, ::1 ou localhost) -- aucune donnee de capture n'est envoyee a l'exterieur."
        )


def build_prompt(facts: dict) -> str:
    logger.debug("build_prompt: facts={}", summarize(facts, "facts"))
    return (
        "Tu es analyste reseau. A partir des FAITS ci-dessous (issus d'une analyse de capture "
        "reseau par Netcross), redige en francais :\n"
        "1. un resume executif de 5 a 8 phrases pour un responsable non technique ;\n"
        "2. une section 'Correlations' reliant les constats entre eux ;\n"
        "3. une section 'Recommandations' priorisee.\n"
        "N'invente aucun fait, aucune version ni aucun identifiant CVE absent des FAITS.\n\n"
        "FAITS (JSON) :\n" + json.dumps(facts, ensure_ascii=False, indent=1)
    )


def _post_json(url: str, payload: dict, timeout: float) -> dict:
    logger.debug(
        "_post_json: url={} payload={} timeout={}",
        summarize(url, "url"),
        summarize(payload, "payload"),
        summarize(timeout, "timeout"),
    )
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 -- boucle locale verifiee
        logger.debug("_post_json: retour loads(...)")
        return json.loads(resp.read().decode("utf-8"))


def llm_generate(kind: str, model: str, url: str, prompt: str, timeout: float = LLM_TIMEOUT_S) -> str:
    logger.debug(
        "llm_generate: kind={} model={} url={} prompt={} timeout={}",
        summarize(kind, "kind"),
        summarize(model, "model"),
        summarize(url, "url"),
        summarize(prompt, "prompt"),
        summarize(timeout, "timeout"),
    )
    check_local_endpoint(url)
    if kind == "ollama":
        payload = {"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.2}}
        text = _post_json(url + "/api/generate", payload, timeout).get("response", "")
    else:
        text = _post_json(url + "/completion", {"prompt": prompt, "n_predict": 900, "temperature": 0.2}, timeout).get(
            "content", ""
        )
    if not str(text).strip():
        logger.debug("llm_generate: refus, RuntimeError")
        raise RuntimeError("reponse vide du modele")
    logger.debug("llm_generate: retour strip(...)")
    return str(text).strip()


def write_summary(
    report: Any, ai: dict | None = None, engine: str = "template", endpoint: str | None = None
) -> Summary:
    kind, model, url = parse_engine(engine, endpoint)
    base = template_summary(report, ai)
    if kind == "template":
        logger.debug("write_summary: retour base")
        return base
    try:
        text = llm_generate(kind, model, url, build_prompt(collect_facts(report, ai)))
    except (OSError, urllib.error.URLError, RuntimeError, ValueError) as exc:
        logger.exception(f"échec dans write_summary: {exc}")
        base.fallback_reason = f"modele local indisponible ({exc}) : resume par gabarit"
        logger.debug("write_summary: retour base")
        return base
    # Le texte libre du modele ; correlations/recommandations deterministes
    # conservees a cote, verifiables.
    logger.debug("write_summary: retour Summary(...)")
    return Summary(f"{kind}:{model}" if model else kind, text, base.correlations, base.recommendations)
