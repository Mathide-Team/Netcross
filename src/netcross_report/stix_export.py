"""
netcross_report.stix_export -- export STIX 2.1 des constats de securite
(issue #279, sous-issue de #170).

STIX n'est pas un format de log mais un graphe d'objets types et relies.
La question de fond est la suivante : **un constat Netcross n'est pas un
indicateur de compromission**. Un ``indicator`` STIX affirme « ce motif
signale une activite malveillante », une affirmation partageable ; Netcross
observe, le plus souvent. D'ou la repartition :

=============================  ==========================================
Constat Netcross               Objets STIX
=============================  ==========================================
service + version detectes     ``observed-data`` -> ``ipv4-addr``/``ipv6-addr``,
                               ``software``, ``network-traffic`` (si port)
CVE confirmee                  ``vulnerability`` + ``relationship`` « has »
                               depuis le ``software``
signature d'exploit            ``indicator`` (seul cas : le motif signale
                               bien une activite malveillante)
autre anomalie avec hote       ``observed-data`` + ``note`` (l'analyse)
autre anomalie sans hote       ``note`` rattachee au ``report``
=============================  ==========================================

Aucun constat d'observation ne produit d'``indicator``.

Determinisme : un bundle exporte deux fois depuis la meme capture est
identique octet pour octet.

- identifiants des SCO : UUID v5 dans l'espace de noms STIX
  (``00abedb4-...``) sur les proprietes contributives definies par la
  specification (§2.9) -- deux outils conformes produisent le meme id ;
- identifiants des SDO/SRO : UUID v5 dans un espace de noms Netcross, derive
  du contenu de l'objet (jamais ``uuid4``) ;
- horodatages : ceux de la capture (``observed_from``/``observed_until``),
  jamais l'heure de l'export ; a defaut, l'epoque Unix ;
- objets tries par identifiant, JSON a cles triees.

Le JSON est produit a la main (peu d'objets, stables) : aucune dependance
d'execution. La conformite au schema OASIS est verifiee dans les tests par
``stix2-validator`` (dependance de developpement).

Attention : un bundle STIX publie sur une plateforme partagee (MISP,
OpenCTI) sort des donnees de topologie interne (adresses, services,
versions). Voir docs/siem-export.md.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import uuid
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Report

logger = get_logger(__name__)

SPEC_VERSION = "2.1"

# Espace de noms impose par STIX 2.1 (§2.9) pour les identifiants de SCO.
STIX_SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-4ca2-8a3c-1ad8e8b8f48d")
# Espace de noms Netcross pour les SDO/SRO (arbitraire mais FIGE : le changer
# casserait la deduplication entre deux exports).
NETCROSS_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/MathildeDec/Netcross/stix")

# Horodatage fixe de l'identite « Netcross » (constante d'un export a l'autre).
_IDENTITY_CREATED = "2026-01-01T00:00:00.000Z"
_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)

# Confiance (0-100, echelle STIX) -- une confiance, pas une severite :
# - observation sur le fil (banniere, flux) : fiable mais falsifiable
#   (une banniere se modifie) ;
# - CVE correlee par version : les retroportages de correctifs donnent des
#   faux positifs connus ;
# - signature d'exploit : une tentative observee, pas une compromission.
CONFIDENCE_OBSERVATION = 85
CONFIDENCE_CVE_BY_VERSION = 60
CONFIDENCE_EXPLOIT = {"critique": 80, "elevee": 70, "moyenne": 50, "faible": 30}
_DEFAULT_EXPLOIT_CONFIDENCE = 30

# Proprietes contributives des SCO (STIX 2.1, §6).
_SCO_ID_PROPERTIES: dict[str, tuple[str, ...]] = {
    "ipv4-addr": ("value",),
    "ipv6-addr": ("value",),
    "software": ("name", "cpe", "swid", "vendor", "version"),
    "network-traffic": ("start", "end", "src_ref", "dst_ref", "src_port", "dst_port", "protocols", "extensions"),
}


def _canonical(obj: Any) -> str:
    """Serialisation canonique (approximation de JCS, RFC 8785, suffisante
    pour des chaines/entiers/listes) : cles triees, sans espaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sco_id(stix_type: str, props: Mapping[str, Any]) -> str:
    contributing = {k: props[k] for k in _SCO_ID_PROPERTIES[stix_type] if k in props}
    return f"{stix_type}--{uuid.uuid5(STIX_SCO_NAMESPACE, _canonical(contributing))}"


def _sdo_id(stix_type: str, content: Mapping[str, Any]) -> str:
    return f"{stix_type}--{uuid.uuid5(NETCROSS_NAMESPACE, stix_type + _canonical(content))}"


def format_timestamp(when: _dt.datetime) -> str:
    """Horodatage STIX : UTC, precision milliseconde, suffixe ``Z``."""
    logger.debug("format_timestamp: when={}", summarize(when, "when"))
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.UTC)
    when = when.astimezone(_dt.UTC)
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def identity_object() -> dict[str, Any]:
    """L'identite « Netcross » a laquelle renvoie chaque ``created_by_ref``."""
    logger.debug("identity_object()")
    content = {"name": "Netcross", "identity_class": "system"}
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": _sdo_id("identity", content),
        "created": _IDENTITY_CREATED,
        "modified": _IDENTITY_CREATED,
        **content,
    }


def _escape_pattern(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


class _Builder:
    """Accumule les objets du bundle, dedoublonnes par identifiant."""

    def __init__(self, first: str, last: str) -> None:
        logger.debug("_Builder.__init__: first={} last={}", summarize(first, "first"), summarize(last, "last"))
        self.first = first
        self.last = last
        self.identity = identity_object()
        self.objects: dict[str, dict[str, Any]] = {self.identity["id"]: self.identity}
        self.skipped: dict[str, int] = {}

    def add(self, obj: dict[str, Any]) -> str:
        self.objects.setdefault(obj["id"], obj)
        return obj["id"]

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def sdo(self, stix_type: str, content: dict[str, Any], *, confidence: int | None = None) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "type": stix_type,
            "spec_version": SPEC_VERSION,
            "id": _sdo_id(stix_type, content),
            "created": self.first,
            "modified": self.first,
            "created_by_ref": self.identity["id"],
            **content,
        }
        if confidence is not None:
            obj["confidence"] = confidence
        return obj

    # -- SCO ------------------------------------------------------------

    def ip(self, value: Any) -> str | None:
        try:
            addr = ipaddress.ip_address(str(value))
        except ValueError:
            logger.exception("échec dans ip")
            return None
        stix_type = "ipv4-addr" if addr.version == 4 else "ipv6-addr"
        props = {"value": str(addr)}
        return self.add({"type": stix_type, "spec_version": SPEC_VERSION, "id": _sco_id(stix_type, props), **props})

    def software(self, name: str, version: Any) -> str:
        props: dict[str, Any] = {"name": str(name)}
        if version:
            props["version"] = str(version)
        return self.add({"type": "software", "spec_version": SPEC_VERSION, "id": _sco_id("software", props), **props})

    def traffic(
        self, *, dst_ref: str, dst_port: Any = None, src_ref: str | None = None, protocol: Any = None
    ) -> str | None:
        props: dict[str, Any] = {"dst_ref": dst_ref, "protocols": ["tcp", str(protocol).lower()] if protocol else []}
        if src_ref:
            props["src_ref"] = src_ref
        if isinstance(dst_port, int) and 0 <= dst_port <= 65535:
            props["dst_port"] = dst_port
        if not props["protocols"]:
            # `protocols` est obligatoire : sans protocole applicatif connu, la
            # couche reseau seule (ipv4/ipv6) est la seule affirmation sure.
            props["protocols"] = ["ipv6" if dst_ref.startswith("ipv6-addr") else "ipv4"]
        return self.add(
            {"type": "network-traffic", "spec_version": SPEC_VERSION, "id": _sco_id("network-traffic", props), **props}
        )

    def observed(self, refs: list[str], point: Any) -> str:
        content: dict[str, Any] = {
            "first_observed": self.first,
            "last_observed": self.last,
            "number_observed": 1,
            "object_refs": sorted(set(refs)),
        }
        if point:
            content["x_netcross_point"] = str(point)
        return self.add(self.sdo("observed-data", content, confidence=CONFIDENCE_OBSERVATION))


def _service_refs(b: _Builder, fp: Mapping[str, Any]) -> list[str]:
    logger.debug("_service_refs: b={} fp={}", summarize(b, "b"), summarize(fp, "fp"))
    software_ref = b.software(fp["service"], fp.get("version"))
    refs = [software_ref]
    host_ref = b.ip(fp.get("host")) if fp.get("host") else None
    if host_ref:
        refs.append(host_ref)
        traffic_ref = b.traffic(dst_ref=host_ref, dst_port=fp.get("port"), protocol=fp.get("protocol"))
        if traffic_ref:
            refs.append(traffic_ref)
    return refs


def _add_services(b: _Builder, fingerprints: Iterable[Mapping[str, Any]]) -> None:
    logger.debug("_add_services: b={} fingerprints={}", summarize(b, "b"), summarize(fingerprints, "fingerprints"))
    for fp in fingerprints:
        if not fp.get("service"):
            b.skip("service sans nom")
            continue
        b.observed(_service_refs(b, fp), fp.get("point"))


def _add_cve(b: _Builder, f: Mapping[str, Any]) -> None:
    cve_id = f.get("cve_id")
    if not cve_id:
        b.skip("cve sans identifiant")
        return
    content: dict[str, Any] = {
        "name": str(cve_id),
        "external_references": [{"source_name": "cve", "external_id": str(cve_id)}],
    }
    if f.get("detail"):
        content["description"] = str(f["detail"])
    if isinstance(f.get("cvss"), int | float):
        content["x_netcross_cvss"] = float(f["cvss"])
    vuln_ref = b.add(b.sdo("vulnerability", content, confidence=CONFIDENCE_CVE_BY_VERSION))
    if not f.get("service"):
        return
    # le software est celui du service detecte (meme id deterministe) ; son
    # observation est deja portee par l'observed-data du service
    software_ref = b.software(f["service"], f.get("version"))
    rel = {"relationship_type": "has", "source_ref": software_ref, "target_ref": vuln_ref}
    b.add(b.sdo("relationship", rel, confidence=CONFIDENCE_CVE_BY_VERSION))


def exploit_pattern(f: Mapping[str, Any]) -> str | None:
    """Motif STIX d'un constat d'exploit : le trafic source -> cible observe.
    None si ni la source ni la cible ne sont des adresses IP valides."""
    parts = []
    for key, prop in (("src", "src_ref"), ("host", "dst_ref")):
        value = f.get(key)
        if value is None:
            continue
        try:
            addr = ipaddress.ip_address(str(value))
        except ValueError:
            logger.exception("échec dans exploit_pattern")
            continue
        parts.append(f"network-traffic:{prop}.value = '{_escape_pattern(str(addr))}'")
    if not parts:
        return None
    port = f.get("port")
    if isinstance(port, int) and 0 <= port <= 65535:
        parts.append(f"network-traffic:dst_port = {port}")
    return "[" + " AND ".join(parts) + "]"


def _add_exploit(b: _Builder, f: Mapping[str, Any]) -> None:
    pattern = exploit_pattern(f)
    if pattern is None:
        b.skip("exploit sans adresse")
        return
    detail = str(f.get("detail") or "signature d'exploit")
    content: dict[str, Any] = {
        "name": str(f.get("signature_id") or detail)[:250],
        "description": detail,
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": b.first,
    }
    cves = f.get("cves") or []
    if cves:
        content["external_references"] = [{"source_name": "cve", "external_id": str(c)} for c in cves]
    if f.get("point"):
        content["x_netcross_point"] = str(f["point"])
    severity = str(f.get("severity") or "faible").lower()
    b.add(b.sdo("indicator", content, confidence=CONFIDENCE_EXPLOIT.get(severity, _DEFAULT_EXPLOIT_CONFIDENCE)))


def _add_anomaly(b: _Builder, f: Mapping[str, Any], orphan_notes: list[dict[str, Any]]) -> None:
    abstract = f"{f.get('category') or 'anomalie'} ({f.get('severity') or 'faible'})"
    content: dict[str, Any] = {"abstract": abstract, "content": str(f.get("detail") or abstract)}
    if f.get("point"):
        content["x_netcross_point"] = str(f["point"])
    host_ref = b.ip(f["host"]) if f.get("host") else None
    if host_ref is None:
        orphan_notes.append(content)
        return
    refs = [host_ref]
    src_ref = b.ip(f["src"]) if f.get("src") else None
    if src_ref:
        refs.append(src_ref)
    if f.get("port") is not None or src_ref:
        traffic_ref = b.traffic(dst_ref=host_ref, dst_port=f.get("port"), src_ref=src_ref)
        if traffic_ref:
            refs.append(traffic_ref)
    observed_ref = b.observed(refs, f.get("point"))
    b.add(b.sdo("note", {**content, "object_refs": [observed_ref]}, confidence=CONFIDENCE_OBSERVATION))


def to_stix_bundle(
    report: Report,
    *,
    observed_from: _dt.datetime | None = None,
    observed_until: _dt.datetime | None = None,
) -> dict[str, Any]:
    """Construit le bundle STIX 2.1 (dict) des services et constats du rapport.

    `observed_from`/`observed_until` : bornes temporelles de la capture
    (premier/dernier paquet). Elles datent TOUS les objets -- jamais
    l'heure de l'export, sinon deux exports differeraient. Absentes :
    l'epoque Unix (bundle toujours deterministe, mais date non significative).
    """
    logger.debug(
        "to_stix_bundle: report={} observed_from={} observed_until={}",
        summarize(report, "report"),
        summarize(observed_from, "observed_from"),
        summarize(observed_until, "observed_until"),
    )
    first = format_timestamp(observed_from or _EPOCH)
    last = format_timestamp(observed_until or observed_from or _EPOCH)
    b = _Builder(first, last)
    orphan_notes: list[dict[str, Any]] = []

    _add_services(b, report.service_fingerprints)
    for f in report.security_findings:
        category = f.get("category")
        if category == "cve":
            _add_cve(b, f)
        elif category == "exploit":
            _add_exploit(b, f)
        else:
            _add_anomaly(b, f, orphan_notes)

    if len(b.objects) > 1 or orphan_notes or b.skipped:
        report_content: dict[str, Any] = {
            "name": "Netcross -- constats de securite",
            "report_types": ["observed-data"],
            "published": last,
            "object_refs": sorted(oid for oid in b.objects if oid != b.identity["id"]) or [b.identity["id"]],
        }
        if b.skipped:
            # ce qui n'a pas pu etre represente (propriete personnalisee x_)
            report_content["x_netcross_skipped"] = dict(sorted(b.skipped.items()))
        report_ref = b.add(b.sdo("report", report_content))
        for content in orphan_notes:
            b.add(b.sdo("note", {**content, "object_refs": [report_ref]}, confidence=CONFIDENCE_OBSERVATION))

    objects = sorted(b.objects.values(), key=lambda o: o["id"])
    bundle_id = f"bundle--{uuid.uuid5(NETCROSS_NAMESPACE, _canonical([o['id'] for o in objects]))}"
    return {"type": "bundle", "id": bundle_id, "objects": objects}


def export_stix(
    report: Report,
    *,
    observed_from: _dt.datetime | None = None,
    observed_until: _dt.datetime | None = None,
) -> str:
    """Bundle STIX 2.1 serialise (JSON indente, cles triees, determinisme
    octet pour octet)."""
    logger.debug(
        "export_stix: report={} observed_from={} observed_until={}",
        summarize(report, "report"),
        summarize(observed_from, "observed_from"),
        summarize(observed_until, "observed_until"),
    )
    bundle = to_stix_bundle(report, observed_from=observed_from, observed_until=observed_until)
    return json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_stix(
    report: Report,
    output_path: str | Path,
    *,
    observed_from: _dt.datetime | None = None,
    observed_until: _dt.datetime | None = None,
) -> str:
    """Ecrit le bundle dans un fichier ; retourne son chemin absolu."""
    logger.debug(
        "write_stix: report={} output_path={} observed_from={} observed_until={}",
        summarize(report, "report"),
        summarize(output_path, "output_path"),
        summarize(observed_from, "observed_from"),
        summarize(observed_until, "observed_until"),
    )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(export_stix(report, observed_from=observed_from, observed_until=observed_until), encoding="utf-8")
    return str(path.resolve())
