# ruff: noqa: E501 -- gabarits HTML/JS en ligne, lisibles tels quels
"""
netcross_report.live_html -- issue #274 : page de presentation du rapport
temps reel (voir netcross_core.live_report).

La page porte l'instantane et la fin du journal **en ligne** (elle reste
lisible ouverte en ``file://``, ou le navigateur interdit ``fetch``) et
propose deux modes de relecture quand elle est servie en HTTP
(``--live-report-serve``) :

- ``?mode=successive`` (defaut) : relit ``live.json`` et **remplace**
  l'affichage ;
- ``?mode=completive`` : relit ``live.jsonl`` et **ajoute** uniquement les
  lignes nouvelles (``seq`` superieur au dernier vu) -- chronologie et
  compteurs cumules cote navigateur, rien n'est jamais efface.

En ``file://``, la page se recharge simplement a chaque intervalle.
Aucune donnee n'est inseree en HTML brut : tout passe par ``textContent``.
"""

from __future__ import annotations

import json

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

_STYLE = """
body{font-family:system-ui,sans-serif;margin:1.5rem;color:#1d2433;background:#f7f8fa}
h1{font-size:1.3rem;margin:0 0 .3rem}h2{font-size:1.05rem;margin:1.4rem 0 .4rem}
table{border-collapse:collapse;background:#fff;min-width:40%}td,th{border:1px solid #d8dce3;padding:.25rem .6rem;
text-align:left;font-variant-numeric:tabular-nums}th{background:#eef1f5}
#etat{color:#555}#etat.final{color:#0a6b2d;font-weight:600}.erreur{color:#a4161a}
nav a{margin-right:1rem}nav a.actif{font-weight:700;text-decoration:none;color:#1d2433}
ul{padding-left:1.2rem}
"""

_SCRIPT = r"""
(function () {
  const INTERVAL = %(interval)d * 1000;
  const inline = JSON.parse(document.getElementById("netcross-live").textContent);
  const params = new URLSearchParams(location.search);
  const mode = params.get("mode") === "completive" ? "completive" : "successive";
  const served = location.protocol === "http:" || location.protocol === "https:";
  document.querySelectorAll("nav a").forEach(a => a.classList.toggle("actif", a.dataset.mode === mode));
  document.getElementById("mode").textContent = mode === "completive"
    ? "relecture completive (journal live.jsonl, ajouts seuls)"
    : "relecture successive (instantane live.json, remplace)";

  function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = String(text); if (cls) e.className = cls; return e; }
  function row(tbody, cells, cls) { const tr = el("tr", undefined, cls); cells.forEach(c => tr.appendChild(el("td", c))); tbody.appendChild(tr); }
  function fmtBytes(n) { const u = ["o", "Ko", "Mo", "Go", "To"]; let i = 0; while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; } return n.toFixed(i ? 1 : 0) + " " + u[i]; }
  function describe(e) {
    const who = e.point ? "[" + e.point + "] " : "";
    switch (e.type) {
      case "nouvel_hote": return who + "nouvel hote " + e.host;
      case "nouveaux_hotes_nombreux": return e.count + " autre(s) nouvel(aux) hote(s) (detail omis)";
      case "point_silencieux": return who + "aucun paquet depuis le dernier releve";
      case "point_repris": return who + "trafic repris";
      case "pic_de_debit": return who + "pic de debit : " + e.pps + " paquets/s (moyenne " + e.moyenne + ")";
      default: return who + e.type.replace(/_/g, " ") + (e.detail ? " -- " + e.detail : "");
    }
  }
  function setState(seq, t, final) {
    const s = document.getElementById("etat");
    s.textContent = (final ? "Capture terminee" : "Capture en cours") + " -- releve n" + seq + " a " + t;
    s.classList.toggle("final", !!final);
  }
  function addEvents(events) {
    const ul = document.getElementById("evenements");
    events.forEach(e => ul.insertBefore(el("li", (e.t || "") + "  " + describe(e)), ul.firstChild));
  }

  function renderSnapshot(s) {
    setState(s.seq, s.generated_at, s.final);
    document.getElementById("totaux").textContent =
      s.totals.packets + " paquet(s), " + fmtBytes(s.totals.bytes) + ", " + s.totals.hosts + " hote(s), depuis " + s.started_at;
    const pts = document.querySelector("#points tbody"); pts.replaceChildren();
    Object.entries(s.points).forEach(([label, p]) => row(pts,
      [label, p.status + (p.error ? " (" + p.error + ")" : ""), p.packets, fmtBytes(p.bytes), p.pps, fmtBytes(p.bps / 8) + "/s", p.retransmissions],
      p.status === "erreur" ? "erreur" : undefined));
    const pr = document.querySelector("#protocoles tbody"); pr.replaceChildren();
    Object.entries(s.protocols).forEach(([k, v]) => row(pr, [k, v]));
    const cv = document.querySelector("#conversations tbody"); cv.replaceChildren();
    s.top_conversations.forEach(c => row(cv, [c.src, c.dst, c.proto, fmtBytes(c.bytes)]));
    document.getElementById("evenements").replaceChildren();
    addEvents(s.last_events);
  }

  // Mode completif : etat reconstruit par cumul des lignes du journal.
  let lastSeq = 0; const cumul = {};
  function applyJournal(lines) {
    const tl = document.querySelector("#chronologie tbody");
    let final = false;
    lines.filter(j => j.seq > lastSeq).forEach(j => {
      lastSeq = j.seq; final = final || j.final;
      Object.entries(j.points).forEach(([label, d]) => {
        const c = cumul[label] || (cumul[label] = { packets: 0, bytes: 0 });
        c.packets += d.packets; c.bytes += d.bytes;
        row(tl, [j.seq, j.t, label, "+" + d.packets, "+" + fmtBytes(d.bytes), d.pps]);
      });
      addEvents(j.events);
      setState(j.seq, j.t, j.final);
    });
    const pts = document.querySelector("#points tbody"); pts.replaceChildren();
    Object.entries(cumul).forEach(([label, c]) => row(pts, [label, final ? "arrete" : "capture", c.packets, fmtBytes(c.bytes), "", "", ""]));
    return final;
  }

  let timer = null;
  function stop() { if (timer) clearInterval(timer); }
  async function poll() {
    try {
      if (mode === "completive") {
        const text = await (await fetch("live.jsonl", { cache: "no-store" })).text();
        const lines = [];
        text.split("\n").forEach(l => { if (l.trim()) { try { lines.push(JSON.parse(l)); } catch (_e) { /* ligne en cours d'ecriture */ } } });
        if (applyJournal(lines)) stop();
      } else {
        const s = await (await fetch("live.json", { cache: "no-store" })).json();
        renderSnapshot(s);
        if (s.final) stop();
      }
    } catch (_e) { /* releve suivant */ }
  }

  document.getElementById("chrono-section").hidden = mode !== "completive";
  if (mode === "completive") { applyJournal(inline.journal); } else { renderSnapshot(inline.snapshot); }
  if (inline.snapshot.final) return;
  if (served) { timer = setInterval(poll, INTERVAL); }
  else { setTimeout(() => location.reload(), INTERVAL); }
})();
"""

_BODY = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
<title>Netcross -- rapport temps reel</title><style>%(style)s</style></head>
<body>
<h1>Netcross -- rapport temps reel</h1>
<p id="etat"></p><p id="totaux"></p>
<nav><a href="?mode=successive" data-mode="successive">Relecture successive</a>
<a href="?mode=completive" data-mode="completive">Relecture completive</a> <small id="mode"></small></nav>
<h2>Points de capture</h2>
<table id="points"><thead><tr><th>Point</th><th>Etat</th><th>Paquets</th><th>Volume</th><th>Paquets/s</th>
<th>Debit</th><th>Retransmissions</th></tr></thead><tbody></tbody></table>
<section id="chrono-section"><h2>Chronologie</h2>
<table id="chronologie"><thead><tr><th>Releve</th><th>Heure</th><th>Point</th><th>Paquets</th><th>Volume</th>
<th>Paquets/s</th></tr></thead><tbody></tbody></table></section>
<h2>Evenements</h2><ul id="evenements"></ul>
<h2>Protocoles</h2><table id="protocoles"><thead><tr><th>Protocole</th><th>Paquets</th></tr></thead><tbody></tbody></table>
<h2>Principales conversations</h2>
<table id="conversations"><thead><tr><th>Source</th><th>Destination</th><th>Protocole</th><th>Volume</th></tr></thead>
<tbody></tbody></table>
<script type="application/json" id="netcross-live">%(data)s</script>
<script>%(script)s</script>
</body></html>
"""


def _inline_json(obj) -> str:
    """JSON sur pour un <script type=application/json> : ``<``, ``>`` et
    ``&`` echappes, donc aucune sequence ``</script>`` possible."""
    logger.debug("_inline_json: retour json.dumps(obj, ensure_ascii=False, sep…(…)")
    return (
        json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def render_live_html(snapshot: dict, journal: list[dict], interval: float) -> str:
    logger.debug("render_live_html: retour _BODY % ('style': _STYLE, 'data': _inline_json(('…")
    return _BODY % {
        "style": _STYLE,
        "data": _inline_json({"snapshot": snapshot, "journal": journal}),
        "script": _SCRIPT % {"interval": max(1, round(interval))},
    }
