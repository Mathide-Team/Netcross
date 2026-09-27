"""#441 : résumé sûr des arguments et instrumentation assistée."""

from __future__ import annotations

import enum
import importlib.util
from pathlib import Path

from netcross_core.logging_config import summarize

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "instrument_loguru.py"


def _module():
    spec = importlib.util.spec_from_file_location("instrument_loguru", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Couleur(enum.Enum):
    ROUGE = 1


def test_summarize_ne_rend_jamais_d_objet_entier_ni_secret():
    assert summarize(3) == "3"
    assert summarize(None) == "None"
    assert summarize("eth0") == "'eth0'"
    assert summarize("x" * 200) == "<str 200 car.>"
    assert summarize("rpcap://bob:pw@hote/if") == "'rpcap://***@hote/if'"
    assert summarize("s3cr3t", "password") == "***"
    assert summarize("abc", "api_key") == "***"
    assert summarize(b"\x00" * 4) == "<bytes 4 octets>"
    assert summarize(Path("/tmp/a.pcap")) == "'/tmp/a.pcap'"
    assert summarize([1, 2, 3]) == "<list 3>"
    assert summarize({"a": 1}) == "<dict 1>"
    assert summarize(_Couleur.ROUGE) == "_Couleur.ROUGE"
    assert summarize(object()) == "<object>"
    assert summarize(iter([])) == "<list_iterator>"


SOURCE = '''
from loguru import logger


def froide(chemin, n=1):
    """Doc."""
    if n < 0:
        raise ValueError("n")
    return chemin * n


def chaude(pkt):
    if pkt is None:
        raise TypeError("pkt")
    x = pkt
    return x


def boucle(packets):
    total = 0
    for pk in packets:
        total += chaude(pk)
    return total


def appelee_par_chaude():
    a = 1
    b = 2
    c = a + b
    return c
'''


def test_instrumentation_froide_et_chemin_chaud():
    mod = _module()
    hot = {"chaude", "appelee_par_chaude"}
    out, done, skipped = mod.instrument_source(SOURCE, hot)
    assert 'logger.debug("froide: chemin={} n={}", summarize(chemin, "chemin"), summarize(n, "n"))' in out
    assert 'logger.debug("froide: refus, ValueError")' in out
    # chemin chaud : aucune trace d'entrée, refus en TRACE
    assert 'logger.debug("chaude' not in out
    assert 'logger.trace("chaude: refus, TypeError")' in out
    assert "from netcross_core.logging_config import summarize" in out
    assert "appelee_par_chaude (chemin chaud)" in skipped
    assert "froide" in done
    compile(out, "<instrumente>", "exec")


def test_detection_des_chemins_chauds(tmp_path):
    mod = _module()
    (tmp_path / "m.py").write_text(SOURCE + "\nTABLE = {'x': froide}\n", encoding="utf-8")
    (tmp_path / "casse.py").write_text("def (:\n", encoding="utf-8")
    hot = mod.hot_names(tmp_path)
    assert "chaude" in hot  # appelée dans une boucle sur des paquets
    assert "froide" in hot  # référencée comme valeur de table de dispatch
    assert "boucle" not in hot


def test_module_sans_logger_inchange():
    mod = _module()
    src = "def f(a):\n    x = a\n    y = x\n    return y\n"
    out, done, skipped = mod.instrument_source(src, set())
    assert out == src and done == [] and skipped == ["module sans logger"]


def test_main_dry_run(tmp_path, capsys):
    mod = _module()
    f = tmp_path / "m.py"
    f.write_text(SOURCE, encoding="utf-8")
    assert mod.main(["--dry-run", str(f)]) == 0
    assert f.read_text(encoding="utf-8") == SOURCE
    assert "instrumentée(s)" in capsys.readouterr().out
