"""
pcap_parser.capinfos_source -- lecture du commentaire de section pcapng
via `capinfos -k`. Meme discipline que test_ek_source.py (capinfos,
comme tshark, n'etant disponible dans aucun des environnements ou ce
projet a ete developpe jusqu'ici -- voir claude.md) : on teste
uniquement la fonction pure de parsing du texte de sortie -- avec des
fixtures capturees sur un vrai capinfos 4.2.2, voir la PR de Job 39/
issue #159 -- et l'orchestration du sous-processus via monkeypatch,
jamais un vrai binaire capinfos.
"""

import subprocess

from pcap_parser.capinfos_source import (
    _capinfos_path,
    _parse_capture_comment,
    read_capture_comment,
)

# -- fixtures : sortie reelle capturee (capinfos 4.2.2) ---------------------

# `capinfos -k` sur un pcapng commente via
# `editcap --capture-comment "Capture de test pour Job 39"`.
_STDOUT_AVEC_COMMENTAIRE = "File name:           final.pcapng\nCapture comment:     Capture de test pour Job 39\n"

# `capinfos -k` sur un pcapng SANS commentaire de section (mais avec le
# support pcapng, via `editcap -F pcapng` sans --capture-comment) : la
# ligne "Capture comment:" est entierement absente, pas presente avec une
# valeur vide.
_STDOUT_SANS_COMMENTAIRE = "File name:           base_ng.pcapng\n"

# `capinfos -k` sur un pcap CLASSIQUE (format sans support des
# commentaires) : meme sortie, au caractere pres, que le cas pcapng sans
# commentaire ci-dessus -- capinfos ne distingue pas les deux cas sur
# cette seule ligne, ce qui est exactement ce dont read_capture_comment a
# besoin (les deux doivent valoir None cote appelant, voir le test
# dedie ci-dessous).
_STDOUT_PCAP_CLASSIQUE = "File name:           base.pcapng\n"


# -- _parse_capture_comment (fonction pure) ----------------------------


def test_parse_capture_comment_present():
    assert _parse_capture_comment(_STDOUT_AVEC_COMMENTAIRE) == "Capture de test pour Job 39"


def test_parse_capture_comment_absent_pcapng_sans_commentaire():
    assert _parse_capture_comment(_STDOUT_SANS_COMMENTAIRE) is None


def test_parse_capture_comment_absent_pcap_classique():
    assert _parse_capture_comment(_STDOUT_PCAP_CLASSIQUE) is None


def test_parse_capture_comment_chaine_vide():
    # capinfos en echec (fichier introuvable) ne produit rien sur stdout
    # -- voir test_read_capture_comment_fichier_introuvable_ne_leve_pas
    # plus bas pour le cas complet avec code de retour non nul.
    assert _parse_capture_comment("") is None


def test_parse_capture_comment_ligne_vide_apres_le_prefixe():
    # Cas limite jamais observe en pratique (capinfos rejette un
    # commentaire vide a l'ecriture, editcap --capture-comment ""
    # produit un fichier SANS la ligne du tout plutot qu'une ligne vide),
    # mais reste tolerant par symetrie avec le reste de ce projet : une
    # ligne "Capture comment:" sans texte utile ne doit pas produire une
    # chaine vide plutot que None.
    assert _parse_capture_comment("Capture comment:     \n") is None


def test_parse_capture_comment_ignore_les_autres_lignes():
    stdout = "File name:           x.pcapng\nFile type:            Wireshark/... - pcapng\nCapture comment:     ok\n"
    assert _parse_capture_comment(stdout) == "ok"


# -- _capinfos_path -------------------------------------------------------


def test_capinfos_path_absent_renvoie_none(monkeypatch):
    # Contrairement a pcap_parser.ek_source._tshark_path(), ne leve
    # jamais si l'executable est absent -- voir la docstring de
    # _capinfos_path (capinfos est facultatif, pas central au pipeline).
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert _capinfos_path() is None


def test_capinfos_path_present(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capinfos")
    assert _capinfos_path() == "/usr/bin/capinfos"


# -- read_capture_comment (orchestration, sous-processus simule) ------------


def test_read_capture_comment_capinfos_absent(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert read_capture_comment("quelconque.pcapng") is None


def test_read_capture_comment_capinfos_installe(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capinfos")

    def fake_run(args, capture_output, text, timeout):
        assert args == ["/usr/bin/capinfos", "-k", "quelconque.pcapng"]
        assert capture_output is True
        assert text is True
        return subprocess.CompletedProcess(args, 0, stdout=_STDOUT_AVEC_COMMENTAIRE, stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    assert read_capture_comment("quelconque.pcapng") == "Capture de test pour Job 39"


def test_read_capture_comment_pas_de_commentaire(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capinfos")
    monkeypatch.setattr(
        "subprocess.run",
        lambda args, **kw: subprocess.CompletedProcess(args, 0, stdout=_STDOUT_SANS_COMMENTAIRE, stderr=""),
    )
    assert read_capture_comment("base_ng.pcapng") is None


def test_read_capture_comment_fichier_introuvable_ne_leve_pas(monkeypatch):
    # Fichier absent/illisible : capinfos sort en erreur (code de retour
    # non nul, message sur stderr) mais ne produit rien sur stdout
    # concernant un commentaire -- verifie empiriquement (capinfos
    # 4.2.2). Pas d'exception cote read_capture_comment : juste None,
    # indiscernable du cas normal "pas de commentaire".
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capinfos")
    monkeypatch.setattr(
        "subprocess.run",
        lambda args, **kw: subprocess.CompletedProcess(
            args, 2, stdout="", stderr='capinfos: The file "x.pcapng" doesn\'t exist.\n'
        ),
    )
    assert read_capture_comment("x.pcapng") is None


def test_read_capture_comment_timeout_ne_leve_pas(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capinfos")

    def fake_run(args, **kw):
        raise subprocess.TimeoutExpired(cmd=args, timeout=kw.get("timeout"))

    monkeypatch.setattr("subprocess.run", fake_run)
    assert read_capture_comment("gros_fichier.pcapng") is None


def test_read_capture_comment_erreur_os_ne_leve_pas(monkeypatch):
    # ex: capinfos disparu du disque entre shutil.which() et l'execution,
    # ou permissions insuffisantes -- meme discipline "jamais bloquant"
    # que le timeout ci-dessus.
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capinfos")

    def fake_run(args, **kw):
        raise OSError("permission refusee")

    monkeypatch.setattr("subprocess.run", fake_run)
    assert read_capture_comment("x.pcapng") is None


# -- Issue #744 : valeurs numeriques illisibles --------------------------------


def test_conversions_numeriques_illisibles_renvoient_none():
    """Lignes 247-249 et 257-259 : texte non numerique -> None."""
    from pcap_parser.capinfos_source import _integer, _number

    assert _integer("douze") is None
    assert _number("1,5 s") is None
    assert _integer("42") == 42
    assert _number("1.5") == 1.5
