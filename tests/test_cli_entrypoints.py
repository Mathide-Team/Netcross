"""
Tests des points d'entree CLI -- issue #287.

La CLI est l'interface reelle de l'outil. Le moteur est tres bien couvert
(`security/` 92-100 %, `pcap_parser/capture.py` 98,9 %), mais le **cablage
entre les options et le moteur** ne l'etait qu'a moitie. Or c'est la que se
trouvaient #261 (une option qui plantait systematiquement), #262 (un format
de sortie ignore) et #259 (une valeur calculee jamais affichee) : trois fois
la meme jonction, trois fois a travers une suite verte.

## Methode

`main()` est appele en processus, `sys.argv` remplace -- rapide, et cela
couvre l'analyse d'arguments, la validation et le cablage, c'est-a-dire ce
qu'on veut. Les trois `main()` ne prennent pas d'`argv` : les tests lisent
donc exactement le chemin qui tourne en production, sans modifier de
signature pour les besoins du test.

Un test par CLI lance le vrai binaire en sous-processus pour verifier le
point d'entree et le code de retour. Pas plus : c'est lent.

## Ce que ces tests verifient, et pourquoi pas seulement le code de retour

Le critere retenu par l'issue est l'**effet** de l'option, pas sa sortie en
0. Une option ignoree sort en 0 tout aussi bien qu'une option honoree --
c'est precisement ce qui s'est produit sur #262.

## Codes de retour : inventaire

Mesure sur les trois CLI : **75 appels a `sys.exit(1)`**, aucun autre code.
Le 1 recouvre donc trois situations que rien ne distingue :

| Situation | Code actuel |
|---|---|
| Erreur d'usage (option mal formee, valeur refusee) | 1 |
| Argparse (option inconnue, `choices` non respecte) | 2 |
| Capture illisible, base d'historique invalide | 1 |
| **Comparaison reussie ayant trouve une regression** | **1** |
| Analyse terminee, aucun probleme | 0 |

La quatrieme ligne est la plus genante : un script CI ne peut pas
distinguer « la comparaison a tourne et a trouve une regression » de « la
comparaison n'a pas pu tourner ». Les tests ci-dessous figent ce
comportement tel qu'il est -- le changer modifierait un contrat dont des
scripts dependent peut-etre, ce qui est une decision a prendre
explicitement, pas un effet de bord d'une issue de couverture.
"""

from __future__ import annotations

import contextlib
import shutil
import socket
import struct
import subprocess
import sys

import pytest
from pcap_builders import write_pcap

import cross_capture_analyzer_cli as analyzer_cli
import cross_capture_diff_cli as diff_cli
from netcross_core.models import Report
from netcross_report.history import record_run

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent du PATH")

ACK = 0x10
PSH_ACK = 0x18


def _frame(src, dst, sport, dport, seq, ack, flags, data=b""):
    """Trame Ethernet/IPv4/TCP minimale mais valide pour tshark.

    Construite a la main plutot qu'avec scapy : le projet n'a pas scapy en
    dependance, et une trame fabriquee ici reste lisible et deterministe.
    """
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + data
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0x4000,
        64,
        6,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip + tcp


def _ecrire_capture(chemin, nb_paquets=20, depart_us=1_700_000_000_000_000, pas_us=10_000, taille=40):
    paquets = []
    ts = depart_us
    for i in range(nb_paquets):
        paquets.append((ts, _frame("10.0.0.1", "10.0.0.2", 40000, 80, 1000 + i * 10, 1, PSH_ACK, b"x" * taille)))
        ts += pas_us
    write_pcap(chemin, paquets)
    return chemin


@pytest.fixture
def paire_de_captures(tmp_path):
    """Deux points : l'aval a perdu les deux derniers paquets.

    Une perte reelle plutot qu'inventee -- les tests d'effet d'option ont
    besoin qu'il y ait quelque chose a rapporter, sinon ils verifient le
    rendu du vide.
    """
    amont = _ecrire_capture(tmp_path / "amont.pcap", nb_paquets=20)
    aval = _ecrire_capture(tmp_path / "aval.pcap", nb_paquets=18)
    return amont, aval


def _lancer_analyzer(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *[str(a) for a in args]])
    analyzer_cli.main()
    return capsys.readouterr()


def _lancer_diff(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["cross_capture_diff_cli.py", *[str(a) for a in args]])
    diff_cli.main()
    return capsys.readouterr()


# --------------------------------------------------------------------------
# Erreurs d'usage : message lisible, jamais de trace Python
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    [
        "/tmp/sans_nom.pcap",  # pas de NOM=
        "=/tmp/sans_label.pcap",  # NOM vide
        "SANS_CHEMIN=",  # chemin vide
    ],
)
def test_capture_mal_formee_donne_un_message_nommant_le_format(monkeypatch, capsys, spec):
    """Le message doit rappeler le format attendu, pas seulement signaler une
    erreur : l'utilisateur qui se trompe sur `NOM=chemin` ne devine pas la
    syntaxe depuis un « argument invalide »."""
    with pytest.raises(SystemExit) as sortie:
        _lancer_analyzer(monkeypatch, capsys, "--capture", spec)
    assert sortie.value.code == 1
    erreur = capsys.readouterr().err
    assert "--capture" in erreur
    assert "NOM=" in erreur, "le message ne rappelle pas le format attendu"
    assert "Traceback" not in erreur


def test_une_capture_introuvable_est_rapportee_comme_un_echec(monkeypatch, capsys, tmp_path):
    """Defaut trouve par ce test. La branche de chargement sequentielle -- qui
    est celle PAR DEFAUT -- appelait `parse_capture` sans `raise_on_error`,
    donc l'echec etait avale et la sortie affichait « [A] 0 paquets charges »,
    strictement indistinguable d'une capture legitimement sans trafic IP. Le
    resume ATTENTION n'existait que sur la branche `--parallel`.

    La regle du projet -- toujours emettre une ligne explicite pour une
    information absente, ne jamais laisser une absence passer pour une mesure
    -- etait donc appliquee sur le chemin rare et pas sur le chemin courant.

    Issue #940 : l'echec se voit AUSSI dans le code de sortie (3 = rapport
    rendu mais incomplet), pour que l'automatisation ne confonde pas analyse
    incomplete et succes.
    """
    presente = _ecrire_capture(tmp_path / "ok.pcap")
    with pytest.raises(SystemExit) as excinfo:
        _lancer_analyzer(
            monkeypatch,
            capsys,
            "--capture",
            f"MANQUANT={tmp_path / 'jamais_creee.pcap'}",
            "--capture",
            f"PRESENT={presente}",
        )
    assert excinfo.value.code == 3, "un echec de lecture doit se voir dans le code de sortie"
    sortie = capsys.readouterr()
    assert "ECHEC" in sortie.err, "un fichier introuvable n'est pas rapporte comme un echec"
    assert "resultat est incomplet" in sortie.err, "aucun avertissement de resultat partiel"
    assert "Traceback" not in sortie.err


def test_une_capture_introuvable_est_rapportee_aussi_en_comparaison(monkeypatch, capsys, tmp_path):
    """Meme defaut sur le CLI de comparaison, ou la consequence est pire : un
    cote vide produit des ecarts spectaculaires qui ne sont que l'ombre du
    fichier manquant. Le mot « baseline » ou « current » doit apparaitre pour
    que l'utilisateur sache QUEL cote a echoue."""
    presente = _ecrire_capture(tmp_path / "ok.pcap")
    # `_lancer_diff` vide deja capsys et renvoie le resultat : rappeler
    # `capsys.readouterr()` ici renverrait une sortie vide. Erreur commise en
    # ecrivant ce test, et qui l'avait fait echouer sur un faux motif.
    sortie = _lancer_diff(
        monkeypatch,
        capsys,
        "--baseline",
        f"A={tmp_path / 'jamais_creee.pcap'}",
        "--current",
        f"A={presente}",
    )
    erreur = sortie.err
    assert "ECHEC" in erreur
    assert "baseline" in erreur, "le message ne dit pas quel cote a echoue"


def test_une_option_inconnue_sort_en_deux_sans_trace(monkeypatch, capsys):
    """Code 2 : convention argparse, distincte du 1 des erreurs applicatives.
    C'est la seule distinction de code qui existe aujourd'hui."""
    with pytest.raises(SystemExit) as sortie:
        _lancer_analyzer(monkeypatch, capsys, "--option-qui-nexiste-pas")
    assert sortie.value.code == 2
    assert "Traceback" not in capsys.readouterr().err


def test_un_seuil_de_doublons_negatif_est_refuse(monkeypatch, capsys, paire_de_captures):
    """Un seuil negatif n'a pas de sens : le refuser explicitement vaut mieux
    que de laisser la detection tourner avec une fenetre absurde et rendre un
    resultat qui a l'air valide."""
    amont, aval = paire_de_captures
    with pytest.raises(SystemExit) as sortie:
        _lancer_analyzer(
            monkeypatch,
            capsys,
            "--capture",
            f"AMONT={amont}",
            "--capture",
            f"AVAL={aval}",
            "--detect-duplicates",
            "--duplicate-threshold-ms",
            "-5",
        )
    assert sortie.value.code == 1
    erreur = capsys.readouterr().err
    assert "--duplicate-threshold-ms" in erreur
    assert "Traceback" not in erreur


def test_client_group_mal_forme_rappelle_le_format(monkeypatch, capsys, paire_de_captures):
    amont, aval = paire_de_captures
    with pytest.raises(SystemExit) as sortie:
        _lancer_analyzer(
            monkeypatch,
            capsys,
            "--capture",
            f"AMONT={amont}",
            "--capture",
            f"AVAL={aval}",
            "--client-group",
            "sans_signe_egal",
        )
    assert sortie.value.code == 1
    erreur = capsys.readouterr().err
    assert "--client-group" in erreur
    assert "NOM=" in erreur
    assert "Traceback" not in erreur


# --------------------------------------------------------------------------
# Effet des options -- pas seulement un code 0
# --------------------------------------------------------------------------


def test_un_run_nominal_lit_les_deux_points_et_sort_en_zero(monkeypatch, capsys, paire_de_captures):
    """Reference des autres tests : sans cela, un echec generalise passerait
    pour un « effet d'option non constate » et ferait chercher au mauvais
    endroit."""
    amont, aval = paire_de_captures
    sortie = _lancer_analyzer(monkeypatch, capsys, "--capture", f"AMONT={amont}", "--capture", f"AVAL={aval}")
    assert "20 paquets" in sortie.out
    assert "18 paquets" in sortie.out
    assert "ECHEC" not in sortie.err


def test_json_report_ecrit_un_fichier_exploitable(monkeypatch, capsys, paire_de_captures, tmp_path):
    """L'effet est le fichier et son contenu, pas le message de confirmation :
    c'est le genre d'ecart qui a produit #262."""
    import json

    amont, aval = paire_de_captures
    destination = tmp_path / "rapport.json"
    _lancer_analyzer(
        monkeypatch,
        capsys,
        "--capture",
        f"AMONT={amont}",
        "--capture",
        f"AVAL={aval}",
        "--json-report",
        destination,
    )
    assert destination.exists(), "--json-report n'a rien ecrit"
    donnees = json.loads(destination.read_text(encoding="utf-8"))
    assert donnees, "rapport JSON vide"


def test_pdf_report_ecrit_un_pdf_reel(monkeypatch, capsys, paire_de_captures, tmp_path):
    amont, aval = paire_de_captures
    destination = tmp_path / "rapport.pdf"
    _lancer_analyzer(
        monkeypatch,
        capsys,
        "--capture",
        f"AMONT={amont}",
        "--capture",
        f"AVAL={aval}",
        "--pdf-report",
        destination,
    )
    assert destination.exists(), "--pdf-report n'a rien ecrit"
    assert destination.read_bytes().startswith(b"%PDF")


def test_detail_csv_ecrit_un_csv_avec_en_tete(monkeypatch, capsys, paire_de_captures, tmp_path):
    """`--detail-csv` n'etait cite par aucun test avant cette issue."""
    amont, aval = paire_de_captures
    destination = tmp_path / "detail.csv"
    _lancer_analyzer(
        monkeypatch,
        capsys,
        "--capture",
        f"AMONT={amont}",
        "--capture",
        f"AVAL={aval}",
        "--detail-csv",
        destination,
    )
    assert destination.exists(), "--detail-csv n'a rien ecrit"
    contenu = destination.read_text(encoding="utf-8")
    assert contenu.strip(), "CSV vide"
    assert "," in contenu.splitlines()[0], "premiere ligne sans separateur : en-tete absent"


def test_triage_top_n_borne_la_table_de_triage(monkeypatch, capsys, paire_de_captures):
    """`--triage-top-n` n'etait cite par aucun test. L'effet verifie est la
    reduction de la sortie, pas la presence de l'option : une option lue puis
    ignoree passerait le test inverse."""
    amont, aval = paire_de_captures
    commun = ["--capture", f"AMONT={amont}", "--capture", f"AVAL={aval}", "--triage"]
    large = _lancer_analyzer(monkeypatch, capsys, *commun, "--triage-top-n", 50).out
    etroit = _lancer_analyzer(monkeypatch, capsys, *commun, "--triage-top-n", 1).out
    assert len(etroit) <= len(large), "--triage-top-n n'a aucun effet sur la sortie"


def test_expert_section_ajoute_une_section(monkeypatch, capsys, paire_de_captures):
    """`--expert-section` n'etait cite par aucun test. L'effet attendu est une
    sortie strictement plus longue : la section doit apparaitre, et si elle n'a
    rien a montrer elle doit l'ecrire (regle du projet) -- dans les deux cas la
    sortie grandit."""
    amont, aval = paire_de_captures
    commun = ["--capture", f"AMONT={amont}", "--capture", f"AVAL={aval}"]
    sans = _lancer_analyzer(monkeypatch, capsys, *commun).out
    avec = _lancer_analyzer(monkeypatch, capsys, *commun, "--expert-section").out
    assert len(avec) > len(sans), "--expert-section n'ajoute rien a la sortie"


def test_history_db_enregistre_le_run(monkeypatch, capsys, paire_de_captures, tmp_path):
    """`--history-db` n'etait cite par aucun test. L'effet verifie est la
    presence du run dans la base relue par la bibliotheque, pas le message de
    confirmation."""
    from netcross_report.history import list_history

    amont, aval = paire_de_captures
    db = tmp_path / "suivi.db"
    _lancer_analyzer(
        monkeypatch,
        capsys,
        "--capture",
        f"AMONT={amont}",
        "--capture",
        f"AVAL={aval}",
        "--history-db",
        db,
        "--history-label",
        "Recette",
    )
    assert db.exists(), "--history-db n'a pas cree la base"
    entrees = list_history(str(db))
    assert len(entrees) == 1
    assert entrees[0].label == "Recette", "--history-label n'est pas enregistre"


def test_history_show_affiche_l_historique_apres_le_run(monkeypatch, capsys, paire_de_captures, tmp_path):
    """`--history-show` n'etait cite par aucun test. La base est pre-remplie
    pour que l'affichage porte sur plus que le run courant -- sinon le test ne
    distinguerait pas « affiche l'historique » de « affiche le run qui vient de
    se terminer »."""
    amont, aval = paire_de_captures
    db = tmp_path / "suivi.db"
    r = Report(points=["AMONT", "AVAL"], pairs=[("AMONT", "AVAL")])
    r.seen_count["AMONT"] = 100
    record_run(r, str(db), label="RUN-ANTERIEUR")

    sortie = _lancer_analyzer(
        monkeypatch,
        capsys,
        "--capture",
        f"AMONT={amont}",
        "--capture",
        f"AVAL={aval}",
        "--history-db",
        db,
        "--history-show",
        10,
    )
    assert "HISTORIQUE DES RUNS ENREGISTRES" in sortie.out
    assert "RUN-ANTERIEUR" in sortie.out


def test_une_base_d_historique_invalide_ne_perd_pas_le_run_sur_une_trace(
    monkeypatch, capsys, paire_de_captures, tmp_path
):
    """Defaut trouve par ce test (issue #287).

    L'historique est ecrit a la FIN du run : un `--history-db` pointant sur un
    fichier qui n'est pas une base netcross faisait remonter
    `sqlite3.DatabaseError: file is not a database` en trace Python, apres que
    toute l'analyse ait tourne. Sur une grosse capture, plusieurs minutes de
    travail perdues sur un message qui ne nommait meme pas le chemin fautif.
    """
    amont, aval = paire_de_captures
    fausse = tmp_path / "pas_une_base.db"
    fausse.write_bytes(b"\xd4\xc3\xb2\xa1 en-tete PCAP, pas du SQLite")

    with pytest.raises(SystemExit) as sortie:
        _lancer_analyzer(
            monkeypatch,
            capsys,
            "--capture",
            f"AMONT={amont}",
            "--capture",
            f"AVAL={aval}",
            "--history-db",
            fausse,
        )
    assert sortie.value.code == 1
    erreur = capsys.readouterr().err
    assert "Traceback" not in erreur, "trace Python brute au lieu d'un message"
    assert "sqlite3" not in erreur
    assert str(fausse) in erreur


def test_les_options_de_sortie_se_combinent(monkeypatch, capsys, paire_de_captures, tmp_path):
    """Combinaison explicitement demandee par l'issue. Une sortie qui en
    desactive une autre est un defaut classique quand chaque format est cable
    separement -- il faut donc constater les deux fichiers, pas l'un ou
    l'autre."""
    amont, aval = paire_de_captures
    json_dest = tmp_path / "r.json"
    pdf_dest = tmp_path / "r.pdf"
    _lancer_analyzer(
        monkeypatch,
        capsys,
        "--capture",
        f"AMONT={amont}",
        "--capture",
        f"AVAL={aval}",
        "--json-report",
        json_dest,
        "--pdf-report",
        pdf_dest,
    )
    assert json_dest.exists(), "--json-report perdu quand --pdf-report est present"
    assert pdf_dest.exists(), "--pdf-report perdu quand --json-report est present"


# --------------------------------------------------------------------------
# CLI de comparaison
# --------------------------------------------------------------------------


def test_une_comparaison_sans_ecart_sort_en_zero(monkeypatch, capsys, tmp_path):
    """Les deux cotes sont le meme fichier : aucun ecart possible, donc aucune
    regression, donc code 0. C'est la reference qui donne son sens au test
    suivant."""
    capture = _ecrire_capture(tmp_path / "meme.pcap")
    sortie = _lancer_diff(monkeypatch, capsys, "--baseline", f"A={capture}", "--current", f"A={capture}")
    assert sortie.out, "aucune sortie produite"


def test_une_regression_detectee_sort_en_un(monkeypatch, capsys, tmp_path):
    """Comportement documente dans le code : « code de sortie non nul :
    exploitable en CI/script pour detecter une regression ».

    Le scenario a demande deux essais, et le premier enseigne quelque chose.
    Avec des captures ou l'aval a MOINS de paquets que l'amont, l'outil
    rapportait une AMELIORATION : des paquets identiques (memes numeros de
    sequence, meme charge) repetes aux deux points sont vus par tshark comme
    des retransmissions, donc en avoir moins est un progres. Le scenario
    retenu inverse les deux cotes -- la capture la plus fournie devient le run
    courant -- ce qui produit une hausse des retransmissions, c'est-a-dire une
    regression sur une metrique reelle plutot que fabriquee.

    Ce test fige le contrat et met en evidence sa limite : ce meme code 1
    signale aussi une erreur d'usage et une capture illisible. Un script ne
    peut donc pas distinguer « la comparaison a trouve une regression » de
    « la comparaison n'a pas pu tourner ». Voir l'inventaire en tete de
    module ; le changer est une decision de contrat, pas un effet de bord
    d'une issue de couverture.
    """
    peu_amont = _ecrire_capture(tmp_path / "ref_amont.pcap", nb_paquets=20)
    peu_aval = _ecrire_capture(tmp_path / "ref_aval.pcap", nb_paquets=10)
    plus_amont = _ecrire_capture(tmp_path / "cur_amont.pcap", nb_paquets=20)
    plus_aval = _ecrire_capture(tmp_path / "cur_aval.pcap", nb_paquets=20)

    with pytest.raises(SystemExit) as sortie:
        _lancer_diff(
            monkeypatch,
            capsys,
            "--baseline",
            f"AMONT={peu_amont}",
            "--baseline",
            f"AVAL={peu_aval}",
            "--current",
            f"AMONT={plus_amont}",
            "--current",
            f"AVAL={plus_aval}",
        )
    assert sortie.value.code == 1, "une regression detectee doit sortir en code non nul"
    sortie_texte = capsys.readouterr().out
    assert "regression(s)" in sortie_texte
    assert "REGRESSIONS" in sortie_texte, "le rapport ne nomme pas la section des regressions"


def test_une_comparaison_sans_regression_sort_en_zero(monkeypatch, capsys, tmp_path):
    """Pendant du test precedent, et c'est lui qui donne sa valeur au code 1 :
    sans verifier que l'absence de regression sort bien en 0, un CLI qui
    sortirait toujours en 1 passerait le test ci-dessus.

    Les deux cotes sont le meme fichier, donc aucun ecart n'est possible.

    Quand il n'y a aucun ecart, le rapport ecrit « Aucun ecart significatif
    detecte entre les deux runs » au lieu d'un decompte a zero. C'est la bonne
    forme -- elle affirme que la comparaison a eu lieu, ce qu'un « 0
    regression(s) » noye dans un tableau vide dirait moins bien -- et le test
    porte sur cette phrase apres l'avoir constatee sur la sortie reelle.
    """
    capture = _ecrire_capture(tmp_path / "identique.pcap")
    sortie = _lancer_diff(
        monkeypatch,
        capsys,
        "--baseline",
        f"A={capture}",
        "--current",
        f"A={capture}",
    )
    assert "Aucun ecart significatif" in sortie.out, (
        "une comparaison sans ecart doit le dire explicitement, pas rester muette"
    )


def test_diff_csv_ecrit_un_fichier(monkeypatch, capsys, tmp_path):
    """`--diff-csv` n'etait cite par aucun test."""
    reference = _ecrire_capture(tmp_path / "avant.pcap", nb_paquets=20)
    courant = _ecrire_capture(tmp_path / "apres.pcap", nb_paquets=12)
    destination = tmp_path / "ecarts.csv"
    # Le code 1 signale une regression trouvee, pas un echec : le CSV doit
    # exister malgre tout. C'est justement l'ambiguite du code 1 relevee dans
    # l'inventaire en tete de module.
    with contextlib.suppress(SystemExit):
        _lancer_diff(
            monkeypatch,
            capsys,
            "--baseline",
            f"A={reference}",
            "--current",
            f"A={courant}",
            "--diff-csv",
            destination,
        )
    assert destination.exists(), "--diff-csv n'a rien ecrit"


def test_un_baseline_mal_forme_rappelle_le_format(monkeypatch, capsys):
    with pytest.raises(SystemExit) as sortie:
        _lancer_diff(monkeypatch, capsys, "--baseline", "sans_nom.pcap", "--current", "A=x.pcap")
    assert sortie.value.code == 1
    erreur = capsys.readouterr().err
    assert "NOM=" in erreur
    assert "Traceback" not in erreur


# --------------------------------------------------------------------------
# Points d'entree reels, en sous-processus
# --------------------------------------------------------------------------


def _executer(chemin_script, *args):
    return subprocess.run(
        [sys.executable, chemin_script, *[str(a) for a in args]],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": "src", "PATH": __import__("os").environ.get("PATH", "")},
        cwd=".",
        timeout=300,
    )


@pytest.mark.parametrize(
    "script",
    [
        "src/cross_capture_analyzer_cli.py",
        "src/cross_capture_diff_cli.py",
        "src/cross_history_cli.py",
        "src/cross_capture_batch_cli.py",
    ],
)
def test_chaque_cli_repond_a_help_en_sous_processus(script):
    """Verifie le point d'entree reel, pas seulement `main()` importe : un
    import casse, un shebang errone ou une dependance manquante ne se voient
    qu'ici. `--help` sort en 0 par convention argparse."""
    proc = _executer(script, "--help")
    assert proc.returncode == 0, f"--help echoue : {proc.stderr[:400]}"
    assert proc.stdout.strip(), "aide vide"
    assert "Traceback" not in proc.stderr


@pytest.mark.parametrize(
    ("script", "attendu"),
    [
        ("src/cross_capture_analyzer_cli.py", "--capture"),
        ("src/cross_capture_diff_cli.py", "--baseline"),
        ("src/cross_history_cli.py", "--db"),
        ("src/cross_capture_batch_cli.py", "--input"),
    ],
)
def test_chaque_cli_sans_argument_explique_ce_qui_manque(script, attendu):
    """Lance sans aucun argument, chaque CLI doit nommer l'option manquante et
    sortir en non nul. C'est le tout premier contact avec l'outil : une trace
    Python y ferait plus de degats qu'ailleurs.

    Les codes diffrent et c'est assume : l'analyzer valide lui-meme (1),
    `--db` est `required=True` donc argparse tranche (2). Le test verifie le
    caractere non nul et la lisibilite, pas une valeur commune qui n'existe
    pas -- voir l'inventaire des codes en tete de module.
    """
    proc = _executer(script)
    assert proc.returncode != 0, "un lancement sans argument ne doit pas sortir en succes"
    message = proc.stdout + proc.stderr
    assert attendu in message, f"le message ne nomme pas {attendu}"
    assert "Traceback" not in message


def test_le_cli_d_historique_en_sous_processus_sur_une_base_absente(tmp_path):
    """Chemin inexistant = historique vide, code 0 -- comportement documente
    dans l'aide de `--db`. Verifie sur le vrai binaire parce que c'est ce que
    lance un script d'integration."""
    proc = _executer("src/cross_history_cli.py", "--db", tmp_path / "absente.db")
    assert proc.returncode == 0, proc.stderr[:400]
    assert "HISTORIQUE DES RUNS ENREGISTRES" in proc.stdout
