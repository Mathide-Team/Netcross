"""
Tests de la remontee de tickets anonymisee (issue #269).

Deux volets : le scrubbing de texte libre
(netcross_core.support.scrubber) et le ticket lui-meme
(netcross_core.support.ticket), en insistant sur les deux invariants du
projet :

- rien n'est ecrit sans consentement explicite ;
- un rapport est TOUJOURS produit, meme quand tout va bien (regle de
  tracabilite, docs/quality/traceability-rule.md).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netcross_core.support import (
    KNOWN_LIMITS,
    SECRET_PLACEHOLDER,
    Consent,
    ConsentRequiredError,
    TextScrubber,
    build_ticket,
    collect_environment,
    format_exception,
    write_support_map_csv,
    write_ticket,
)

# -- scrubber : adresses ---------------------------------------------------


def test_scrub_remplace_une_ipv4_par_une_adresse_de_documentation():
    out, rep = TextScrubber().scrub("connexion vers 10.1.2.3 refusee")
    assert "10.1.2.3" not in out
    assert "192.0.2." in out
    assert rep.par_categorie["ipv4"] == 1
    assert rep.statut == "redige"


def test_scrub_conserve_le_port_apres_une_ipv4():
    out, _ = TextScrubber().scrub("cible 10.1.2.3:8443")
    assert out.endswith(":8443")
    assert "10.1.2.3" not in out


def test_scrub_remplace_une_ipv6_par_la_plage_rfc3849():
    out, rep = TextScrubber().scrub("pair fe80::1c2d:3e4f:5a6b:7c8d indisponible")
    assert "fe80::" not in out
    assert "2001:db8::" in out
    assert rep.par_categorie["ipv6"] == 1


def test_scrub_remplace_une_mac_par_un_oui_localement_administre():
    out, rep = TextScrubber().scrub("voisin aa:bb:cc:dd:ee:ff vu en A")
    assert "aa:bb:cc:dd:ee:ff" not in out
    assert "02:00:00:00:" in out
    assert rep.par_categorie["mac"] == 1


def test_scrub_traite_la_mac_avant_l_ipv6_pas_de_confusion():
    """Une MAC et une IPv6 partagent le separateur ':' -- l'ordre des
    regles doit empecher l'IPv6 de manger la MAC."""
    out, rep = TextScrubber().scrub("mac 00:11:22:33:44:55 ip fe80::abcd")
    assert rep.par_categorie["mac"] == 1
    assert rep.par_categorie["ipv6"] == 1
    assert "02:00:00:00:" in out and "2001:db8::" in out


# -- scrubber : identites et secrets --------------------------------------


def test_scrub_remplace_un_email():
    out, rep = TextScrubber().scrub("contact jean.dupont@acme-corp.fr")
    assert "jean.dupont@acme-corp.fr" not in out
    assert "@example.invalid" in out
    assert rep.par_categorie["email"] == 1


def test_scrub_ecrase_un_mot_de_passe_sans_le_pseudonymiser():
    """Un secret n'a aucune valeur de correlation : il est ecrase, pas
    remplace par un pseudonyme stable."""
    out, rep = TextScrubber().scrub("connexion avec password=Sup3rS3cret!")
    assert "Sup3rS3cret" not in out
    assert SECRET_PLACEHOLDER in out
    assert "password=" in out  # la CLE reste : savoir qu'il y en avait un est utile
    assert rep.par_categorie["secret"] == 1


def test_scrub_ecrase_un_jeton_bearer():
    out, rep = TextScrubber().scrub("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abcdef")
    assert "eyJhbGciOiJIUzI1NiJ9abcdef" not in out
    assert SECRET_PLACEHOLDER in out
    assert rep.par_categorie["secret"] >= 1


def test_scrub_remplace_une_url_complete():
    out, rep = TextScrubber().scrub("appel POST https://intranet.acme.local/api/v1/clients?id=42")
    assert "intranet.acme.local" not in out
    assert "example.invalid" in out
    assert rep.par_categorie["url"] == 1


def test_scrub_remplace_un_fqdn_nu():
    out, rep = TextScrubber().scrub("resolution de srv-compta.acme.local echouee")
    assert "srv-compta.acme.local" not in out
    assert "host-1.example.invalid" in out
    assert rep.par_categorie["hostname"] == 1


# -- scrubber : chemins et captures ---------------------------------------


def test_scrub_anonymise_le_repertoire_personnel_unix_en_gardant_le_reste():
    out, rep = TextScrubber().scrub("lecture de /home/jdupont/captures/site.txt")
    assert "jdupont" not in out
    assert out.split("lecture de ")[1] == "/home/user-1/captures/site.txt"
    assert rep.par_categorie["path"] == 1


def test_scrub_anonymise_le_repertoire_personnel_windows():
    out, rep = TextScrubber().scrub(r"fichier C:\Users\jdupont\Desktop\trace.txt")
    assert "jdupont" not in out
    assert r"C:\Users\user-1" in out
    assert rep.par_categorie["path"] == 1


def test_scrub_anonymise_le_nom_de_capture_en_gardant_l_extension():
    """Le nom d'une capture nomme souvent le client ; l'extension, elle,
    est une information de format utile au diagnostic."""
    out, rep = TextScrubber().scrub("echec sur client_acme_site3.pcapng")
    assert "client_acme" not in out
    assert out.endswith("capture-1.pcapng")
    assert rep.par_categorie["capture"] == 1


# -- scrubber : mapping, stabilite, idempotence ---------------------------


def test_scrub_attribue_le_meme_pseudonyme_a_la_meme_valeur():
    sc = TextScrubber()
    a, _ = sc.scrub("de 10.0.0.1 vers 10.0.0.2")
    b, _ = sc.scrub("retour de 10.0.0.2 vers 10.0.0.1")
    p1, p2 = a.split("de ")[1].split(" vers ")
    assert p2 in b and p1 in b
    assert p1 != p2


def test_scrub_partage_le_mapping_entre_deux_textes_differents():
    sc = TextScrubber()
    tb, _ = sc.scrub("Traceback : hote srv.acme.local")
    log, _ = sc.scrub("journal : hote srv.acme.local injoignable")
    assert "host-1.example.invalid" in tb
    assert "host-1.example.invalid" in log


def test_scrub_est_idempotent_sur_ses_propres_remplacements():
    """Rescrubber un texte deja scrubbe ne doit rien changer -- sinon les
    pseudonymes deriveraient a chaque passe."""
    sc = TextScrubber()
    once, _ = sc.scrub("hote srv.acme.local et ip 10.0.0.9")
    twice, rep = sc.scrub(once)
    assert twice == once
    assert rep.par_categorie.get("hostname", 0) == 0


def test_mapping_csv_rows_expose_la_correspondance_triee():
    sc = TextScrubber()
    sc.scrub("de 10.0.0.1 vers jean@acme.fr")
    rows = sc.mapping_csv_rows()
    assert len(rows) == 2
    kinds = {kind for _, _, kind in rows}
    assert kinds == {"ipv4", "email"}


def test_write_support_map_csv_ecrit_un_entete_et_les_lignes(tmp_path):
    sc = TextScrubber()
    sc.scrub("ip 10.0.0.1")
    path = str(tmp_path / "map.csv")
    write_support_map_csv(sc, path)
    lignes = Path(path).read_text(encoding="utf-8").strip().splitlines()
    assert lignes[0] == "valeur_reelle,pseudonyme,categorie"
    assert lignes[1].startswith("10.0.0.1,192.0.2.")


# -- scrubber : tracabilite ----------------------------------------------


def test_scrub_produit_un_rapport_meme_sans_rien_a_rediger():
    """Regle de tracabilite : "tout va bien" est un resultat affirme."""
    out, rep = TextScrubber().scrub("analyse terminee sans anomalie")
    assert out == "analyse terminee sans anomalie"
    assert rep.total == 0
    assert rep.statut == "aucune_donnee_sensible_detectee"
    assert rep.par_categorie == {}


def test_le_rapport_porte_toujours_les_limites_connues():
    _, rep = TextScrubber().scrub("texte neutre")
    assert rep.limites == KNOWN_LIMITS
    assert rep.to_dict()["limites"]


def test_scrub_accepte_none_et_chaine_vide():
    sc = TextScrubber()
    out_none, rep_none = sc.scrub(None)
    assert out_none is None
    assert rep_none.total == 0
    out, rep = sc.scrub("")
    assert out == ""
    assert rep.total == 0


def test_scrub_lines_agrege_le_rapport():
    sc = TextScrubber()
    lignes, rep = sc.scrub_lines(["ip 10.0.0.1", "ip 10.0.0.2", "rien ici"])
    assert len(lignes) == 3
    assert rep.par_categorie["ipv4"] == 2
    assert rep.valeurs_distinctes == 2


# -- ticket : consentement -----------------------------------------------


def test_write_ticket_refuse_sans_consentement(tmp_path):
    ticket = build_ticket(consent=Consent(granted=False))
    with pytest.raises(ConsentRequiredError):
        write_ticket(ticket, str(tmp_path / "ticket.json"))
    assert not (tmp_path / "ticket.json").exists()


def test_write_ticket_ecrit_avec_consentement(tmp_path):
    ticket = build_ticket(consent=Consent(granted=True))
    path = write_ticket(ticket, str(tmp_path / "ticket.json"))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["consentement"]["accorde"] is True
    assert data["schema_version"] == "1.0"


def test_une_portee_non_autorisee_est_omise_et_tracee():
    """Le contenu non autorise est absent -- et son absence est expliquee,
    pas silencieuse."""
    consent = Consent(granted=True, scopes=("environnement",))
    ticket = build_ticket(consent=consent, log_lines=["ligne secrete"])
    assert ticket.log_lines == []
    journal = next(c for c in ticket.self_check if c["controle"] == "journal")
    assert journal["statut"] == "omis"
    assert "non autorisee" in journal["detail"]


def test_l_environnement_est_omis_si_non_autorise():
    ticket = build_ticket(consent=Consent(granted=True, scopes=("journal",)))
    assert ticket.environment == {}
    env = next(c for c in ticket.self_check if c["controle"] == "environnement")
    assert env["statut"] == "omis"


# -- ticket : contenu ----------------------------------------------------


def test_ticket_diagnostic_sans_incident_reste_informatif():
    """Un ticket "rien n'a casse" est valide et porte l'information."""
    ticket = build_ticket(consent=Consent(granted=True), kind="diagnostic")
    assert ticket.kind == "diagnostic"
    assert ticket.crash is None
    incident = next(c for c in ticket.self_check if c["controle"] == "incident")
    assert incident["statut"] == "ok"
    assert "aucune exception" in incident["detail"]


def test_ticket_de_crash_porte_le_type_et_la_trace_anonymisee():
    try:
        raise ValueError("echec sur /home/jdupont/capture_acme.pcapng")
    except ValueError as exc:
        ticket = build_ticket(consent=Consent(granted=True), kind="crash", exception=exc)
    assert ticket.crash["type"] == "ValueError"
    assert "jdupont" not in ticket.crash["message"]
    assert "capture_acme" not in ticket.crash["message"]
    assert ticket.crash["trace_appels"]


def test_la_trace_d_appels_est_omise_si_non_autorisee():
    try:
        raise RuntimeError("boum")
    except RuntimeError as exc:
        consent = Consent(granted=True, scopes=("environnement",))
        ticket = build_ticket(consent=consent, kind="crash", exception=exc)
    assert "trace_appels" not in ticket.crash
    tr = next(c for c in ticket.self_check if c["controle"] == "trace_appels")
    assert tr["statut"] == "omis"


def test_les_erreurs_de_traitement_sont_anonymisees():
    ticket = build_ticket(
        consent=Consent(granted=True),
        kind="erreur_traitement",
        errors=["impossible de lire 10.0.0.5", "timeout sur srv.acme.local"],
    )
    joint = " ".join(ticket.errors)
    assert "10.0.0.5" not in joint
    assert "srv.acme.local" not in joint
    assert "192.0.2." in joint


def test_le_journal_est_anonymise_ligne_par_ligne():
    ticket = build_ticket(
        consent=Consent(granted=True),
        log_lines=["INFO demarrage", "ERROR echec sur 10.0.0.7"],
    )
    assert ticket.log_lines[0] == "INFO demarrage"
    assert "10.0.0.7" not in ticket.log_lines[1]


def test_un_run_id_est_genere_si_absent():
    ticket = build_ticket(consent=Consent(granted=True))
    assert "run_id" in ticket.markers
    assert ticket.markers["run_id"]


def test_les_marqueurs_fournis_sont_conserves():
    ticket = build_ticket(
        consent=Consent(granted=True),
        markers={"trace_id": "T-042", "capture_id": "C-7"},
    )
    assert ticket.markers["trace_id"] == "T-042"
    assert ticket.markers["capture_id"] == "C-7"
    assert "run_id" in ticket.markers


def test_une_nature_de_ticket_inconnue_est_refusee():
    with pytest.raises(ValueError, match="nature de ticket inconnue"):
        build_ticket(consent=Consent(granted=True), kind="n_importe_quoi")


# -- ticket : tracabilite ------------------------------------------------


def test_le_ticket_porte_toujours_une_section_anonymisation():
    ticket = build_ticket(consent=Consent(granted=True))
    assert ticket.anonymization["statut"] == "aucune_donnee_sensible_detectee"
    assert ticket.anonymization["mapping_joint"] is False


def test_le_ticket_porte_toujours_une_auto_verification_complete():
    ticket = build_ticket(consent=Consent(granted=True))
    controles = {c["controle"] for c in ticket.self_check}
    assert {"marqueurs", "environnement", "incident", "erreurs_traitement", "journal", "anonymisation"} <= controles


def test_le_mapping_n_est_jamais_dans_le_ticket(tmp_path):
    """Invariant de securite : le ticket seul ne permet pas de remonter
    aux valeurs reelles."""
    ticket = build_ticket(
        consent=Consent(granted=True),
        errors=["echec sur 10.11.12.13"],
    )
    brut = ticket.to_json()
    assert "10.11.12.13" not in brut
    assert ticket.anonymization["mapping_joint"] is False


def test_le_compte_d_anonymisation_est_exact():
    ticket = build_ticket(
        consent=Consent(granted=True),
        errors=["ip 10.0.0.1", "ip 10.0.0.1 encore", "mail a@b.fr"],
    )
    assert ticket.anonymization["par_categorie"]["ipv4"] == 2
    assert ticket.anonymization["par_categorie"]["email"] == 1
    assert ticket.anonymization["total_occurrences"] == 3


# -- environnement et exceptions -----------------------------------------


def test_collect_environment_ne_fuit_ni_machine_ni_utilisateur():
    env = collect_environment()
    assert set(env) == {
        "systeme",
        "version_systeme",
        "architecture",
        "python",
        "tshark_disponible",
        "netcross_log_level",
    }
    valeurs = " ".join(str(v) for v in env.values())
    import getpass
    import socket

    assert socket.gethostname() not in valeurs
    assert getpass.getuser() not in valeurs


def test_format_exception_renvoie_type_message_et_lignes():
    try:
        raise KeyError("absent")
    except KeyError as exc:
        kind, msg, lignes = format_exception(exc)
    assert kind == "KeyError"
    assert "absent" in msg
    assert any("KeyError" in ligne for ligne in lignes)


def test_le_ticket_est_serialisable_en_json():
    ticket = build_ticket(consent=Consent(granted=True), errors=["souci"])
    data = json.loads(ticket.to_json())
    assert data["nature"] == "diagnostic"
    assert data["auto_verification"]


# -- Issue #714 : echappement CSV et installation du gestionnaire de crash ---


def test_csv_echappe_virgules_et_guillemets():
    """Lignes 360-361 : valeur contenant , ou " mise entre guillemets."""
    from netcross_core.support.ticket import _csv

    assert _csv('a,"b"') == '"a,""b"""'
    assert _csv("simple") == "simple"


def test_install_crash_handler_sans_consentement_n_installe_rien(monkeypatch):
    """Lignes 378-381 : sans consentement, sys.excepthook est inchange."""
    import sys

    from netcross_core.support.ticket import install_crash_handler

    sentinelle = object()
    monkeypatch.setattr(sys, "excepthook", sentinelle)
    install_crash_handler("/tmp/inutile.json", Consent(granted=False))
    assert sys.excepthook is sentinelle


def test_install_crash_handler_ecrit_le_ticket_puis_chaine(monkeypatch, tmp_path, capsys):
    """Lignes 383-402 : avec consentement, le hook ecrit le ticket puis
    appelle le hook precedent ; un echec d'ecriture est signale sans
    masquer le crash."""
    import sys

    from netcross_core.support import ticket as ticket_mod

    appels = []
    monkeypatch.setattr(sys, "excepthook", lambda *a: appels.append(a))
    chemin = tmp_path / "crash.json"
    ticket_mod.install_crash_handler(str(chemin), Consent(granted=True))
    assert sys.excepthook is not None

    try:
        raise RuntimeError("boum")
    except RuntimeError as exc:
        info = (type(exc), exc, exc.__traceback__)
    sys.excepthook(*info)
    assert chemin.exists()
    assert len(appels) == 1
    assert "Ticket de support anonymise ecrit" in capsys.readouterr().err

    def _echec(*a, **k):
        raise OSError("disque plein")

    monkeypatch.setattr(ticket_mod, "write_ticket", _echec)
    sys.excepthook(*info)
    assert len(appels) == 2
    assert "Echec d'ecriture du ticket de support : disque plein" in capsys.readouterr().err
