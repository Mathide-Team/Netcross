"""
Issue #259 -- les empreintes JA4/HASSH doivent (a) etre correctes au
regard de l'implementation de reference, (b) atteindre reellement
l'analyste dans le rapport.

Trois familles de tests, repondant chacune a un constat de l'issue :

1. **Conformite a la reference.** Le calcul JA4/HASSH etait ecrit depuis
   la specification publique mais jamais confronte a une implementation de
   reference (critere de #143 laisse en suspens par la PR #223, faute de
   tshark). Les vecteurs de `tests/data/reference_fingerprints.json` sont
   de VRAIES trames capturees en boucle locale, dont la valeur attendue a
   ete calculee par Wireshark, pas par nous. Ces tests ne dependent
   d'aucun outil externe : les octets et les valeurs attendues sont
   figes.

2. **Base d'outils connus non vide.** Elle etait livree vide, donc rien
   n'etait identifiable, alors que le critere « base chargeable » etait
   coche.

3. **Bout en bout.** Le hash et la forme lisible etaient construits puis
   silencieusement jetes par `security_report._build_services`. C'est ce
   test-la qui aurait attrape le constat principal de l'issue : les 26
   tests unitaires existants verifiaient le calcul, jamais le rendu.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netcross_core.fingerprint import ssh_hassh, tls_ja4
from netcross_core.fingerprint.known import identify_tool, load_known_fingerprints

VECTEURS = json.loads((Path(__file__).parent / "data" / "reference_fingerprints.json").read_text(encoding="utf-8"))


# -- 1. conformite a l'implementation de reference -----------------------------


@pytest.mark.parametrize("cas", VECTEURS["ja4"], ids=lambda c: c["nom"])
def test_ja4_concorde_avec_l_implementation_de_reference(cas):
    """Notre JA4 doit etre identique, caractere pour caractere, a celui
    calcule par Wireshark sur la meme trame."""
    resultat = tls_ja4.identify(bytes.fromhex(cas["payload_hex"]))
    assert resultat is not None, "le ClientHello n'a pas ete reconnu"
    assert resultat[0] == cas["attendu"]


@pytest.mark.parametrize("cas", VECTEURS["hassh"], ids=lambda c: c["nom"])
def test_hassh_concorde_avec_l_implementation_de_reference(cas):
    resultat = ssh_hassh.identify(bytes.fromhex(cas["payload_hex"]), cas["sport"], cas["dport"])
    assert resultat is not None, "le KEXINIT n'a pas ete reconnu"
    assert resultat[0] == cas["attendu"]


def test_les_trois_segments_du_ja4_sont_bien_formes():
    """Un JA4 se lit `a_b_c` : partie lisible, puis deux hashs tronques de
    12 caracteres hexadecimaux. Une derive sur la longueur de troncature
    rendrait nos empreintes incomparables a toute base publique, sans
    forcement casser l'egalite ci-dessus si la reference derivait aussi."""
    resultat = tls_ja4.identify(bytes.fromhex(VECTEURS["ja4"][0]["payload_hex"]))
    a, b, c = resultat[0].split("_")
    assert a.startswith("t12") or a.startswith("t13")
    for hash_tronque in (b, c):
        assert len(hash_tronque) == 12
        assert all(ch in "0123456789abcdef" for ch in hash_tronque)


def test_le_ja4_est_stable_entre_deux_calculs():
    """Meme trame, meme empreinte : une empreinte qui varierait (GREASE mal
    ecarte, iteration sur un set...) serait inutilisable pour correler."""
    payload = bytes.fromhex(VECTEURS["ja4"][1]["payload_hex"])
    assert tls_ja4.identify(payload)[0] == tls_ja4.identify(payload)[0]


def test_la_version_negociee_change_le_prefixe_du_ja4():
    """curl force en TLS 1.2 et curl par defaut doivent produire deux
    empreintes distinctes -- sinon JA4 ne distinguerait pas deux
    configurations qui se rencontrent toutes les deux en production."""
    tls12, tls13 = (tls_ja4.identify(bytes.fromhex(c["payload_hex"]))[0] for c in VECTEURS["ja4"])
    assert tls12.startswith("t12")
    assert tls13.startswith("t13")
    assert tls12 != tls13


def test_client_et_serveur_ssh_ont_des_empreintes_distinctes():
    """HASSH (client) et HASSH-Server sont deux empreintes differentes du
    meme OpenSSH : les confondre attribuerait au client les algorithmes du
    serveur."""
    client, serveur = (
        ssh_hassh.identify(bytes.fromhex(c["payload_hex"]), c["sport"], c["dport"])[0] for c in VECTEURS["hassh"]
    )
    assert client != serveur


# -- 2. base d'outils connus ---------------------------------------------------


def test_la_base_livree_n_est_plus_vide():
    """Elle l'etait, alors que le critere « base chargeable » de #143 etait
    coche : le mecanisme de chargement existait, mais rien n'etait
    identifiable."""
    base = load_known_fingerprints()
    assert base["ja4"], "aucune empreinte JA4 connue livree"
    assert base["hassh"], "aucune empreinte HASSH connue livree"


def test_les_empreintes_de_reference_sont_identifiees_par_la_base():
    """Boucle fermee : les empreintes capturees sont celles que la base
    connait. Si l'une des deux derive, le lien casse."""
    for cas in VECTEURS["ja4"]:
        assert identify_tool("ja4", cas["attendu"]) is not None, f"{cas['nom']} absent de la base"
    for cas in VECTEURS["hassh"]:
        assert identify_tool("hassh", cas["attendu"]) is not None, f"{cas['nom']} absent de la base"


def test_curl_est_identifie_nommement():
    """Le critere de #143 parlait d'identifier curl : verifions le nom, pas
    seulement qu'une valeur non nulle sort."""
    libelle = identify_tool("ja4", VECTEURS["ja4"][0]["attendu"])
    assert "curl" in libelle.lower()


def test_openssh_est_identifie_nommement():
    libelle = identify_tool("hassh", VECTEURS["hassh"][0]["attendu"])
    assert "openssh" in libelle.lower()


def test_chaque_entree_de_la_base_documente_sa_provenance():
    """Une empreinte sans provenance ne peut etre ni contestee ni
    reproduite. Le format enrichi exige donc l'outil, sa version et la
    reference contre laquelle la valeur a ete verifiee."""
    base = load_known_fingerprints()
    for famille in ("ja4", "hassh"):
        for empreinte, valeur in base[famille].items():
            assert isinstance(valeur, dict), f"{empreinte} : format court, provenance absente"
            for champ in ("libelle", "outil", "version", "verifie_contre", "methode"):
                assert valeur.get(champ), f"{empreinte} : champ '{champ}' manquant"


def test_identify_tool_accepte_encore_le_format_court():
    """Compatibilite : une base ecrite a la main, valeurs = chaines.
    Casser ce format invaliderait sans preavis les bases utilisateur."""
    assert identify_tool("ja4", "abc", {"ja4": {"abc": "outil maison 1.0"}}) == "outil maison 1.0"


def test_une_empreinte_inconnue_ne_renvoie_rien():
    assert identify_tool("ja4", "t13i0000h0_000000000000_000000000000") is None


# -- 3. bout en bout : le hash atteint-il le rapport ? -------------------------


def _rapport_depuis_empreintes(empreintes):
    """Passe une liste d'empreintes par la vraie chaine d'affichage :
    apply_security_findings -> format_security_report."""
    from netcross_core.models import Report
    from netcross_report.security_report import build_security_report, format_security_report

    r = Report(points=["A"])
    r.service_fingerprints = empreintes
    return "\n".join(format_security_report(build_security_report(r)))


def test_le_hash_ja4_apparait_dans_le_rapport():
    """Constat principal de l'issue #259 : la ligne produite etait
    `[ok] TLS/JA4 @ 10.0.0.5 -- aucune vulnerabilite connue`, sans aucune
    valeur de hash."""
    attendu = VECTEURS["ja4"][0]["attendu"]
    sortie = _rapport_depuis_empreintes(
        [
            {
                "service": "TLS/JA4",
                "version": "curl 8.18.0",
                "host": "10.0.0.5",
                "port": None,
                "point": "A",
                "protocol": "tls",
                "fingerprint": attendu,
                "banner": "ciphers=[0xc02c,0xc030] extensions=[0x000d] alpn=[h2] sni=False",
            }
        ]
    )
    assert f"JA4={attendu}" in sortie, "le hash JA4 n'apparait pas dans le rapport"
    assert "ciphers=" in sortie, "la forme lisible n'apparait pas dans le rapport"
    assert "curl" in sortie


def test_le_hash_hassh_apparait_avec_son_prefixe():
    """#143 demandait explicitement la forme `HASSH=xy123`."""
    attendu = VECTEURS["hassh"][0]["attendu"]
    sortie = _rapport_depuis_empreintes(
        [
            {
                "service": "SSH/HASSH",
                "version": "OpenSSH 10.2p1",
                "host": "10.0.0.7",
                "port": 22,
                "point": "A",
                "protocol": "ssh",
                "fingerprint": attendu,
                "banner": "kex=[curve25519-sha256] enc=[aes128-ctr]",
            }
        ]
    )
    assert f"HASSH={attendu}" in sortie
    assert "kex=" in sortie


def test_deux_empreintes_du_meme_hote_ne_sont_pas_fusionnees():
    """Deux JA4 differents sur un meme hote sont deux clients differents.
    La cle de deduplication ignorait l'empreinte : les fusionner effacait
    l'information la plus utile de la section."""
    a, b = VECTEURS["ja4"][0]["attendu"], VECTEURS["ja4"][1]["attendu"]
    commun = {"service": "TLS/JA4", "host": "10.0.0.5", "port": None, "point": "A", "protocol": "tls"}
    sortie = _rapport_depuis_empreintes(
        [
            {**commun, "fingerprint": a, "banner": "ciphers=[0x002f]", "version": None},
            {**commun, "fingerprint": b, "banner": "ciphers=[0x1301]", "version": None},
        ]
    )
    assert f"JA4={a}" in sortie
    assert f"JA4={b}" in sortie


def test_la_forme_lisible_trop_longue_est_tronquee_mais_signalee():
    """Une liste complete de ciphers fait plusieurs centaines de
    caracteres. On tronque pour garder un rapport texte lisible, mais la
    troncature doit se voir -- sinon le lecteur croit avoir la liste
    entiere."""
    from netcross_report.security_report import MAX_READABLE_LEN

    longue = "ciphers=[" + ",".join(f"0x{i:04x}" for i in range(80)) + "]"
    assert len(longue) > MAX_READABLE_LEN
    sortie = _rapport_depuis_empreintes(
        [
            {
                "service": "TLS/JA4",
                "host": "10.0.0.5",
                "port": None,
                "point": "A",
                "protocol": "tls",
                "version": None,
                "fingerprint": VECTEURS["ja4"][0]["attendu"],
                "banner": longue,
            }
        ]
    )
    assert "..." in sortie
    assert longue not in sortie


def test_un_service_sans_empreinte_reste_affiche_comme_avant():
    """Les services detectes par banniere (CVE-1) n'ont pas d'empreinte :
    leur ligne ne doit pas se mettre a porter un `JA4=None`."""
    sortie = _rapport_depuis_empreintes(
        [{"service": "nginx", "version": "1.18.0", "host": "10.0.0.9", "port": 80, "point": "A"}]
    )
    assert "nginx" in sortie
    assert "JA4=" not in sortie
    assert "None" not in sortie


# -- Issue #707 : gardes du parseur ClientHello (JA4) -------------------------


def test_parse_client_hello_gardes_et_troncatures():
    """Lignes 108-111 : ClientHello tronque -> None ; lignes 132 et 139-140 :
    corps trop court, on passe a l'enregistrement suivant ; lignes 207-208
    et 222-223 : extensions ALPN et supported_versions vides."""
    from netcross_core.fingerprint.tls_ja4 import (
        _parse_alpn,
        _parse_supported_versions,
        parse_client_hello,
    )

    court = b"\x16\x03\x01\x00\x02\x01\x00"
    assert parse_client_hello(court) is None
    tronque = b"\x16\x03\x01\x00\x06\x01\x00\x00\x40\x03\x03"
    assert parse_client_hello(tronque) is None
    assert _parse_alpn(b"\x00") == []
    assert _parse_supported_versions(b"") == []
