#!/usr/bin/env python3
"""
Peuple `known_fingerprints.json` avec de VRAIES empreintes JA4/HASSH
(issue #259), capturees sur la boucle locale et verifiees contre
l'implementation de reference de Wireshark.

Pourquoi un script plutot que des valeurs collees a la main
---------------------------------------------------------------------
La base etait livree vide, avec une note honnete : aucune empreinte
n'avait pu etre verifiee faute de tshark. Coller des valeurs trouvees sur
internet aurait remplace un vide assume par une fausse certitude. Un
script, lui, est re-executable : on peut reproduire chaque valeur, et la
completer avec d'autres outils (un navigateur, un client maison) sans
avoir a nous croire sur parole.

Double verification systematique
---------------------------------------------------------------------
Pour chaque empreinte, le script compare la valeur calculee par
`netcross_core.fingerprint` a celle calculee par tshark
(`tls.handshake.ja4`, `ssh.kex.hassh`, `ssh.kex.hasshserver`). En cas de
desaccord, l'empreinte est REJETEE et l'ecart est signale, jamais
enregistre : c'est exactement le critere « verifier la coherence avec la
reference » de l'issue #143, laisse en suspens par la PR #223 faute
d'implementation de reference disponible.

Usage
---------------------------------------------------------------------
    sudo env "PYTHONPATH=src:$(python3 -c 'import site;print(site.getusersitepackages())')" \
        python3 scripts/capture_reference_fingerprints.py [--dry-run]

La capture sur interface exige les privileges reseau, d'ou `sudo`. Le
`env PYTHONPATH=...` explicite est necessaire parce que `sudo` purge
l'environnement (`-E` est refuse par la configuration par defaut) et que
root ne voit pas le site-packages utilisateur ou vivent les dependances. Les
outils absents de la machine sont sautes avec un message : la base
produite est alors partielle, ce que le fichier de sortie indique
explicitement plutot que de laisser croire a l'exhaustivite.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger  # noqa: E402

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "src"))

from netcross_core.fingerprint import ssh_hassh, tls_ja4  # noqa: E402

BASE = RACINE / "src" / "netcross_core" / "fingerprint" / "known_fingerprints.json"

PORT_TLS = 14443
PORT_SSH = 12222


# -- utilitaires ---------------------------------------------------------------


def _requis(*outils: str) -> bool:
    return all(shutil.which(o) for o in outils)


def _version_outil(commande: list[str]) -> str:
    """Premiere ligne de la sortie de version, ou "?" -- la version est la
    seule chose qui donne un sens a une empreinte : JA4 change d'une
    version de curl a l'autre des que la liste de ciphers bouge."""
    try:
        proc = subprocess.run(commande, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("version de l'outil indisponible : {}", exc)
        return "?"
    sortie = (proc.stdout or proc.stderr).strip().splitlines()
    return sortie[0].strip() if sortie else "?"


def _libelle(outil: str, version: str) -> str:
    """Libelle court destine a l'affichage : "curl 8.18.0".

    La version complete (`curl --version` entier, plusieurs centaines de
    caracteres de bibliotheques liees) est conservee a part : precieuse
    pour reproduire une empreinte, illisible dans une ligne de rapport.
    """
    import re as _re

    trouve = _re.search(r"\d+\.\d+[\w.]*", version or "")
    return f"{outil} {trouve.group(0)}" if trouve else outil


def _attendre_port(port: int, delai: float = 10.0) -> bool:
    """Attend qu'un service ecoute, plutot qu'un sleep fixe : un sleep trop
    court produit une capture vide et un diagnostic trompeur."""
    fin = time.monotonic() + delai
    while time.monotonic() < fin:
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


class Capture:
    """Capture tshark sur la boucle locale, en gestionnaire de contexte."""

    def __init__(self, chemin: Path, filtre: str):
        self.chemin = chemin
        self.filtre = filtre
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> Capture:
        self.proc = subprocess.Popen(
            ["tshark", "-i", "lo", "-f", self.filtre, "-w", str(self.chemin), "-q"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        # tshark met ~1 a 2 s a ouvrir l'interface ; demarrer le client
        # avant cela perdrait le ClientHello, c'est-a-dire le seul paquet
        # qui nous interesse.
        time.sleep(2.5)
        return self

    def __exit__(self, *_exc) -> None:
        if self.proc is not None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired as exc:  # pragma: no cover
                logger.debug("arret force du processus (timeout) : {}", exc)
                self.proc.kill()
        time.sleep(0.5)


def _champs(pcap: Path, filtre: str, champs: list[str]) -> list[list[str]]:
    args = ["tshark", "-r", str(pcap), "-Y", filtre, "-T", "fields"]
    for c in champs:
        args += ["-e", c]
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    # Les lignes " ** (tshark:...)" sont des avertissements de dissecteur
    # (ex. KEX post-quantique) melanges a la sortie utile.
    return [ligne.split("\t") for ligne in proc.stdout.splitlines() if ligne.strip() and not ligne.startswith(" **")]


# -- collecte TLS --------------------------------------------------------------


def _serveur_tls(dossier: Path) -> subprocess.Popen | None:
    """Lance un `openssl s_server` local. Son propre ClientHello n'est
    jamais analyse : on ne veut que celui des clients."""
    cle, cert = dossier / "k.pem", dossier / "c.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(cle),
            "-out",
            str(cert),
            "-days",
            "2",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ],
        capture_output=True,
        check=False,
    )
    if not cert.is_file():
        return None
    proc = subprocess.Popen(
        ["openssl", "s_server", "-key", str(cle), "-cert", str(cert), "-accept", str(PORT_TLS), "-www", "-quiet"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc if _attendre_port(PORT_TLS) else None


def _clients_tls() -> list[tuple[str, str, list[str]]]:
    """(nom d'outil, commande de version, commande client) a exercer.

    Chaque entree produit un ClientHello distinct. On force explicitement
    TLS 1.2 pour curl EN PLUS de son defaut : la version negociee change
    la premiere partie du JA4 (`t12...` vs `t13...`), et les deux se
    rencontrent en production.
    """
    url = f"https://127.0.0.1:{PORT_TLS}/"
    clients = []
    if _requis("curl"):
        clients.append(("curl", ["curl", "--version"], ["curl", "-sk", url, "-o", os.devnull]))
        clients.append(
            (
                "curl (TLS 1.2 force)",
                ["curl", "--version"],
                ["curl", "-sk", "--tlsv1.2", "--tls-max", "1.2", url, "-o", os.devnull],
            ),
        )
    if _requis("wget"):
        clients.append(
            ("wget", ["wget", "--version"], ["wget", "-q", "--no-check-certificate", "-O", os.devnull, url]),
        )
    if _requis("openssl"):
        clients.append(
            (
                "openssl s_client",
                ["openssl", "version"],
                ["openssl", "s_client", "-connect", f"127.0.0.1:{PORT_TLS}", "-brief"],
            ),
        )
    clients.append(
        (
            "python ssl",
            [sys.executable, "-VV"],
            [
                sys.executable,
                "-c",
                "import ssl,urllib.request as u;c=ssl._create_unverified_context();"
                f"u.urlopen('{url}',context=c,timeout=5).read()",
            ],
        ),
    )
    return clients


def _collecter_tls(dossier: Path, rapport: list[str]) -> dict[str, dict]:
    if not _requis("tshark", "openssl"):
        rapport.append("TLS saute : tshark ou openssl absent")
        return {}

    clients = _clients_tls()
    serveur = None
    # Un client par capture : sans cela, rien ne permet d'attribuer un
    # ClientHello a l'outil qui l'a emis (meme hote, meme port source
    # ephemere, aucun marqueur applicatif avant chiffrement).
    resultats: dict[str, dict] = {}
    try:
        serveur = _serveur_tls(dossier)
        if serveur is None:
            rapport.append("TLS saute : impossible de demarrer openssl s_server")
            return {}
        for nom, cmd_version, cmd_client in clients:
            pcap_outil = dossier / f"tls-{abs(hash(nom))}.pcap"
            with Capture(pcap_outil, f"tcp port {PORT_TLS}"):
                subprocess.run(
                    cmd_client, capture_output=True, timeout=30, check=False, input=b"" if "s_client" in nom else None
                )
                time.sleep(1.5)
            lignes = _champs(pcap_outil, "tls.handshake.type==1", ["tcp.payload", "tls.handshake.ja4"])
            if not lignes:
                rapport.append(f"{nom} : aucun ClientHello capture -- non enregistre")
                continue
            payload = bytes.fromhex(lignes[0][0].replace(":", ""))
            reference = lignes[0][1] if len(lignes[0]) > 1 else ""
            calcule = tls_ja4.identify(payload)
            if calcule is None:
                rapport.append(f"{nom} : netcross n'a pas su lire le ClientHello -- non enregistre")
                continue
            empreinte, lisible = calcule
            if not reference:
                rapport.append(f"{nom} : tshark n'a pas fourni de JA4 de reference -- non enregistre")
                continue
            if empreinte != reference:
                rapport.append(f"{nom} : DESACCORD netcross={empreinte} tshark={reference} -- non enregistre")
                continue
            version_complete = _version_outil(cmd_version)
            resultats[empreinte] = {
                "libelle": _libelle(nom, version_complete),
                "outil": nom,
                "version": version_complete,
                "lisible": lisible,
                "verifie_contre": "tshark " + _version_tshark(),
                "methode": "capture reelle sur boucle locale",
            }
            rapport.append(f"{nom} : JA4={empreinte} (concorde avec tshark)")
    finally:
        if serveur is not None:
            serveur.terminate()
    return resultats


# -- collecte SSH --------------------------------------------------------------


def _collecter_ssh(dossier: Path, rapport: list[str]) -> dict[str, dict]:
    if not _requis("tshark", "ssh") or not Path("/usr/sbin/sshd").exists():
        rapport.append("SSH saute : tshark, ssh ou sshd absent")
        return {}

    subprocess.run(["mkdir", "-p", "/run/sshd"], check=False, capture_output=True)
    subprocess.run(["ssh-keygen", "-A"], check=False, capture_output=True)

    pcap = dossier / "ssh.pcap"
    resultats: dict[str, dict] = {}
    sshd = None
    try:
        with Capture(pcap, f"tcp port {PORT_SSH}"):
            sshd = subprocess.Popen(
                ["/usr/sbin/sshd", "-p", str(PORT_SSH), "-D", "-o", "PidFile=none"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if not _attendre_port(PORT_SSH):
                rapport.append("SSH saute : sshd n'ecoute pas")
                return {}
            # L'authentification echoue volontairement : le KEXINIT est
            # echange AVANT toute authentification, donc l'empreinte est
            # deja capturee. Inutile de creer un compte pour cela.
            subprocess.run(
                [
                    "ssh",
                    "-p",
                    str(PORT_SSH),
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=5",
                    "nobody@127.0.0.1",
                    "true",
                ],
                capture_output=True,
                timeout=30,
                check=False,
            )
            time.sleep(1.5)

        version = _version_outil(["ssh", "-V"])
        for ligne in _champs(
            pcap,
            "ssh.message_code==20",
            ["tcp.payload", "ssh.kex.hassh", "ssh.kex.hasshserver", "tcp.srcport", "tcp.dstport"],
        ):
            payload = bytes.fromhex(ligne[0].replace(":", ""))
            ref_client = ligne[1] if len(ligne) > 1 else ""
            ref_serveur = ligne[2] if len(ligne) > 2 else ""
            reference = ref_client or ref_serveur
            role_attendu = "client" if ref_client else "serveur"
            if not reference:
                continue
            calcule = ssh_hassh.identify(payload, int(ligne[3]), int(ligne[4]))
            if calcule is None:
                rapport.append(f"OpenSSH ({role_attendu}) : KEXINIT illisible par netcross -- non enregistre")
                continue
            empreinte, lisible = calcule[0], calcule[-1]
            if empreinte != reference:
                rapport.append(
                    f"OpenSSH ({role_attendu}) : DESACCORD netcross={empreinte} tshark={reference} -- non enregistre"
                )
                continue
            resultats[empreinte] = {
                "libelle": _libelle(f"OpenSSH ({role_attendu})", version),
                "outil": f"OpenSSH ({role_attendu})",
                "version": version,
                "lisible": lisible,
                "verifie_contre": "tshark " + _version_tshark(),
                "methode": "capture reelle sur boucle locale",
            }
            rapport.append(f"OpenSSH ({role_attendu}) : HASSH={empreinte} (concorde avec tshark)")
    finally:
        if sshd is not None:
            sshd.terminate()
    return resultats


def _version_tshark() -> str:
    premiere = _version_outil(["tshark", "--version"])
    return premiere.replace("TShark (Wireshark) ", "").rstrip(".")


# -- ecriture ------------------------------------------------------------------


def _ecrire(ja4: dict, hassh: dict, rapport: list[str], dry_run: bool) -> int:
    contenu = {
        "_note": (
            "Base peuplee par scripts/capture_reference_fingerprints.py (issue #259). "
            "Chaque empreinte a ete capturee sur du trafic REEL en boucle locale, puis "
            "verifiee identique a celle calculee par l'implementation de reference de "
            "Wireshark (tls.handshake.ja4, ssh.kex.hassh, ssh.kex.hasshserver). Toute "
            "empreinte en desaccord avec tshark est rejetee par le script, jamais "
            "enregistree. Liste NON exhaustive : elle ne contient que les outils "
            "presents sur la machine de generation -- l'absence d'un navigateur ici ne "
            "dit rien de son empreinte. Relancer le script pour l'enrichir."
        ),
        "_genere_le": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "_journal_de_generation": rapport,
        "ja4": ja4,
        "hassh": hassh,
    }
    rendu = json.dumps(contenu, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    if dry_run:
        print(rendu)
        return 0
    BASE.write_text(rendu, encoding="utf-8")
    print(f"{BASE} ecrit : {len(ja4)} JA4, {len(hassh)} HASSH.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parseur = argparse.ArgumentParser(description=__doc__)
    parseur.add_argument("--dry-run", action="store_true", help="affiche le resultat sans ecrire")
    args = parseur.parse_args(argv)

    if os.geteuid() != 0:
        print(
            "ERREUR : la capture sur interface exige les privileges reseau. Relancer avec :\n"
            "  sudo env \"PYTHONPATH=src:$(python3 -c 'import site;print(site.getusersitepackages())')\" \\\n"
            "      python3 scripts/capture_reference_fingerprints.py",
            file=sys.stderr,
        )
        return 2

    rapport: list[str] = [f"genere avec tshark {_version_tshark()}"]
    with tempfile.TemporaryDirectory(prefix="netcross-fp-") as tmp:
        dossier = Path(tmp)
        ja4 = _collecter_tls(dossier, rapport)
        hassh = _collecter_ssh(dossier, rapport)

    for ligne in rapport:
        print(f"  {ligne}")
    if not ja4 and not hassh:
        # Regle de tracabilite : un echec total doit etre bruyant, pas
        # ecraser la base par un fichier vide.
        print("\nAucune empreinte collectee : la base n'est PAS modifiee.", file=sys.stderr)
        return 1
    return _ecrire(ja4, hassh, rapport, args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
