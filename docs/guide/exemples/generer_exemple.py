"""Régénère les captures d'exemple du guide utilisateur.

Scénario : un poste (10.0.0.5) ouvre trois connexions TCP vers un serveur
(203.0.113.10:443). Les mêmes paquets sont capturés sur le LAN (TTL 64),
puis 4 ms plus tard côté WAN, après un routeur (TTL 63). Cinq segments de
données de la première connexion n'atteignent jamais le WAN : c'est la
vérité terrain que l'analyse doit retrouver.

Fichiers produits :

- lan.pcap, wan.pcap : la situation « avant », avec les 5 pertes ;
- lan_apres.pcap, wan_apres.pcap : la même situation une fois le problème
  corrigé (aucune perte), pour l'exemple de comparaison avant/après.

Usage : python3 generer_exemple.py   (nécessite scapy : pip install scapy)
"""

from __future__ import annotations

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT, SERVEUR = "10.0.0.5", "203.0.113.10"
T0 = 1_700_000_000.0
LATENCE_S = 0.004
SEQ_CLIENT, SEQ_SERVEUR = 1000, 5000  # numeros de sequence initiaux
PERDUS = {12, 13, 20, 31, 32}  # indices des segments perdus, 1re connexion


def generer(dossier: Path, perdus: set[int], suffixe: str = "") -> tuple[int, int]:
    lan, wan = [], []

    def ajouter(fabrique, instant, vers_wan=True):
        paquet = fabrique(64)
        paquet.time = instant
        lan.append(paquet)
        if vers_wan:
            copie = fabrique(63)  # un routeur entre les deux points : TTL - 1
            copie.time = instant + LATENCE_S
            wan.append(copie)

    for connexion in range(3):
        sport, debut = 40000 + connexion, T0 + 2 * connexion

        def syn(ttl, sport=sport):
            return (
                Ether() / IP(src=CLIENT, dst=SERVEUR, ttl=ttl) / TCP(sport=sport, dport=443, flags="S", seq=SEQ_CLIENT)
            )

        def syn_ack(ttl, sport=sport):
            return (
                Ether()
                / IP(src=SERVEUR, dst=CLIENT, ttl=ttl)
                / TCP(sport=443, dport=sport, flags="SA", seq=SEQ_SERVEUR, ack=SEQ_CLIENT + 1)
            )

        def ack(ttl, sport=sport):
            return (
                Ether()
                / IP(src=CLIENT, dst=SERVEUR, ttl=ttl)
                / TCP(sport=sport, dport=443, flags="A", seq=SEQ_CLIENT + 1, ack=SEQ_SERVEUR + 1)
            )

        ajouter(syn, debut)
        ajouter(syn_ack, debut + 0.02)
        ajouter(ack, debut + 0.021)
        numero = SEQ_CLIENT + 1
        for i in range(40):

            def donnees(ttl, sport=sport, numero=numero, charge=bytes([i % 256]) * 500):
                return (
                    Ether()
                    / IP(src=CLIENT, dst=SERVEUR, ttl=ttl)
                    / TCP(sport=sport, dport=443, flags="PA", seq=numero, ack=SEQ_SERVEUR + 1)
                    / Raw(charge)
                )

            ajouter(donnees, debut + 0.03 + i * 0.01, vers_wan=connexion != 0 or i not in perdus)
            numero += 500

    wrpcap(str(dossier / f"lan{suffixe}.pcap"), lan)
    wrpcap(str(dossier / f"wan{suffixe}.pcap"), wan)
    return len(lan), len(wan)


if __name__ == "__main__":
    ici = Path(__file__).resolve().parent
    for perdus, suffixe in ((PERDUS, ""), (set(), "_apres")):
        n_lan, n_wan = generer(ici, perdus, suffixe)
        print(f"lan{suffixe}.pcap : {n_lan} paquets, wan{suffixe}.pcap : {n_wan} paquets")
