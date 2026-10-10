# Préparer les captures

Netcross compare des captures prises **en même temps** à plusieurs
endroits. La qualité du diagnostic dépend d'abord de celle des captures :
quelques minutes de préparation évitent des conclusions fausses.

## Où capturer

Placez un point de capture de chaque côté de chaque équipement suspect.
Pour un poste qui accède lentement à une application hébergée :

```text
 Poste ──[1]── switch ──[2]── routeur/pare-feu ──[3]── WAN ──[4]── serveur
```

Avec les points 2 et 3, une perte constatée entre eux met en cause le
routeur ou le pare-feu. Avec les points 1 et 4, on sait seulement que le
problème se trouve quelque part sur le chemin.

Méthodes de capture possibles : port miroir (SPAN) d'un switch, TAP
matériel, `tcpdump`/`dumpcap` directement sur un hôte, capture distante
via SSH ([Capture distante](../capture-distante.md)), miroir de trafic de
l'hyperviseur ou du cloud. Le README détaille chacune d'elles, section
« Solutions de capture prises en charge ».

Donnez à chaque point un **nom court et parlant** (`POSTE`, `LAN`, `WAN`,
`DC`...) et notez l'équipement physique auquel il correspond. Netcross
retrouve l'ordre des points tout seul, mais il ne peut pas deviner que
`WAN` est la sortie du pare-feu du 2e étage.

## Les règles qui comptent

1. **Capturer en même temps.** Lancez toutes les captures avant de
   reproduire le problème et arrêtez-les après. Deux captures qui ne se
   recouvrent pas dans le temps ne peuvent pas être corrélées.
2. **Synchroniser les horloges** (NTP, idéalement PTP) de toutes les
   machines de capture. Sans cela, Netcross estime le décalage à partir
   des poignées de main TCP et corrige la latence, mais la latence brute
   n'est plus fiable.
3. **Ne pas tronquer les paquets** : `tcpdump -s 0`, ou `dumpcap` sans
   limite de taille. Un paquet tronqué empêche l'analyse de DNS, HTTP, SIP,
   RTP et DHCP, ainsi que la corrélation à travers un NAT.
4. **Désactiver les offloads de la carte réseau** sur les hôtes qui
   capturent eux-mêmes, pour voir les paquets tels qu'ils circulent sur le
   câble et non tels que le pilote les reconstitue :
   `sudo ethtool -K eth0 gro off lro off tso off gso off`.
5. **Préférer le format pcapng** : il enregistre l'horodatage en
   nanosecondes, utile quand les points sont proches et la latence faible.

Exemple sur un hôte Linux, capture limitée au trafic vers le serveur
concerné :

```bash
sudo tcpdump -i eth0 -s 0 -w poste.pcapng host 203.0.113.10
```

## Cas particuliers

- **Un NAT ou un PAT entre deux points** modifie les adresses et les
  ports : ajoutez `--nat-tolerant` (ou cochez « Corrélation tolérante au
  NAT » dans l'interface). Netcross reconnaît alors les paquets à leur
  contenu plutôt qu'à leurs adresses.
- **Une capture découpée en plusieurs fichiers** (rotation `tcpdump -C` ou
  `tshark -b`) : donnez tous les fichiers au même point, séparés par des
  virgules et dans l'ordre chronologique, sans les fusionner :
  `--capture LAN=lan_00001.pcapng,lan_00002.pcapng`. Dans l'interface
  graphique, ajoutez chaque fichier et donnez le même nom à toutes ces
  lignes, dans l'ordre chronologique. Avec l'API, répétez l'étiquette dans
  `labels` (`POST /captures/multi`, par exemple `labels=LAN,LAN,DC`), ou
  envoyez les segments suivants dans `extra_files` (`POST /captures`).
- **Plusieurs captures dans un seul fichier pcapng** (capture sur plusieurs
  interfaces, fichiers concaténés, `mergecap -I none`) : ajoutez
  `--split-interfaces`. Chaque interface du fichier devient un point nommé
  `NOM:INTERFACE`, et l'analyse croisée se fait entre elles :
  `--capture SITE=site.pcapng --split-interfaces`. Attention : sans
  `-I none`, `mergecap` fusionne les interfaces décrites à l'identique,
  qui ne sont alors plus séparables. Dans l'interface graphique, cochez
  « Séparer les interfaces d'un pcapng ». Avec l'API, passez
  `split_interfaces=true` à `POST /captures/multi` (voir
  [Automatiser avec l'API](api.md)).
- **Des données sensibles** : `--redact` remplace les adresses IP et MAC
  par des pseudonymes avant l'analyse, par exemple pour transmettre un
  rapport à un prestataire.
