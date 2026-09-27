# Installation

Netcross s'appuie sur **tshark**, la version en ligne de commande de
Wireshark, pour décoder les captures. C'est le seul prérequis
indispensable : sans lui, aucune capture ne peut être lue.

## Paquet Debian/Ubuntu ou RHEL/Rocky (recommandé)

Les paquets `.deb` et `.rpm` installent toutes les commandes dans
`/usr/bin` (`netcross`, `netcross-diff`, `netcross-gui`...) et tirent
leurs dépendances système, `tshark` compris. GTK4 n'est que
« recommandé » : sur un serveur sans interface graphique, la ligne de
commande fonctionne sans lui. Leur construction est décrite
dans le README, section « Construire les paquets .deb / .rpm ».

```bash
sudo apt install ./netcross_*.deb     # Debian / Ubuntu
sudo dnf install ./netcross-*.rpm     # RHEL / Rocky 8 et 9
```

## Depuis les sources, avec le script d'installation

```bash
git clone https://github.com/MathildeDec/Netcross.git netcross
cd netcross
./install.sh              # ligne de commande + interface graphique GTK4
./install.sh --cli-only   # ligne de commande et rapport PDF, sans GTK4
```

Le script reconnaît Debian, Ubuntu, RHEL, Rocky, CentOS et AlmaLinux
(sur les dérivés de RHEL, il active au besoin le dépôt EPEL). Il installe
`tshark` (`wireshark-cli` côté RHEL), les bibliothèques Python des rapports
et, sauf avec `--cli-only`, GTK4 et PyGObject pour l'interface graphique.
Sur une autre distribution, il s'arrête en indiquant les paquets à
installer : utilisez alors la méthode pip ci-dessous.

## Depuis les sources, avec pip

```bash
pip install -r requirements.txt
sudo apt install tshark                        # ou : sudo dnf install wireshark-cli
sudo apt install python3-gi gir1.2-gtk-4.0     # interface graphique uniquement
```

GTK4 et PyGObject ne s'installent pas proprement avec pip : ils viennent
toujours des paquets de la distribution.

Python 3.10 ou plus récent est requis.

## Vérifier l'installation

```bash
tshark --version | head -1
python3 src/cross_capture_analyzer_cli.py --help | head -3     # ou : netcross --help
```

Puis lancez l'analyse d'exemple décrite dans
[Première analyse](premiere-analyse.md) : si elle retrouve les 5 paquets
perdus, tout fonctionne.

## Capturer soi-même (optionnel)

Analyser des fichiers existants ne demande aucun droit particulier. La
**capture en direct** (`--live` ou la case « Capture en direct » de
l'interface) demande les mêmes droits que `tshark` : être root, ou
autoriser `dumpcap` à capturer. Sur Debian/Ubuntu :

```bash
sudo dpkg-reconfigure wireshark-common     # répondre « Oui »
sudo usermod -aG wireshark "$USER"         # puis se reconnecter
```
