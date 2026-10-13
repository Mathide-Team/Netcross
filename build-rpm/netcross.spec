Name:           netcross
Version:        1.0.0
Release:        1%{?dist}
Summary:        Analyse croisee de captures Wireshark multi-points
License:        MIT
URL:            https://github.com/MathildeDec/netcross
BuildArch:      noarch

# paquet "native" sans tarball amont : les sources sont copiees dans le
# repertoire de build par build-rpm/build.sh avant l'appel a rpmbuild
Source0:        netcross-%{version}.tar.gz

Requires:       python3
# le paquet CLI de Wireshark (tshark, dumpcap...) s'appelle wireshark-cli
# sur Fedora/RHEL/Rocky recents -- sur des bases plus anciennes ou
# d'autres distributions RPM, il peut s'agir du paquet "wireshark" complet
Requires:       wireshark-cli
Requires:       python3-cryptography
# loguru est obligatoire depuis l'issue #245 (EPEL sur RHEL/Rocky)
Requires:       python3-loguru
Requires:       python3-reportlab
Requires:       python3-matplotlib
Requires:       python3-networkx
Recommends:     python3-gobject
Recommends:     gtk4
# API REST (netcross_api) et IA locale (netcross_ai) : optionnels
Suggests:       python3-fastapi
Suggests:       python3-uvicorn
Suggests:       python3-scikit-learn

%description
netcross correle plusieurs captures reseau (.pcap/.pcapng) prises en
differents points d'un chemin reseau pour du depannage : pertes,
latence/gigue, TTL et topologie deduite automatiquement, QoS, saturation
et bufferbloat, fragmentation/MTU, tunnels (MPLS/GRE/VXLAN/GTP-U/ERSPAN/
CAPWAP), DHCP, SIP, RTP/MOS, et decomposition reseau vs serveur.

Fournit un CLI (netcross), un CLI de comparaison avant/apres
(netcross-diff), un CLI d'interrogation de l'historique --history-db
(netcross-history), une documentation hors ligne de l'API Lua
Wireshark (netcross-lua-doc), un generateur de rapport PDF, et une interface
graphique GTK4 optionnelle (netcross-gui, necessite les paquets
Recommends python3-gobject et gtk4 -- disponibilite variable selon la
version de RHEL/Rocky, voir le README du depot).

%prep
%setup -q

%build
# rien a compiler (Python pur)

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_datadir}/netcross
mkdir -p %{buildroot}%{_bindir}

cp -r pcap_parser %{buildroot}%{_datadir}/netcross/
cp -r netcross_core %{buildroot}%{_datadir}/netcross/
cp -r netcross_report %{buildroot}%{_datadir}/netcross/
cp -r netcross_gtk4 %{buildroot}%{_datadir}/netcross/
cp -r netcross_api %{buildroot}%{_datadir}/netcross/
cp -r netcross_ai %{buildroot}%{_datadir}/netcross/
cp cross_capture_analyzer_cli.py %{buildroot}%{_datadir}/netcross/
cp cross_capture_diff_cli.py %{buildroot}%{_datadir}/netcross/
cp cross_history_cli.py %{buildroot}%{_datadir}/netcross/
cp cross_capture_batch_cli.py %{buildroot}%{_datadir}/netcross/
cp netcross_ai_models_cli.py %{buildroot}%{_datadir}/netcross/
cp netcross_lua_doc_cli.py %{buildroot}%{_datadir}/netcross/
cp netcross_annotations_cli.py %{buildroot}%{_datadir}/netcross/
mkdir -p %{buildroot}%{_datadir}/netcross/data
cp data/lua_api.json %{buildroot}%{_datadir}/netcross/data/
mkdir -p %{buildroot}%{_datadir}/locale
cp -r locale/* %{buildroot}%{_datadir}/locale/

install -m 755 netcross-wrapper %{buildroot}%{_bindir}/netcross
install -m 755 netcross-gui-wrapper %{buildroot}%{_bindir}/netcross-gui
install -m 755 netcross-diff-wrapper %{buildroot}%{_bindir}/netcross-diff
install -m 755 netcross-history-wrapper %{buildroot}%{_bindir}/netcross-history
install -m 755 netcross-batch-wrapper %{buildroot}%{_bindir}/netcross-batch
install -m 755 netcross-ai-models-wrapper %{buildroot}%{_bindir}/netcross-ai-models
install -m 755 netcross-lua-doc-wrapper %{buildroot}%{_bindir}/netcross-lua-doc

%files
%{_datadir}/netcross/
%{_bindir}/netcross
%{_bindir}/netcross-gui
%{_bindir}/netcross-diff
%{_bindir}/netcross-history
%{_bindir}/netcross-batch
%{_bindir}/netcross-ai-models
%{_bindir}/netcross-lua-doc
%{_datadir}/locale/*/LC_MESSAGES/netcross.mo

%changelog
* Mon Aug 17 2026 Mathilde Deuscher <149895843+MathildeDec@users.noreply.github.com> - 1.0.0-1
- Version initiale : analyse croisee de captures multi-points, CLI,
  rapport PDF, interface GTK4.
