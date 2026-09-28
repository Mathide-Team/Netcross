"""Issue #760 : SSH HASSH ne doit pas planter sur des donnees non-SSH."""

from netcross_core.fingerprint.ssh_hassh import identify, parse_kexinit


def test_parse_kexinit_payload_binaire_non_ssh_ne_plante_pas():
    """Des donnees binaires quelconques sur le port 22 ne doivent pas
    declencher un UnicodeDecodeError (issue #760)."""
    # Payload binaire avec des octets non-ASCII (similaire aux traces
    # TLS/SSL qui passent par le port 22 dans la capture de #760)
    payload = b"\x00\x00\x00\xad\x00\x14" + b"\x89\xad\xe5\xb4\x8c" * 20
    result = parse_kexinit(payload)
    # Doit retourner None ou un dict, jamais lever une exception
    assert result is None or isinstance(result, dict)


def test_parse_kexinit_payload_avec_banniere_ssh_et_donnees_non_ascii():
    """Une banniere SSH suivie de donnees non-ASCII ne doit pas planter."""
    payload = b"SSH-2.0-OpenSSH_8.9\r\n" + b"\x00\x00\x00\xad\x00\x14" + b"\x89\xad\xe5\xb4\x8c" * 20
    result = parse_kexinit(payload)
    assert result is None or isinstance(result, dict)


def test_identify_donnees_non_ssh_ne_plante_pas():
    """identify() sur des donnees non-SSH ne doit pas planter (issue #760).
    Peut retourner None ou un resultat avec des algorithmes errones --
    l'important est l'absence d'exception."""
    payload = b"\x00\x00\x00\xad\x00\x14" + b"\x89\xad\xe5\xb4\x8c" * 20
    # Ne doit pas lever UnicodeDecodeError/UnicodeEncodeError
    result = identify(payload, sport=51234, dport=22)
    assert result is None or isinstance(result, tuple)
