"""PR jetable (#334) : échec volontaire pour vérifier que la protection de
`dev` bloque la fusion. À fermer sans fusionner."""

import pytest


def test_echec_volontaire_protection_dev():
    pytest.fail("échec volontaire : la protection de dev doit bloquer cette PR (#334)")
