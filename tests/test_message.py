from memoryhole import message

import pytest


def test_protection_level():
    pl0 = message.ProtectionLevel(signed_by=['alice'], encrypted_by=['alice'])
    pl1 = message.ProtectionLevel(signed_by=['alice'])
    pl2 = message.ProtectionLevel(encrypted_by=['alice'])
    pl3 = message.ProtectionLevel()
    assert pl0 > pl1
    assert pl1 > pl2
    assert pl2 > pl3
    assert pl0 == pl0
    assert pl1 == pl1
    assert pl2 == pl2
    assert pl2 < pl1
    assert pl1 < pl0


def test_compare_wrong_types():
    pl0 = message.ProtectionLevel(signed_by=['alice'])
    with pytest.raises(TypeError):
        assert pl0 > 1
