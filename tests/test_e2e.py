from zope.interface import implementer

from memoryhole import protect, ProtectConfig, IOpenPGP, unwrap

from .common import dummy_msg, BODY


def test_encrypt_decrypt():
    openpgp = EncrypterDecrypter()
    conf = ProtectConfig(openpgp=openpgp)
    protected = protect(dummy_msg, config=conf)
    unwrapped = unwrap(protected, openpgp)

    assert unwrapped.signed == set((openpgp.signfp,))
    assert unwrapped.encrypted == set((openpgp.encfp,))
    assert unwrapped.headers_signed == set((openpgp.signfp,))
    assert unwrapped.headers_encrypted == set((openpgp.encfp,))
    assert unwrapped.body_part.get_payload(1).get_payload() == BODY + '\n'

    for header, value in unwrapped.items():
        if header in dummy_msg:
            assert value == dummy_msg[header]

        if header.lower() not in conf.replaced_headers:
            continue

        assert unwrapped.is_header_signed(header)
        replace = conf.replaced_headers[header.lower()]
        unwrap_replace = unwrapped.header_replacement(header)
        if unwrap_replace is None:
            assert replace is None
        else:
            assert unwrap_replace.force_display == replace.force_display
            assert unwrap_replace.orig_value == replace.replacement


@implementer(IOpenPGP)
class EncrypterDecrypter(object):
    encstr = "this is encrypted"
    encfp = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
    signfp = "1111111111111111111111111111111111111111"

    def encrypt(self, data, encraddr):
        self.encdata = data
        self.encraddr = encraddr
        return self.encstr

    def decrypt(self, data):
        assert data == self.encstr
        self.decdata = data
        return self.encdata, self.encfp, self.signfp
