from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from zope.interface import implementer

from memoryhole import unwrap, IOpenPGP
from memoryhole.rfc3156 import MultipartEncrypted, PGPEncrypted, PGPSignature
from memoryhole.unwrapping import MULTIPART_ENCRYPTED, MULTIPART_SIGNED

from .common import get_body, dummy_msg, BODY


def test_decrypt():
    decrypter = Decrypter()
    _encrypted(dummy_msg, BODY)
    unwrapped = unwrap(dummy_msg, decrypter)

    assert unwrapped.body_part.get_payload() == decrypter.decstr
    assert unwrapped.encrypted == set((decrypter.encfp,))
    assert unwrapped.signed == set((decrypter.signfp,))
    assert BODY == decrypter.data


def test_verify():
    signature = "this is a signature"

    verifier = Verifier()
    _signed(dummy_msg, BODY, signature)
    unwrapped = unwrap(dummy_msg, verifier)

    assert unwrapped.body_part.get_payload() == BODY
    assert unwrapped.encrypted == set()
    assert unwrapped.signed == set((verifier.signfp,))
    assert BODY == get_body(verifier.data)
    assert signature == verifier.signature


def _encrypted(msg, encstr):
    msg.set_type(MULTIPART_ENCRYPTED)
    encmsg = MIMEApplication(
        encstr, _subtype='octet-stream', _encoder=lambda x: x)
    encmsg.add_header('content-disposition', 'attachment',
                      filename='msg.asc')

    # create meta message
    metamsg = PGPEncrypted()
    metamsg.add_header('Content-Disposition', 'attachment')
    # attach pgp message parts to new message
    msg.set_payload([metamsg, encmsg])


def _signed(msg, body, signature):
    msg.set_type(MULTIPART_SIGNED)
    bodymsg = MIMEText(body)
    sigmsg = PGPSignature(signature)
    msg.set_payload([bodymsg, sigmsg])


@implementer(IOpenPGP)
class Decrypter(object):
    decstr = "this is decrypted"
    encfp = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
    signfp = "1111111111111111111111111111111111111111"

    def decrypt(self, data):
        self.data = data
        return self.decstr, self.encfp, self.signfp


@implementer(IOpenPGP)
class Verifier(object):
    valid = True
    signfp = "1111111111111111111111111111111111111111"

    def verify(self, data, signature):
        self.data = data
        self.signature = signature
        return self.valid, self.signfp
