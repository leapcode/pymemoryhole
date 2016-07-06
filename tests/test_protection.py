import six
import unittest
from base64 import b64encode
from email.parser import Parser
from zope.interface import implementer

from memoryhole import protect, ProtectConfig, IOpenPGP


FROM = "me@domain.com"
TO = "you@other.com"
SUBJECT = "some subject"
BODY = "body text"
EMAIL = """From: %(from)s
To: %(to)s
Subject: %(subject)s

%(body)s
""" % {
    "from": FROM,
    "to": TO,
    "subject": SUBJECT,
    "body": BODY
}


class ProtectTest(unittest.TestCase):
    def test_pgp_encrypted_mime(self):
        p = Parser()
        msg = p.parsestr(EMAIL)
        encrypter = Encrypter()
        conf = ProtectConfig(openpgp=encrypter)
        encmsg = protect(msg, config=conf)

        self.assertEqual(encmsg.get_payload(1).get_payload(), encrypter.encstr)
        self.assertEqual(BODY, encrypter.data[1:-1])  # remove '\n'
        self.assertEqual([TO], encrypter.encraddr)
        self.assertEqual(encmsg.get_content_type(), "multipart/encrypted")

    def test_unobscured_headers(self):
        p = Parser()
        msg = p.parsestr(EMAIL)
        encrypter = Encrypter()
        conf = ProtectConfig(openpgp=encrypter, obscured_headers=[])
        encmsg = protect(msg, config=conf)

        self.assertEqual(encmsg['from'], FROM)
        self.assertEqual(encmsg['to'], TO)
        self.assertEqual(encmsg['subject'], SUBJECT)

    def test_pgp_signed_mime(self):
        p = Parser()
        msg = p.parsestr(EMAIL)
        signer = Signer()
        conf = ProtectConfig(openpgp=signer)
        encmsg = protect(msg, encrypt=False, config=conf)

        b64body = b64encode(six.b(BODY+'\n'))
        self.assertEqual(six.b(encmsg.get_payload(0).get_payload()), b64body)
        self.assertEqual(encmsg.get_payload(1).get_payload(), signer.signature)
        self.assertEqual(
            six.b("Content-Transfer-Encoding: base64\r\n\r\n")+b64body,
            six.b(signer.data))
        self.assertEqual(encmsg.get_content_type(), "multipart/signed")

    def test_signed_headers(self):
        p = Parser()
        msg = p.parsestr(EMAIL)
        signer = Signer()
        conf = ProtectConfig(openpgp=signer)
        encmsg = protect(msg, encrypt=False, config=conf)

        self.assertEqual(encmsg['from'], FROM)
        self.assertEqual(encmsg['to'], TO)
        self.assertEqual(encmsg['subject'], SUBJECT)


@implementer(IOpenPGP)
class Encrypter(object):
    encstr = "this is encrypted"

    def encrypt(self, data, encraddr):
        self.data = data
        self.encraddr = encraddr
        return self.encstr


@implementer(IOpenPGP)
class Signer(object):
    signature = "this is a signature"

    def sign(self, data):
        self.data = data
        return self.signature


if __name__ == "__main__":
    unittest.main()
