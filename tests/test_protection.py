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
        conf = ProtectConfig(openpgp=encrypter, obscured_headers=[])
        encmsg = protect(msg, config=conf)

        self.assertEqual(encmsg.get_payload(1).get_payload(), encrypter.encstr)
        self._assert_body(encrypter.data, BODY+'\n')
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

    def test_obscured_headers(self):
        p = Parser()
        msg = p.parsestr(EMAIL)
        encrypter = Encrypter()
        conf = ProtectConfig(openpgp=encrypter)
        encmsg = protect(msg, config=conf)

        for header, value in conf.obscured_headers.items():
            msgheaders = encmsg.get_all(header, [])
            if msgheaders:
                self.assertEqual(msgheaders, [value])

        encpart = p.parsestr(encrypter.data)
        self.assertEqual(encpart.get_content_type(), "multipart/mixed")
        rfc822part = encpart.get_payload(0)
        self.assertEqual(rfc822part.get_content_type(), "text/rfc822-headers")
        rfc822body = "Subject: %s\n" % (SUBJECT,)
        self.assertEqual(rfc822part.get_payload(), rfc822body)
        self.assertEqual(encpart.get_payload(1).get_payload(),
                         BODY+'\n')

    def test_pgp_signed_mime(self):
        p = Parser()
        msg = p.parsestr(EMAIL)
        signer = Signer()
        conf = ProtectConfig(openpgp=signer)
        encmsg = protect(msg, encrypt=False, config=conf)

        b64body = b64encode(six.b(BODY+'\n'))
        self.assertEqual(six.b(encmsg.get_payload(0).get_payload()), b64body)
        self.assertEqual(encmsg.get_payload(1).get_payload(), signer.signature)
        self._assert_body(signer.data, b64body.decode('utf-8'))
        self.assertEqual(encmsg.get_content_type(), "multipart/signed")

    def test_signed_headers(self):
        p = Parser()
        msg = p.parsestr(EMAIL)
        signer = Signer()
        conf = ProtectConfig(openpgp=signer)
        signmsg = protect(msg, encrypt=False, config=conf)

        self.assertEqual(signmsg['from'], FROM)
        self.assertEqual(signmsg['to'], TO)
        self.assertEqual(signmsg['subject'], SUBJECT)

        signedpart = signmsg.get_payload(0)
        self.assertEqual(signedpart['from'], FROM)
        self.assertEqual(signedpart['to'], TO)
        self.assertEqual(signedpart['subject'], SUBJECT)

    def _assert_body(self, data, body):
        p = Parser()
        msg = p.parsestr(data)
        self.assertEqual(msg.get_payload(), body)


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
