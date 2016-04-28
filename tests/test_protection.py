import base64
import unittest
from email.parser import Parser
from zope.interface import implementer

from memoryhole import protect, OpenPGP


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
    def test_pgp_mime(self):
        p = Parser()
        msg = p.parsestr(EMAIL)
        encrypter = Encrypter()
        encmsg = protect(msg, encrypter)

        self.assertEqual(encmsg.get_payload(1).get_payload(), encrypter.encstr)
        self.assertEqual(BODY, encrypter.data[1:-1])  # remove '\n'
        self.assertEqual(encmsg.get_content_type(), "multipart/encrypted")


@implementer(OpenPGP)
class Encrypter(object):
    encstr = "this is encrypted"

    def encrypt(self, data, encraddr, singaddr):
        self.data = data
        return self.encstr


if __name__ == "__main__":
    unittest.main()
