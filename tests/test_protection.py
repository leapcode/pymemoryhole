import six
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

parser = Parser()


def test_pgp_encrypted_mime():
    msg = parser.parsestr(EMAIL)
    encrypter = Encrypter()
    conf = ProtectConfig(openpgp=encrypter, obscured_headers=[])
    encmsg = protect(msg, config=conf)

    assert encmsg.get_payload(1).get_payload() == encrypter.encstr
    assert [TO] == encrypter.encraddr
    assert encmsg.get_content_type() == "multipart/encrypted"
    assert get_body(encrypter.data) == BODY + '\n'


def test_unobscured_headers():
    msg = parser.parsestr(EMAIL)
    encrypter = Encrypter()
    conf = ProtectConfig(openpgp=encrypter, obscured_headers=[])
    encmsg = protect(msg, config=conf)

    assert encmsg['from'] == FROM
    assert encmsg['to'] == TO
    assert encmsg['subject'] == SUBJECT


def test_obscured_headers():
    msg = parser.parsestr(EMAIL)
    encrypter = Encrypter()
    conf = ProtectConfig(openpgp=encrypter)
    encmsg = protect(msg, config=conf)

    for header, value in conf.obscured_headers.items():
        msgheaders = encmsg.get_all(header, [])
        if msgheaders:
            assert msgheaders == [value]

    encpart = parser.parsestr(encrypter.data)
    assert encpart.get_content_type() == "multipart/mixed"

    rfc822part = encpart.get_payload(0)
    assert rfc822part.get_content_type() == "text/rfc822-headers"

    rfc822body = "Subject: %s\n" % (SUBJECT,)
    assert rfc822part.get_payload() == rfc822body
    assert encpart.get_payload(1).get_payload() == BODY+'\n'


def test_pgp_signed_mime():
    msg = parser.parsestr(EMAIL)
    signer = Signer()
    conf = ProtectConfig(openpgp=signer)
    encmsg = protect(msg, encrypt=False, config=conf)

    b64body = b64encode(six.b(BODY+'\n'))
    assert six.b(encmsg.get_payload(0).get_payload()) == b64body
    assert encmsg.get_payload(1).get_payload() == signer.signature
    assert get_body(signer.data) == b64body.decode('utf-8')
    assert encmsg.get_content_type() == "multipart/signed"


def test_signed_headers():
    msg = parser.parsestr(EMAIL)
    signer = Signer()
    conf = ProtectConfig(openpgp=signer)
    signmsg = protect(msg, encrypt=False, config=conf)

    assert signmsg['from'] == FROM
    assert signmsg['to'] == TO
    assert signmsg['subject'] == SUBJECT

    signedpart = signmsg.get_payload(0)
    assert signedpart['from'] == FROM
    assert signedpart['to'] == TO
    assert signedpart['subject'] == SUBJECT


def get_body(data):
    return parser.parsestr(data).get_payload()


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
