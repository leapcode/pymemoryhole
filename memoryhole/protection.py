import re

try:
        from StringIO import StringIO
except ImportError:
        from io import StringIO
from email.mime.application import MIMEApplication
from email.utils import getaddresses

from memoryhole.gpg import Gnupg
from memoryhole.rfc3156 import (
    PGPEncrypted, MultipartEncrypted, RFC3156CompliantGenerator,
    MultipartSigned, PGPSignature, encode_base64_rec
)


class ProtectConfig(object):

    PROTECTED_HEADERS = ('Subject', 'Message-ID', 'Date', 'To', 'From')
    OBSCURED_HEADERS = ('Subject', 'Message-ID', 'Date', 'To', 'From')

    def __init__(self, openpgp=None, protected_headers=PROTECTED_HEADERS,
                 obscured_headers=OBSCURED_HEADERS):
        """
        Configuration parameters for the protection

        :param openpgp: the implementation of openpgp to use for encryption
                        and/or signature
        :type openpgp: IOpenPGP
        :param protected_headers: list of headers to protect
        :type protected_headers: [str]
        :param obscured_headers: list of headers to obscure
        :type obscured_headers: [str]
        """
        if openpgp is None:
            openpgp = Gnupg()
        self.openpgp = openpgp


def protect(msg, encrypt=True, config=None):
    """
    Protect an email with memory hole. It will protect the PROTECTED_HEADERS
    and if obscure=True will obscure the OBSCURED_HEADERS

    :param msg: the email to be protected
    :type msg: Message
    :param encrypt: should the message be encrypted
    :type encrypt: bool

    :return: an encrypted and/or signed email
    :rtype: Message
    """
    if config is None:
        config = ProtectConfig()

    if encrypt:
        return _encrypt_mime(msg, config)

    return _sign_mime(msg, config)


def _encrypt_mime(msg, config):
    encraddr = _recipient_addresses(msg)

    newmsg = MultipartEncrypted('application/pgp-encrypted')
    for hkey, hval in msg.items():
        newmsg.add_header(hkey, hval)
        del(msg[hkey])

    encstr = config.openpgp.encrypt(msg.as_string(unixfrom=False), encraddr)
    encmsg = MIMEApplication(
        encstr, _subtype='octet-stream', _encoder=lambda x: x)
    encmsg.add_header('content-disposition', 'attachment',
                      filename='msg.asc')

    # create meta message
    metamsg = PGPEncrypted()
    metamsg.add_header('Content-Disposition', 'attachment')
    # attach pgp message parts to new message
    newmsg.attach(metamsg)
    newmsg.attach(encmsg)
    return newmsg


def _sign_mime(msg, config):
    newmsg = MultipartSigned('application/pgp-signature', 'pgp-sha512')
    for hkey, hval in msg.items():
        newmsg.add_header(hkey, hval)
        del(msg[hkey])

    # apply base64 content-transfer-encoding
    encode_base64_rec(msg)
    # get message text with headers and replace \n for \r\n
    fp = StringIO()
    g = RFC3156CompliantGenerator(fp, mangle_from_=False, maxheaderlen=76)
    g.flatten(msg)
    msgtext = re.sub('\r?\n', '\r\n', fp.getvalue())
    # make sure signed message ends with \r\n as per OpenPGP stantard.
    if msg.is_multipart() and not msgtext.endswith("\r\n"):
        msgtext += "\r\n"

    signature = config.openpgp.sign(msgtext)
    sigmsg = PGPSignature(signature)
    # attach original message and signature to new message
    newmsg.attach(msg)
    newmsg.attach(sigmsg)
    return newmsg


def _recipient_addresses(msg):
    recipients = []
    for header in ('to', 'cc', 'bcc'):
        recipients += msg.get_all(header, [])
    return [r[1] for r in getaddresses(recipients)]
