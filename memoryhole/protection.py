import re

try:
        from StringIO import StringIO
except ImportError:
        from io import StringIO
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import getaddresses
from copy import deepcopy

from memoryhole.gpg import Gnupg
from memoryhole.rfc3156 import (
    PGPEncrypted, MultipartEncrypted, RFC3156CompliantGenerator,
    MultipartSigned, PGPSignature, encode_base64_rec
)


class ProtectConfig(object):

    PROTECTED_HEADERS = ('subject', 'message-id', 'date', 'to', 'from')
    OBSCURED_HEADERS = {
        'subject': 'encrypted email',
        'message-id': 'C@memoryhole.example',
        'date': 'Thu, 1 Jan 1970 00:00:00 +0000',
    }

    def __init__(self, openpgp=None, protected_headers=PROTECTED_HEADERS,
                 obscured_headers=OBSCURED_HEADERS):
        """
        Configuration parameters for the protection

        :param openpgp: the implementation of openpgp to use for encryption
                        and/or signature
        :type openpgp: IOpenPGP
        :param protected_headers: list of headers to protect in the signed
                                  part, they need to be in lower case
        :type protected_headers: [str]
        :param obscured_headers: list of headers to obscure replacing it by
                                 a predefined value in the email headers,
                                 the headers need to be in lower case
        :type obscured_headers: {str: str}
        """
        if openpgp is None:
            openpgp = Gnupg()
        self.openpgp = openpgp

        self.protected_headers = protected_headers
        self.obscured_headers = obscured_headers


def protect(msg, encrypt=True, config=None):
    """
    Protect an email with memory hole. It will protect the
    config.protected_headers and will obscure the config.obscured_headers

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

    newmsg, part = _protect_headers(
        msg, MultipartEncrypted('application/pgp-encrypted'), config)
    if config.obscured_headers:
        newmsg, part = _obscure_headers(newmsg, part, config)

    encstr = config.openpgp.encrypt(part.as_string(unixfrom=False), encraddr)
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
    newmsg, part = _protect_headers(
        msg, MultipartSigned('application/pgp-signature', 'pgp-sha512'),
        config)

    # apply base64 content-transfer-encoding
    encode_base64_rec(part)
    # get message text with headers and replace \n for \r\n
    fp = StringIO()
    g = RFC3156CompliantGenerator(fp, mangle_from_=False, maxheaderlen=76)
    g.flatten(part)
    msgtext = re.sub('\r?\n', '\r\n', fp.getvalue())
    # make sure signed message ends with \r\n as per OpenPGP stantard.
    if msg.is_multipart() and not msgtext.endswith("\r\n"):
        msgtext += "\r\n"

    signature = config.openpgp.sign(msgtext)
    sigmsg = PGPSignature(signature)

    # attach original message and signature to new message
    newmsg.attach(part)
    newmsg.attach(sigmsg)
    return newmsg


def _obscure_headers(msg, part, config):
    headers = ""
    for header, value in msg.items():
        if header.lower() in config.obscured_headers:
            headers += header + ": " + value + "\n"
    headerspart = MIMEText(headers, 'rfc822-headers')
    # TODO: should this be an attachment????
    newpart = MIMEMultipart('mixed', _subparts=[headerspart, part])

    for header, value in config.obscured_headers.items():
        if header in msg:
            del(msg[header])
            if value:
                msg.add_header(header, value)
    return msg, newpart


def _protect_headers(oldmsg, newmsg, config):
    part = deepcopy(oldmsg)
    for header, value in part.items():
        newmsg.add_header(header, value)
        if header.lower() not in config.protected_headers:
            del(part[header])
    return newmsg, part


def _recipient_addresses(msg):
    recipients = []
    for header in ('to', 'cc', 'bcc'):
        recipients += msg.get_all(header, [])
    return [r[1] for r in getaddresses(recipients)]
