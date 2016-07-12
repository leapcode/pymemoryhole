import re

try:
        from StringIO import StringIO
except ImportError:
        from io import StringIO
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import getaddresses
from collections import namedtuple
from copy import deepcopy

from memoryhole.gpg import Gnupg
from memoryhole.rfc3156 import (
    PGPEncrypted, MultipartEncrypted, RFC3156CompliantGenerator,
    MultipartSigned, PGPSignature, encode_base64_rec
)


class ProtectConfig(object):

    Replace = namedtuple("Replace", ("force_display", "replacement"))

    REPLACED_HEADERS = {
        "subject": Replace(True, "encrypted email"),
        "message-id": Replace(True, "C@memoryhole.example"),
        "date": Replace(True, "Thu, 1 Jan 1970 00:00:00 +0000"),
        "in-reply-to": Replace(False, None),
        "references": Replace(False, None),
        "user-agent": Replace(False, None),
    }

    def __init__(self, openpgp=None, replaced_headers=REPLACED_HEADERS):
        """
        Configuration parameters for the protection.

        For encrypted emails the header will be replaced if they are present in
        the replaced_headers list. Each header will be putted in the MIMEpart
        headers unless 'force_display' is True. Top level headers will be
        replaced by 'replacement' unless 'replacement' is None, in which case
        the header will be removed completely from the top level headers.

        All header names need to be in lower case.

        :param openpgp: the implementation of openpgp to use for encryption
                        and/or signature
        :type openpgp: IOpenPGP
        :param replaced_headers: a dict of headers to be replaced
        :type replaced_headers: {str: Header}
        """
        if openpgp is None:
            openpgp = Gnupg()
        self.openpgp = openpgp

        self.replaced_headers = replaced_headers


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
    if config.replaced_headers:
        newmsg, part = _replace_headers(newmsg, part, config)

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


def _replace_headers(msg, part, config):
    headers = ""
    for header, value in msg.items():
        h = header.lower()
        if (h in config.replaced_headers and
                config.replaced_headers[h].force_display):
            headers += header + ": " + value + "\n"
    headerspart = MIMEText(headers, 'rfc822-headers')
    headerspart.set_param('protected-headers', 'v1')
    newpart = MIMEMultipart('mixed', _subparts=[headerspart, part])

    for header, value in config.replaced_headers.items():
        if header in msg:
            del(msg[header])
            if value.replacement is not None:
                msg.add_header(header, value.replacement)
    return msg, newpart


def _protect_headers(oldmsg, newmsg, config):
    part = deepcopy(oldmsg)
    part.set_param('protected-headers', 'v1')
    for header, value in part.items():
        newmsg.add_header(header, value)
    return newmsg, part


def _recipient_addresses(msg):
    recipients = []
    for header in ('to', 'cc', 'bcc'):
        recipients += msg.get_all(header, [])
    return [r[1] for r in getaddresses(recipients)]
