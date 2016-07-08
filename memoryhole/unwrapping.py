try:
        from StringIO import StringIO
except ImportError:
        from io import StringIO
from copy import deepcopy
from email.parser import HeaderParser

from memoryhole.errors import MalformedMessage
from memoryhole.gpg import Gnupg
from memoryhole.message import MemoryHoleMessage, parsemsg, to_memoryhole

import sys
if sys.version_info.major >= 3 and sys.version_info.minor >= 3:
    from email.generator import Generator
else:
    from memoryhole.rfc3156 import Generator


MULTIPART_ENCRYPTED = "multipart/encrypted"
MULTIPART_SIGNED = "multipart/signed"
TEXT_HEADERS = "text/rfc822-headers"


def unwrap(msg, openpgp=Gnupg()):
    """
    Unwrap an email replacing and verifying memory hole headers.

    :param msg: the email to be unwrapped
    :type msg: Message
    :param openpgp: the implementation of openpgp to use for decryption and/or
                    verification
    :type openpgp: OpenPGP

    :return: a decrypted email
    :rtype: MemoryHoleMessage
    """
    mhmsg = to_memoryhole(deepcopy(msg))
    rabbit_hole = _RabbitHole(mhmsg, openpgp)
    rabbit_hole.down()
    return mhmsg


class _RabbitHole(object):
    def __init__(self, mhmsg, openpgp):
        self.openpgp = openpgp
        self.mhmsg = mhmsg
        self._body_part = mhmsg
        self._force_display = None

    def down(self):
        self._down(self.mhmsg)
        self.mhmsg.set_body_part(self._body_part)
        self._replace_payload_headers(self._force_display)
        self._replace_mime_headers(self._body_part)

    def _down(self, msg):
        if msg.get_content_type() == MULTIPART_ENCRYPTED:
            self._encrypted_sanity_check(msg)
            decrmsg = self._decrypt(msg)
            msg.set_payload(decrmsg.get_payload())
            msg.set_type(decrmsg.get_content_type())
            self._set_mimepart(decrmsg)
            self._down(msg)

        elif msg.get_content_type() == MULTIPART_SIGNED:
            self._signed_sanity_check(msg)
            signedpart = self._verify(msg)
            self._set_mimepart(signedpart)
            self._down(signedpart)

        elif (msg.get_content_type() == TEXT_HEADERS and
                self._force_display is None and
                self._body_part.encrypted == msg.encrypted and
                self._body_part.signed == msg.signed):
            self._force_display = msg

        elif msg.is_multipart():
            for payload in msg.get_payload():
                childmsg = to_memoryhole(payload, msg.signed, msg.encrypted)
                self._down(childmsg)

    def _decrypt(self, msg):
        pgpencmsg = msg.get_payload()[1]
        encdata = pgpencmsg.get_payload()
        decrdata, enckey, signkey = self.openpgp.decrypt(encdata)
        msg.append_encrypted(enckey)
        msg.append_signed(signkey)
        return parsemsg(decrdata, msg.signed, msg.encrypted)

    def _verify(self, msg):
        data = self._serialize_msg(msg.get_payload(0))
        detached_sig = msg.get_payload(1).get_payload()
        valid, signkey = self.openpgp.verify(data, detached_sig)

        # TODO: what about with not valid signatures?
        part = to_memoryhole(msg.get_payload(0), msg.signed, msg.encrypted)
        if valid:
            part.append_signed(signkey)
        return part

    def _serialize_msg(self, msg):
        buf = StringIO()
        g = Generator(buf)
        g.flatten(msg)
        return buf.getvalue()

    def _set_mimepart(self, msg):
        if _bigger_protection(msg, self._body_part):
            self._body_part = msg
            self._force_display = None

    def _replace_mime_headers(self, msg):
        if msg is None or not msg.get_param('protected-headers'):
            return

        for name, value in msg.items():
            if name.lower() == 'content-type':
                continue
            print(name)
            self.mhmsg.add_protected_header(name, value)

    def _replace_payload_headers(self, msg):
        if msg is None or not msg.get_param('protected-headers'):
            return

        hstr = msg.get_payload()
        parser = HeaderParser()
        hmsg = parser.parsestr(hstr)

        for name, value in hmsg.items():
            self.mhmsg.add_protected_header(name, value, force_display=True)

    def _encrypted_sanity_check(self, msg):
        payload = msg.get_payload()
        if len(payload) != 2:
            raise MalformedMessage(
                'Multipart/encrypted messages should have exactly 2 body '
                'parts (instead of %d).' % len(payload))
        if payload[0].get_content_type() != 'application/pgp-encrypted':
            raise MalformedMessage(
                "Multipart/encrypted messages' first body part should "
                "have content type equal to 'application/pgp-encrypted' "
                "(instead of %s)." % payload[0].get_content_type())
        if payload[1].get_content_type() != 'application/octet-stream':
            raise MalformedMessage(
                "Multipart/encrypted messages' second body part should "
                "have content type equal to 'octet-stream' (instead of "
                "%s)." % payload[1].get_content_type())

    def _signed_sanity_check(self, msg):
        payload = msg.get_payload()
        if len(payload) != 2:
            raise MalformedMessage(
                'Multipart/signed messages should have exactly 2 body '
                'parts (instead of %d).' % len(payload))
        # TODO: what format should they have?


def _bigger_protection(p1, p2):
    if len(p1.encrypted) != len(p2.encrypted):
        return len(p1.encrypted) > len(p2.encrypted)

    return len(p1.signed) >= len(p2.signed)
