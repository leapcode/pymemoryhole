import logging
import tempfile

import email
from email.message import Message
from email.header import Header
from email.MIMEMultipart import MIMEMultipart
from email.parser import Parser
from StringIO import StringIO

import gnupg

logger = logging.getLogger(__name__)

COPY_HEADERS = ('Subject', 'Message-ID', 'Date', 'To', 'From')


class ProtectionLevel(object):

    def __init__(self, signed_by, encrypted_by):

        self.signed_by = signed_by
        self.encrypted_by = encrypted_by

    # TODO add __cmp__

    @property
    def score(self):
        if self.signed_by and self.encrypted_by:
            return 3
        elif self.signed_by:
            return 2
        elif self.encrypted_by:
            return 1
        else:
            return 0

    def __repr__(self):
        return '<ProtectionLevel: sig(%s) encr(%s) score:%s>' % (
            len(self.signed_by), len(self.encrypted_by), self.score)


class MemoryHoleHeader(Header):

    def __init__(self, name, value):
        self._name = name
        self._value = value

        self._h = Header(value, header_name=name)

        self.signed_by = set([])
        self.encrypted_by = set([])

        self._firstlinelen = self._h._firstlinelen
        self._chunks = self._h._chunks
        self._continuation_ws = self._h._continuation_ws
        self._charset = self._h._charset

    @property
    def protection_level(self):
        return ProtectionLevel(self.signed_by, self.encrypted_by)

    def __repr__(self):
        return '<MemoryHoleHeader(%s) [%s: %s]>' % (
            self.protection_level.score, self._name, self._value)


class MemoryHoleMessage(Message):

    def __init__(self, msg, gpg):
        self._msg = msg
        self._gpg = gpg

        verified = verify_signature(msg, gpg)
        self.signed = verified.valid

        self._mh_headers = {}
        inner_headers = extract_wrapped_headers(msg)

        for name, value in inner_headers.items():
            mhh = MemoryHoleHeader(name, value)
            mhh.signed_by.add(verified.key_id)
            self._mh_headers[name] = mhh

        self._charset = self._msg._charset
        self._headers = self._msg._headers
        self._payload = self._msg._payload
        self.preamble = self._msg.preamble

    def get_protected_header(self, header_name):
        return self._mh_headers.get(header_name)

    # TODO add is_tampered_header
    # TODO add __getattr__, lookup the protected headers first


def extract_wrapped_headers(msg):
    top_payload = msg.get_payload()[0]
    if top_payload.get_content_type() == 'multipart/mixed':
        headers = _extract_attached_headers(top_payload)
        return headers


def verify_signature(msg, gpg):
    if not msg.get_content_type() == 'multipart/signed':
        logger.error('attempted to verify signature, but msg is not signed')
        return False
    payloads = msg.get_payload()
    body = payloads[0]
    attached_sig = payloads[1]

    if not attached_sig.get_content_type() == 'application/pgp-signature':
        logger.error('expected an attached signature')
        return False
    sig = _extract_sig_block(attached_sig.as_string())
    fd, sig_fname = tempfile.mkstemp()
    with open(sig_fname, 'w') as sigfile:
        sigfile.write(sig)

    body = body.as_string().replace('\n', '\r\n')
    verified = gpg.verify_file(StringIO(body), sig_file=sig_fname)
    return verified


def protect_message(basemsg, gpg, do_sign=True, boundary=None,
                    sign_digest_algo='SHA512', passphrase=None):

    msg = email.message.Message()
    _msg = MIMEMultipart(
        _subtype="signed", micalg="pgp-%s" % sign_digest_algo.lower(),
        protocol="application/pgp-signature")

    for hdr in COPY_HEADERS:
        msg[hdr] = basemsg[hdr]
    for hdr in _msg.keys():
        msg[hdr] = _msg[hdr]
    if boundary:
        msg.set_boundary(boundary())

    wrapper = _wrap_with_header(basemsg, boundary=boundary)
    msg.attach(wrapper)

    if do_sign:
        payload = wrapper.as_string().replace('\n', '\r\n')
        sig = gpg.sign(
            payload, detach=True,
            digest_algo=sign_digest_algo, clearsign=False,
            passphrase=passphrase)

        signed_msg = _make_signature_subpart(sig)
        msg.attach(signed_msg)
    return msg


def _extract_sig_block(text):
    sep = '\n'
    BEGIN = '-----BEGIN PGP SIGNATURE-----'
    sig_lines = text.split(sep)
    return sep.join(sig_lines[sig_lines.index(BEGIN):])


def _extract_attached_headers(msg):

    def split_header(line):
        sep = ': '
        split = line.split(sep)
        return (split[0], sep.join(split[1:]))

    first = msg.get_payload()[0]
    if first.get_content_type() == 'text/rfc822-headers':
        raw = first.get_payload()
        headers = dict([
            split_header(line) for line in filter(None, raw.split('\n'))])
        return headers


def _build_embedded_header(msg):
    r = ''
    for x in COPY_HEADERS:
        if msg.get(x):
            r += x + ': ' + msg.get(x) + '\n'
    return r


def _boundary_factory(start):
    counter = {'value': ord(start)}

    def _gen_boundary():
        boundary = chr(counter['value']) * 12
        counter['value'] -= 1
        return boundary
    return _gen_boundary



def _wrap_with_header(msg, boundary=None):
    body = email.message.Message()
    body.set_payload(msg.get_payload())
    body.add_header('Content-Type', msg['Content-Type'])

    emh = email.message.Message()
    emh.set_type('text/rfc822-headers')
    emh.add_header('Content-Disposition', 'attachment')
    emh.set_payload(_build_embedded_header(msg))
    del emh['MIME-Version']

    wrapper = email.message.Message()
    wrapper.set_type('multipart/mixed')
    if boundary:
        wrapper.set_boundary(boundary())

    wrapper.set_payload([emh, body])
    del wrapper['MIME-Version']
    return wrapper


def _make_signature_subpart(signature):
    message = Message()
    message['Content-Type'] = 'application/pgp-signature; name="signature.asc"'
    message.set_payload(str(signature))
    return message

if __name__ == "__main__":
    import os
    import sys
    import logging
    if os.environ.get('DEBUG'):
        logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 3:
        print "Usage: memoryhole mail_path key_path"
        sys.exit()
    msg_path = sys.argv[1]
    key_path = sys.argv[2]
    parser = Parser()
    gpg = gnupg.GPG(
        binary='/usr/bin/gpg',
        homedir='/tmp/memoryhole-tests/', use_agent=False)

    with open('tests/corpus/OpenPGP/' + key_path + '.key') as key_f:
        key_data = key_f.read()
        gpg.import_keys(key_data)
    with open('tests/corpus/OpenPGP/' + key_path + '.pgp') as key_f:
        key_data = key_f.read()
        gpg.import_keys(key_data)

    #if not gpg.list_keys():
        #key_input = gpg.gen_key_input(key_length=1024, key_type='RSA')
        #gpg.gen_key(key_input)

    with open(msg_path) as f:
        basetext = f.read()
    basemsg = parser.parsestr(basetext)

    boundary = _boundary_factory('c')
    msg = protect_message(
            basemsg, gpg, boundary=boundary,
            sign_digest_algo='SHA256', passphrase='_' + key_path + '_')
    print msg.as_string()
