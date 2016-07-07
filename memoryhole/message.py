from email.message import Message
from email.header import Header


class ProtectionLevel(object):

    def __init__(self, signed_by=None, encrypted_by=None):
        if signed_by is None:
            signed_by = set([])
        self.signed_by = signed_by

        if encrypted_by is None:
            encrypted_by = set([])
        self.encrypted_by = encrypted_by

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

    def __cmp__(self, other):
        try:
            return cmp(self.score, other.score)
        except AttributeError:
            raise TypeError('Tried to compare something that is '
                            'not a ProtectionLevel')

    def __eq__(self, other):
        try:
            return (not self.score < other.score and
                    not other.score < self.score)
        except AttributeError:
            raise TypeError('Not a ProtectionLevel')

    def __ne__(self, other):
        try:
            return (self.score < other.score or
                    other.score < self.score)
        except AttributeError:
            raise TypeError('Not a ProtectionLevel')

    def __gt__(self, other):
        try:
            return other.score < self.score
        except AttributeError:
            raise TypeError('Not a ProtectionLevel')

    def __ge__(self, other):
        try:
            return not self.score < other.score
        except AttributeError:
            raise TypeError('Not a ProtectionLevel')

    def __le__(self, other):
        try:
            return not other.score < self.score
        except AttributeError:
            raise TypeError('Not a ProtectionLevel')

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

        verified = False
        # verified = verify_signature(msg, gpg)
        self.signed = verified.valid

        self._mh_headers = {}
        # inner_headers = extract_wrapped_headers(msg)
        inner_headers = {}

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

    # TODO add is_tampered_header?
    # TODO add __getattr__, lookup the protected headers first
