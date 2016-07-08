from collections import namedtuple
from email.message import Message
from email.parser import Parser


HeaderReplacement = namedtuple("HeaderReplacement",
                               ("force_display", "orig_value"))


class MemoryHoleMessage(Message):

    @property
    def signed(self):
        return getattr(self, '_signed', set())

    @property
    def encrypted(self):
        return getattr(self, '_encrypted', set())

    @property
    def body_part(self):
        return getattr(self, '_body_part', None)

    @property
    def headers_signed(self):
        return self._body_part.signed

    @property
    def headers_encrypted(self):
        return self._body_part.encrypted

    def is_header_signed(self, header_name):
        return header_name.lower() in self._mh_headers

    def header_replacement(self, header_name):
        return self._mh_headers.get(header_name.lower())

    def append_signed(self, fingerprint):
        self._signed.add(fingerprint)

    def append_encrypted(self, fingerprint):
        self._encrypted.add(fingerprint)

    def set_body_part(self, part):
        self._body_part = part

    def add_protected_header(self, name, value, force_display=False):
        if not self._body_part:
            raise MalformedMessage("Couldn't find a body in the message")

        name = name.lower()

        if name in self._mh_headers:
            return

        encrypted = self._body_part.encrypted
        signed = self._body_part.signed

        orig_value = None
        if name in self:
            orig_value = self[name]
            self.replace_header(name, value)
        else:
            self.add_header(name, value)

        # TODO: what about errors on date of minutes?
        #       or subject with something added to it?
        replacement = None
        if encrypted and (not orig_value or value not in orig_value):
            replacement = HeaderReplacement(force_display, orig_value)
        self._mh_headers[name] = replacement


def parsemsg(msgstr, signed=None, encrypted=None):
    parser = Parser()
    msg = parser.parsestr(msgstr)
    return to_memoryhole(msg, signed, encrypted)


def to_memoryhole(msg, signed=None, encrypted=None):
    msg.__class__ = MemoryHoleMessage

    msg._signed = set()
    if signed is not None:
        msg._signed = signed
    msg._encrypted = set()
    if encrypted is not None:
        msg._encrypted = encrypted

    msg._mh_headers = {}
    msg._body_part = msg
    return msg
