from memoryhole.protection import protect
from memoryhole.openpgp import OpenPGP
from memoryhole.gpg import Gnupg


PROTECTED_HEADERS = ('Subject', 'Message-ID', 'Date', 'To', 'From')
OBSCURED_HEADERS = ('Subject', 'Message-ID', 'Date', 'To', 'From')


def unwrap(msg, opengp=Gnupg()):
    raise NotImplementedError()


__all__ = ["protect", "unwrap", "OpenPGP"]
