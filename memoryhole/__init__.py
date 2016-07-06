from memoryhole.protection import protect
from memoryhole.openpgp import OpenPGP
from memoryhole.gpg import Gnupg


PROTECTED_HEADERS = ('Subject', 'Message-ID', 'Date', 'To', 'From')
OBSCURED_HEADERS = ('Subject', 'Message-ID', 'Date', 'To', 'From')


def unwrap(msg, opengp=Gnupg()):
    """
    Unwrap an email replacing and verifying memory hole headers.

    :param msg: the email to be unwrapped
    :type msg: Message
    :param openpgp: the implementation of openpgp to use for decryption and/or
                    verification
    :type openpgp: OpenPGP

    :return: a dencrypted email
    :rtype: Message
    """
    raise NotImplementedError()


__all__ = ["protect", "unwrap", "OpenPGP"]
