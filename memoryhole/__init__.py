from memoryhole.protection import protect, ProtectConfig
from memoryhole.openpgp import IOpenPGP
from memoryhole.gpg import Gnupg


def unwrap(msg, opengp=Gnupg()):
    """
    Unwrap an email replacing and verifying memory hole headers.

    :param msg: the email to be unwrapped
    :type msg: Message
    :param openpgp: the implementation of openpgp to use for decryption and/or
                    verification
    :type openpgp: OpenPGP

    :return: a decrypted email
    :rtype: Message
    """
    raise NotImplementedError()


__all__ = ["protect", "ProtectConfig", "unwrap", "IOpenPGP"]
