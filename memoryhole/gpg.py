from gnupg import GPG
from zope.interface import implementer

from memoryhole.openpgp import OpenPGP


@implementer(OpenPGP)
class Gnupg(object):
    def __init__(self):
        self.gpg = GPG()

    def encrypt(self, data, encraddr, singaddr):
        # TODO
        encfp = 0
        signfp = 0
        return self.gpg.encrypt(data, encfp, default_key=signfp)

    def decrypt(self, data):
        pass

    def verify(self, data, signature):
        pass
