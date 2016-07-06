from zope.interface import implementer

from memoryhole.openpgp import IOpenPGP


@implementer(IOpenPGP)
class Gnupg(object):
    def __init__(self):
        from gnupg import GPG
        self.gpg = GPG()

    def encrypt(self, data, encraddr):
        result = self.gpg.encrypt(data, *encraddr)
        self._check_gpg_error(result)
        return result.data

    def sign(self, data):
        result = self.gpg.sign(data)
        self._check_gpg_error(result)
        return result.data

    def decrypt(self, data):
        pass

    def verify(self, data, signature):
        pass

    def _check_gpg_error(self, result):
        stderr = getattr(result, 'stderr', '')
        if getattr(result, 'ok', False) is not True:
            raise RuntimeError('Failed gnupg operation: %s' % stderr)
