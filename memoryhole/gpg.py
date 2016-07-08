import io
import os
import tempfile

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
        result = self.gpg.decrypt(data)
        self._check_gpg_error(result)
        signkey = None
        if result.valid:
            signkey = result.pubkey_fingerprint
        return result.data, result.fingerprint, signkey

    def verify(self, data, signature):
        sf, sfname = tempfile.mkstemp()
        with os.fdopen(sf, 'w') as sfd:
            sfd.write(detached_sig)
        result = self.gpg.verify_file(io.BytesIO(data), sig_file=sfname)
        os.unlink(sfname)
        self._check_gpg_error(result)
        return result.valid, result.fingerprint

    def _check_gpg_error(self, result):
        stderr = getattr(result, 'stderr', '')
        if getattr(result, 'ok', False) is not True:
            raise RuntimeError('Failed gnupg operation: %s' % stderr)
