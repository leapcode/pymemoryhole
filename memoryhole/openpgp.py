from zope.interface import Interface


class OpenPGP(Interface):
    def encrypt(data, encraddr, singaddr):
        pass

    def decrypt(data):
        pass

    def verify(data, signature):
        pass
