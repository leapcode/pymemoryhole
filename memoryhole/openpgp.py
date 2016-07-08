from zope.interface import Interface


class IOpenPGP(Interface):
    def encrypt(self, data, encraddr):
        """
        Encrypt and sign data.

        :param data: data to be encrypted
        :type data: str
        :param encraddr: list of email addresses to encrypt to
        :type encraddr: [str]
        :param singaddr: email address to sign with
        :type singaddr: str

        :return: encrypted and signed data
        :rtype: str
        """
        pass

    def sign(self, data):
        """
        Sign data.

        :param data: data to be encrypted
        :type data: str

        :return: signature
        :rtype: str
        """
        pass

    def decrypt(self, data):
        """
        Decrypt and verify data.

        :param data: data to be decrypted
        :type data: str

        :return: decrypted data, the fingerprint of the key used for the
                 decryption and the fingerprint of the key that signed it
        :rtype: str, str, str
        """
        pass

    def verify(self, data, signature):
        """
        Verify a signature.

        :param data: data to be virified
        :type data: str
        :param signature: detached signature
        :type signature: str

        :return: is signature valid and the fingerprint of the key that signed
                 it
        :rtype: bool, str
        """
        pass
