from zope.interface import Interface


class IOpenPGP(Interface):
    def encrypt(data, encraddr, singaddr):
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

    def decrypt(data):
        """
        Decrypt and verify data.

        :param data: data to be decrypted
        :type data: str

        :return: decrypted data
        :rtype: str
        """
        # What about verification???
        pass

    def verify(data, signature):
        """
        Verify a signature.

        :param data: data to be virified
        :type data: str
        :param signature: detached signature
        :type signature: str

        :return: is signature valid
        :rtype: bool
        """
        pass
