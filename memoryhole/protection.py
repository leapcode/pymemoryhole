from email.mime.application import MIMEApplication
from email.utils import getaddresses, parseaddr

from memoryhole.gpg import Gnupg
from memoryhole.rfc3156 import PGPEncrypted, MultipartEncrypted


def protect(msg, openpgp=Gnupg(), encrypt=True, obscure=True):
    """
    Protect an email with memory hole. It will protect the PROTECTED_HEADERS
    and if obscure=True will obscure the OBSCURED_HEADERS

    :param msg: the email to be protected
    :type msg: Message
    :param openpgp: the implementation of openpgp to use for encryption and/or
                    signature
    :type openpgp: OpenPGP
    :param encrypt: should the message be encrypted
    :type encrypt: bool
    :param obscure: should the headers be obscured
    :type obsucre: bool

    :return: an encrypted and/or signed email
    :rtype: Message
    """
    if encrypt:
        return _encrypt_mime(msg, openpgp)

    raise NotImplementedError()


def _encrypt_mime(msg, openpgp):
    newmsg = MultipartEncrypted('application/pgp-encrypted')
    for hkey, hval in msg.items():
        newmsg.add_header(hkey, hval)
        del(msg[hkey])

    encraddr = ""  # TODO
    signaddr = ""  # TODO
    encstr = openpgp.encrypt(msg.as_string(unixfrom=False),
                             encraddr, signaddr)
    encmsg = MIMEApplication(
        encstr, _subtype='octet-stream', _encoder=lambda x: x)
    encmsg.add_header('content-disposition', 'attachment',
                      filename='msg.asc')

    # create meta message
    metamsg = PGPEncrypted()
    metamsg.add_header('Content-Disposition', 'attachment')
    # attach pgp message parts to new message
    newmsg.attach(metamsg)
    newmsg.attach(encmsg)
    return newmsg
