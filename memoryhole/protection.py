from email.mime.application import MIMEApplication

from memoryhole.gpg import Gnupg
from memoryhole.rfc3156 import PGPEncrypted, MultipartEncrypted


def protect(msg, openpgp=Gnupg(), encrypt=True, obscure=True):
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
