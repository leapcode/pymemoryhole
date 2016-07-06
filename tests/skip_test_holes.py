import os
from email.parser import Parser

import unittest
import gnupg

from memoryhole import memoryhole


here = os.path.dirname(os.path.realpath(__file__))
corpus = os.path.join(here, 'corpus')
gpgdata = os.path.join(corpus, 'OpenPGP')


class MemoryHoleTest(unittest.TestCase):

    def setUp(self):
        self.gpg = gnupg.GPG(
            binary='/usr/bin/gpg',
            homedir='/tmp/memoryhole-tests', use_agent=False)

    def test_texthtml_signed(self):
        sampleid = 'A'
        keyowner = 'julia'
        _load_key(keyowner, self.gpg)

        orig = _get_raw_message(sampleid)
        boundary = _boundary_factory('c')
        expected = _load_expected_msg(sampleid)
        msg = memoryhole.protect_message(
            orig, self.gpg, boundary=boundary,
            sign_digest_algo='SHA256', passphrase='_' + keyowner + '_')
        # TODO -- how to compare messages??
        self.assertEqual(dict(msg), dict(expected))


def _load_key(keyname, gpg):
    with open(gpgdata + '/' + keyname + '.key') as keyf:
        keydata = keyf.read()
        gpg.import_keys(keydata)
    with open(gpgdata + '/' + keyname + '.pgp') as keyf:
        keydata = keyf.read()
        gpg.import_keys(keydata)


def _get_raw_message(identifier):
    path = os.path.join(corpus, 'sample.' + identifier + '.eml')
    return _parse(_load_file(path))


def _load_expected_msg(identifier):
    path = os.path.join(corpus, 'expected.' + identifier + '.eml')
    return _parse(_load_file(path))


def _load_file(path):
    with open(path) as f:
        raw = f.read()
    return raw


def _parse(raw):
    parser = Parser()
    return parser.parsestr(raw)


def _boundary_factory(start):
    counter = {'value': ord(start)}

    def _gen_boundary():
        boundary = chr(counter['value']) * 12
        counter['value'] -= 1
        return boundary
    return _gen_boundary


if __name__ == "__main__":
    unittest.main()
