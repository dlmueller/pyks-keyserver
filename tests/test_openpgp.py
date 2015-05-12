# -*- coding: utf-8 -*-
"""
Checks the functionality expected from the OpenPGP-Python package
"""

#---
#--- Python
import os
import unittest
import sys

#---
#--- Extend Python search path
sys.path.append(os.getcwd())

#---
import testhelpers

#--- ThirdParty SUT
from pyks import openpgp

class OpenPGPTest(unittest.TestCase) :

    def setUp(self) :
        self.publicKey_data = testhelpers.readBinaryFile("data/ascii-armor-public-key.gpg")

    def test_smoketest(self) :
        data = self.publicKey_data
        self.assertEqual(data[0], '\x99')

    def test_public_key_packet(self) :
        data = self.publicKey_data
        loadedKeys = openpgp.load_keys(data)
        self.assertEqual(1, len(loadedKeys), "expected exactly one key")
        for k in loadedKeys :
            self.assertEqual(openpgp.fingerprint(k), '5E8C8A788F2685BB19306180890A4614448701A8')
            self.assertEqual(openpgp.key_id(k), '448701A8')
            break

if __name__ == "__main__" :
    unittest.main()
