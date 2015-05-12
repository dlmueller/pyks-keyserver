# -*- coding: utf-8 -*-
"""
"""

#---
#--- Python
import os
import os.path
import unittest
import sys

#---
#--- Extend Python search path
sys.path.append(os.getcwd())

#---
#--- SUT
from pyks import openpgp

#---
__all__ = ['OpenPGPAsciiArmorTest']


#---
class OpenPGPAsciiArmorTest(unittest.TestCase) :

    def setUp(self) :
        self.dirname = os.path.dirname(os.path.abspath(__file__))
        self.armorHeaders = {'Version':'GnuPG v2.0.22 (MingW32)'}
        self.publicKey_armored = os.path.join(self.dirname, "data/ascii-armor-public-key.asc")
        self.publicKey_binary = os.path.join(self.dirname, "data/ascii-armor-public-key.gpg")
        with open(self.publicKey_binary, "rb") as f :
            self.data = "".join(f.xreadlines())
        with open(self.publicKey_armored, "rt") as g :
            self.text = "".join(g.xreadlines())

    def test_asciiarmor_enarmor(self) :
        text = openpgp.ascii_enarmor(self.data, headers = self.armorHeaders)
        self.assertEqual(text, self.text)

    def test_asciiarmor_unarmor(self) :
        data = openpgp.ascii_unarmor(self.text)
        self.assertEqual(data, self.data)

#    def test_asciiarmor_unarmor_with_bad_checksum(self) :
#        # GnuPG meldet beim Importieren einen Prüfsummenfehler: 1d049e - 58bd96
#        textWithBadChecksum = self.text.replace('=WL2W', '=ML2M') # W --> M
#        self.assertRaises(asciiarmor.ChecksumMismatchException, asciiarmor.unarmor, textWithBadChecksum)

 #   def test_asciiarmor_unarmor_read_armor_headers(self) :
 #       headers = asciiarmor.armor_headers(self.text)
 #       self.assertEqual(headers, self.armorHeaders)
