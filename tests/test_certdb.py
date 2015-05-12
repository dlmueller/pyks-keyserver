# -*- coding: utf-8 -*-
"""
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
#--- SUT
from pyks import cert_db

#---
__all__ = ['CertificateDataBaseTest']


#---
class CertificateDataBaseTest(unittest.TestCase) :

    def setUp(self) :
        self.certDB = cert_db.CertificateDB()

    def test_has_fixed_test_entity(self) :
        cert = self.certDB.getTestCertificate()
        self.assertEqual(cert.keylen, 4096)
        self.assertEqual(cert.algo, 1)

    def test_pub_line(self) :
        cert = self.certDB.getTestCertificate()
        actualLine = cert.pubLine()
        expectedLine = 'pub:0xFBB75451:1:4096:1399464000::'
        # I'm not sure about the time-zone, therefor +/- 3600 might occure in MEZ
        self.assertEqual(expectedLine, actualLine)
