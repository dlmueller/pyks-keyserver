# -*- coding: utf-8 -*-
"""
Checks the functionality expected from the OpenPGP-Python package
"""

#---
#--- Python
import os
import collections
import datetime
import unittest
import sys

#---
#--- Extend Python search path
sys.path.append(os.getcwd())

#--- Helpers
import testhelpers
testhelpers.AddLocalSearchPath("..")
testhelpers.SetTestMethodPrefix("should")

#--- ThirdParty SUT
from pyks import openpgp
import pgpy

#---
class OpenPgpFacadeTest(unittest.TestCase) :

    def setUp(self) :
        pass


    def should_know_what_pgpy_offers_key2(self) :
        keyAsc = testhelpers.readTextFile("data/public_key_2.asc")
        k = pgpy.keys.PGPKey(keyAsc)
        primaryKey = k.primarykey # k.keypkts[0]
        self.assertEqual(k.ascii_headers,
            collections.OrderedDict([('Version', u'GnuPG v2.0.22 (MingW32)')]))
        self.assertEqual(k.is_ascii, True)
        self.assertEqual(primaryKey.fingerprint, '5E8C8A788F2685BB19306180890A4614448701A8')
        self.assertEqual(primaryKey.keyid, '890A4614448701A8')
        self.assertEqual(primaryKey.key_algorithm.value, 1) # 1 = 'RSA (Encrypt or Sign)',
        self.assertEqual(primaryKey.key_algorithm.name, 'RSAEncryptOrSign')
        self.assertEqual(primaryKey.version.name, 'v4')
        self.assertEqual(primaryKey.version.value, 4)
        self.assertEqual(primaryKey.key_creation, datetime.datetime(2014, 5, 27, 7, 41, 22))
        keyMaterial = primaryKey.key_material#
        self.assertEqual(keyMaterial.n['bitlen'], 2048)

    def should_know_what_pgpy_offers_ubuntu(self) :
        keyAsc = testhelpers.readTextFile("data/ubuntu.asc")
        k = pgpy.keys.PGPKey(keyAsc)
        primaryKey = k.primarykey # k.keypkts[0]
        self.assertEqual(k.ascii_headers,
            collections.OrderedDict([('Version', u'SKS 1.1.0')]))
        self.assertEqual(k.is_ascii, True)
        self.assertEqual(primaryKey.fingerprint, 'C5986B4F1257FFA86632CBA746181433FBB75451')
        self.assertEqual(primaryKey.keyid, '46181433FBB75451')
        self.assertEqual(primaryKey.key_algorithm.value, 17) # 17 = 'DSA (Digital Signature Standard)',
        self.assertEqual(primaryKey.key_algorithm.name, 'DSA') # 17 = 'DSA (Digital Signature Standard)',
        self.assertEqual(primaryKey.version.name, 'v4')
        self.assertEqual(primaryKey.version.value, 4)
        self.assertEqual(primaryKey.key_creation, datetime.datetime(2004, 12, 30, 19, 9, 44))
        keyMaterial = primaryKey.key_material # pgpy.packet.fields.keyfields.DSAMPI
        self.assertEqual(keyMaterial.g['bitlen'], 1024)

    def should_create_certificate_datastructure(self) :
        keyAsc = testhelpers.readTextFile("data/public_key_2.asc")
        k = pgpy.keys.PGPKey(keyAsc)
        primaryKey = k.primarykey # k.keypkts[0]
        #keyMaterial = primaryKey.key_material#
        cert = openpgp.CreatePublicKeyCertificate(keyAsc)
        self.assertNotEqual(cert, None)
        self.assertEqual(primaryKey.fingerprint, cert.fingerprint)

    def should_extract_user_identities(self) :
        testData = {
            "data/public_key_2.asc" : [
                u'Max Mustermann (Test User) <max.mustermann@localhost.de>',
                ],
            "data/ubuntu.asc" : [
                u'Ubuntu CD Image Automatic Signing Key <cdimage@ubuntu.com>'
                ],
            }
        for (filename, expected) in testData.iteritems() :
            keyAsc = testhelpers.readTextFile(filename)
            actual = list(openpgp.GetAllUserIdentities(keyAsc, 'utf-8'))
            self.assertEqual(actual, expected)


    def should_extract_emails_from_user_identities(self) :
        testData = {
            "data/public_key_2.asc" : [
                u'max.mustermann@localhost.de',
                ],
            "data/ubuntu.asc" : [
                u'cdimage@ubuntu.com'
                ],
            }
        for (filename, expected) in testData.iteritems() :
            keyAsc = testhelpers.readTextFile(filename)
            actual = list(openpgp.GetAllEmailsFromUserIdentities(keyAsc, 'utf-8'))
            self.assertEqual(actual, expected)


    def should_extract_email_addresses_from_identity_data(self) :
        # User IDs of the form: "name (comment) <email>"
        self.assertEqual(openpgp.GetEmailFromIdentity(u'Max Mustermann (Test User) <max.mustermann@localhost.de>'),
                         u'max.mustermann@localhost.de')
        # User IDs of the form: "name <email>"
        self.assertEqual(openpgp.GetEmailFromIdentity(u'Ubuntu CD Image Automatic Signing Key <cdimage@ubuntu.com>'),
                         u'cdimage@ubuntu.com')
        # User IDs of the form: "name"
        # TODO
        # User IDs of the form: "<email>"
        # TODO
        # illegal formats
        # TODO

    def should_extract_fingerprints(self) :
        testData = {
            "data/public_key_2.asc" : [
                u'5E8C8A788F2685BB19306180890A4614448701A8'
                ],
            "data/ubuntu.asc" : [
                u'C5986B4F1257FFA86632CBA746181433FBB75451'
                ],
            }
        for (filename, expected) in testData.iteritems() :
            keyAsc = testhelpers.readTextFile(filename)
            actual = list(openpgp.GetAllFingerprints(keyAsc, 'utf-8'))
            self.assertEqual(actual, expected)


    def should_extract_keyids(self) :
        testData = {
            "data/public_key_2.asc" : [
                u'890A4614448701A8'
                ],
            "data/ubuntu.asc" : [
                u'46181433FBB75451'
                ],
            }
        for (filename, expected) in testData.iteritems() :
            keyAsc = testhelpers.readTextFile(filename)
            actual = list(openpgp.GetAllKeyIds(keyAsc, 'utf-8'))
            self.assertEqual(actual, expected)


if __name__ == "__main__" :
    unittest.main()
