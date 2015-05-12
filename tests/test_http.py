# -*- coding: utf-8 -*-
"""
Tests the HTTP Keyserver Protokol (HKP) by making HTTP requests against the
HKP-server running on localhost (listens at TCP/IP port 11371 by default).

@author: dlmueller
"""

#---
#--- Python
import os
import urllib
import urllib2
import unittest
import sys

#---
#--- Extend Python search path
sys.path.append(os.getcwd())

#---
#--- ThirdParty - Python-HKP
import hkp

#---
#--- .
from pyks import hkpd_config
from pyks import cert_db

#---
__all__ = ['HttpTest']

# Ubuntu key data
FINGERPRINT = '0x46181433FBB75451'
KEYID = '0x%s' % FINGERPRINT[-8:]
UID = 'Ubuntu CD Image Automatic Signing Key'
FULL_UID = UID + ' <cdimage@ubuntu.com>'
#DINGUS = Dingus()

#---
class ItemLine(object) :
    def __init__(self) :
        pass
#
#class InformationLine(ItemLine) :
#    """
#    info:<version>:<count>
#
#    This line is optional in 'draft-shaw-openpgp-hkp-00.txt' (March 2003)
#    and defaults to version=1 if not given in the server output.
#
#    Belongs to "Machine Readable Index"
#    """
#    def __init__(self, version, keyCount):
#        """
#        @param version: the version of the output format, currently (May 2014)
#            this is still number 1
#        @type  version: str
#
#        @param keyCount: number of keys returned in the response,
#            i.e. the number of "pub:" lines
#        @type  keyCount: int
#        """
#        ItemLine.__init__(self)
#        self.version = version = ''
#        self.count = keyCount = ''
#
#
#class PublicKeyLine(ItemLine):
#    """
#    pub:<keyid>:<algo>:<keylen>:<creationdate>:<expirationdate>:<flags>
#
#    This line specifies the primary key
#
#    Belongs to "Machine Readable Index"
#    """
#    def __init__(self, keyid, algo):
#        """
#        @param keyid: either the fingerprint or the key ID of the key.
#
#        """
#        ItemLine.__init__(self)
#        self.keyid = keyid = ''
#        self.algo = algo = ''
#        self.keylen = keylen = ''
#        self.creationdate = creationdate = ''
#        self.expirationdate = expirationdate = ''
#        self.flags = flags = ''
#
#class UserIdentityLine(ItemLine):
#    """
#    uid:<escaped_uid_string>:<creationdate>:<expirationdate>:<flags>
#
#    These line(s)
#    Belongs to "Machine Readable Index"
#    """
#    def __init__(self):
#        ItemLine.__init__(self)

class MachineReadableIndexLineParser(object) :
    """
    Takes one of the following lines an returnes the corresponding object
    representation:

        - info:<version>:<count>
        - pub:<keyid>:<algo>:<keylen>:<creationdate>:<expirationdate>:<flags>
        - uid:<escaped_uid_string>:<creationdate>:<expirationdate>:<flags>

    """
    def __init__(self, version = 1):
        """
        @param version: the version of the output format, currently (May 2014)
            this is still number 1
        @type  version: str | int
        """
        self.formatVersion = version # maybe updated by the optional initial "info:" line
        self.result = [] # [PublicKeyCertificate]
        self.current_cert = None

    def iterCertificates(self) :
        """
        @return: generator[PublicKeyCertificate]
        """
        return iter(self.result)

    def ParseLine(self, lineWithEnding):
        """
        @rtype: None | L{ItemLine}
        """
        lineItem = None
        line = lineWithEnding.rstrip() # Zeilenumbruch entfernen
        items = line.split(':')

        if items[0] == 'pub':
            # pub:%(keyid)s:%(algo)s:%(keylen)s:%(creationdate)s:%(expirationdate)s:%(flags)s
            DEFAULT = None # or empty string?
            keyid = getItemByIndex(items, 1, DEFAULT)
            algo = getItemByIndex(items, 2, DEFAULT)
            keylen = getItemByIndex(items, 3, DEFAULT)
            creationdate = getItemByIndex(items, 4, DEFAULT)
            expirationdate = getItemByIndex(items, 5, DEFAULT)
            flags = getItemByIndex(items, 6, DEFAULT)

            if self.current_cert : # vorherigen Schlüssel ggf. abschließen
                pass

            #key = hkp.client.Key(self.serv.host, self.serv.port,)
            lineItem = cert_db.PublicKeyCertificate(fingerprint = keyid,
                algo = algo,
                keylen = keylen,
                creationdate = creationdate,
                expirationdate = expirationdate,
                flags = flags)

            self.current_cert = lineItem
            self.result += [self.current_cert]

        elif items[0] == 'uid' and self.current_cert :
            # uid:%(escaped_uid_line)s:%(creationdate)s:%(expirationdate)s:%(flags)s
            lineItem = hkp.client.Identity(*items[1:])
            keyIdentity = lineItem
            self.current_cert.identities.append(keyIdentity)

        else : # not implemented
            lineItem = None

        return lineItem


def getItemByIndex(theList, index, defaultValue):
    """
    @type theList: list | tuple
    @type index: int
    """
    try :
        value = theList[index]
    except IndexError :
        value = defaultValue
    return value

class HttpTest(unittest.TestCase) :

    HKP_SERVER_HOST = hkpd_config.HKP_LOCAL_PROXY_HOST
    HKP_SERVER_PORT = hkpd_config.HKP_LOCAL_PROXY_PORT

    def setUp(self):
        self.server_host = self.HKP_SERVER_HOST
        self.BASE_URL = '%s:%i' % (self.HKP_SERVER_HOST, self.HKP_SERVER_PORT)
        self.certDB = cert_db.CertificateDB()

    def test_index_page(self):
        spc = hkpd_config.SitePageContent()
        u = urllib.urlopen(self.BASE_URL)
        lines = u.readlines()
        self.assertEqual(lines, list(spc.iterIndexPageLines()))

    def test_search_by_id(self):
        """
        Test search with keyid.
        """
        cert = self.certDB.getTestCertificate()
        KEYID = cert.keyid
        self.serv = hkp.KeyServer('http://localhost')
        #result = self.serv.search(KEYID)
        request_url = (self.server_host + ':11371/pks/lookup'
                '?search=' + KEYID + '&exact=off&options=mr&op=index')

        # muss die erste Zeile verworfen werden?
        lines = urllib2.urlopen(request_url).readlines()

        #lines = response.splitlines()[1:]

        # Parse machine readable index response.
        mriParser = MachineReadableIndexLineParser(version = 1)
        for (unused_lineno, line) in enumerate(lines) :
            unused_Item = mriParser.ParseLine(line)

        result = mriParser.result
        #return result

        def ensure_0x_prefix(keyid) :
            """fügt fehlendes '0x' am Anfang hinzu"""
            if not keyid.startswith('0x') :
                return "0x%s" % (keyid,)
            keyid

        def remove_0x_prefix(keyid):
            """entfernt etwaiges führendes '0x'."""
            if keyid.startswith('0x') :
                return keyid[2:]
            return keyid

#        u = urllib.urlopen(self.BASE_URL)
#        lines = u.readlines()
#        self.assertEqual(lines, [])
#        self.assertTrue(DINGUS.calls('()', search_url).once())
        self.assertEqual(len(result), 1)
        firstKey = result[0]
        self.assertEqual(ensure_0x_prefix(firstKey.keyid), ensure_0x_prefix(KEYID))
        self.assertEqual(remove_0x_prefix(firstKey.keyid), remove_0x_prefix(KEYID))
        self.assertEqual(firstKey.identities[0].uid, FULL_UID)
