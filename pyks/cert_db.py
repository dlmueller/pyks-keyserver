# -*- coding: utf-8 -*-
"""
Represents the access layer to database were the key certificates are stored.
"""

#---
#--- Python
import datetime
import sqlite3

#---
#--- .
from pyks import hkp_internals
from pyks import util

#---
__all__ = ['Key', 'Identity', 'KeyServer']

#---
# Loosely taken from RFC2440 (http://tools.ietf.org/html/rfc2440#section-9.1)
# should be updated with RFC4880 (http://tools.ietf.org/html/rfc4880)
PUBLIC_KEY_ALGORITHMS = {
    1: 'RSA (Encrypt or Sign)',
    2: 'RSA Encrypt-Only',
    3: 'RSA Sign-Only',
    16: 'Elgamal (Encrypt-Only)',
    17: 'DSA (Digital Signature Standard)',
    18: 'Elliptic Curve',
    19: 'ECDSA',
    20: 'Elgamal (Encrypt or Sign)',


#       21         - Reserved for Diffie-Hellman (X9.42,
#                    as defined for IETF-S/MIME)
#       100 to 110 - Private/Experimental algorithm.
}

ALGO_RSA_ENCRYPT_AND_SIGN = 1
ALGO_RSA_ENCRYPT_ONLY = 2
ALGO_RSA_SIGN_ONLY = 3
#9.2. Symmetric Key Algorithms
#
#
#       ID           Algorithm
#       --           ---------
#       0          - Plaintext or unencrypted data
#       1          - IDEA [IDEA]
#       2          - Triple-DES (DES-EDE, as per spec -
#                    168 bit key derived from 192)
#       3          - CAST5 (128 bit key, as per RFC 2144)
#       4          - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
#       5          - SAFER-SK128 (13 rounds) [SAFER]
#       6          - Reserved for DES/SK
#       7          - Reserved for AES with 128-bit key
#       8          - Reserved for AES with 192-bit key
#       9          - Reserved for AES with 256-bit key
#       100 to 110 - Private/Experimental algorithm.


#9.3. Compression Algorithms
#
#
#       ID           Algorithm
#       --           ---------
#       0          - Uncompressed
#       1          - ZIP (RFC 1951)
#       2          - ZLIB (RFC 1950)
#       100 to 110 - Private/Experimental algorithm.
#
#   Implementations MUST implement uncompressed data. Implementations
#   SHOULD implement ZIP. Implementations MAY implement ZLIB.
#
#---
# Ubuntu key data
FINGERPRINT = '0x46181433FBB75451'
KEYID = '0x%s' % FINGERPRINT[-8:]
UID = 'Ubuntu CD Image Automatic Signing Key'
FULL_UID = UID + ' <cdimage@ubuntu.com>'
#DINGUS = Dingus()

#---
class CertificateDB(object) :
    """
    Represents the access layer to database were the key certificates are stored.
    """

    def __init__(self):
        pass

    def getTestCertificate(self) :
        """
        Returns special Test Key not actually stored within the DB.
        @rtype: L{PublicKeyCertificate}
        """
        cert = PublicKeyCertificate(fingerprint = '0x46181433FBB75451',
            creationdate = util.datetime_totimestamp(datetime.datetime(2014, 5, 7, 12, 00)),
            algo = ALGO_RSA_ENCRYPT_AND_SIGN,
            keylen = 4096)
        return cert


#---
class PublicKeyCertificate(object):
    """
    Public key object inspired by hkp.client.Key

    Doctests::
        >>> cert = PublicKeyCertificate(fingerprint = '0x46181433FBB75451', algo = ALGO_RSA_ENCRYPT_AND_SIGN, keylen = 4098)
    """

    _begin_header = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
    _end_header = '-----END PGP PUBLIC KEY BLOCK-----'

    def __init__(self, **keywords):
        """
        DOES NOT take keyserver host and port used to look up ASCII armored key, and
        data as it is present in search query result.

        @keyword fingerprint: e.g. '0x46181433FBB75451' (for Ubuntu CD Automatic Signing Key)
        @type    fingerprint: str

        @keyword algo: one of the L{PUBLIC_KEY_ALGORITHMS} constants
        @type    algo: int | str

        @keyword keylen: 1024, 2048, 4096 etc.
        @type    keylen: int | str

        @keyword creationdate, expirationdate: Seconds since 01.01.1970
        @type    creationdate, expirationdate: datetime.datetime | int | None

        @keyword flags: in any order
            r = revoked,
            d = disabled (implementation specific),
            e = expired
        @type    flags: str
        """

        # Pflichtparameter
        fingerprint = keywords['fingerprint']
        algo = int(keywords['algo'])
        keylen = int(keywords['keylen'])
        creationdate = keywords['creationdate']

        # optionale Parameter
        expirationdate = keywords.get('expirationdate', None)
        flags = keywords.get('flags', '')

        #self.host = host
        #self.port = port
        self.fingerprint = fingerprint
        self.keyid = '0x%s' % fingerprint[-8:]
        self.algo = int(algo) # PUBLIC_KEY_ALGORITHMS.get(algo, algo)
        self.keylen = int(keylen)
        self.creationdate = util.datetime_totimestamp(creationdate)
        self.expirationdate = util.datetime_totimestamp(expirationdate) if expirationdate else None
        self.flags = flags
        self.revoked = True if 'r' in flags else False
        self.disabled = True if 'd' in flags else False
        self.expired = True if 'e' in flags else False

        self.identities = []


    def pubLine(self):
        """
        @return: pub:%(keyid)s:%(algo)s:%(keylen)s:%(creationdate)s:%(expirationdate)s:%(flags)s
        @rtype: str
        """
        cert = self
        keyid = cert.keyid
        algo = cert.algo # 1 = RSA, 17 = DSA, ...
        keylen = cert.keylen # 1024, 2048, 4096, ...
        creationdate = cert.creationdate
        expirationdate = cert.expirationdate or ''
        flags = cert.flags # r = revoked, d = disabledl, e = expired
        pubLine = hkp_internals.pubLine(keyid, algo, keylen, creationdate, expirationdate, flags)
        return pubLine


    def uidLine(self, keyIdentity):
        """
        uid:%(escaped_uid_line)s:%(creationdate)s:%(expirationdate)s:%(flags)s
        @rtype: str
        """
        cert = self
        # uid-line
        escaped_uid_line = "davidlukas@web.de"
        creationdate = cert.creationdate
        expirationdate = '' # util.datetime_totimestamp(keyExpireDate)
        flags = "" # r = revoked, d = disabledl, e = expired
        uidLine = hkp_internals.uidLine(escaped_uid_line, creationdate, expirationdate, flags)
        return uidLine

class PersistentData(object) :
    """
    Handles local data storage
    """

    def __init__(self, dbName = ":memory:") :
        """
        @param dbName: Name of the SQLite-DB to use
            ':memory:' or 'localkeys.db' etc
        @type  dbName: str
        """
        self.dbName = dbName
        self.connection = None
        self.connect()
        self._createSchemaIfNecessary()


    def _createSchemaIfNecessary(self):
        if 'stocks' in self.listTables() :
            return
        self._createDataBase()
        return

    def _createDataBase(self) :
        """
        Before first usage.
        """
        con = self.connect()
        c = con.cursor()

        # Create table
        c.execute('''CREATE TABLE stocks
                     (date text, trans text, symbol text, qty real, price real)''')

        # Save (commit) the changes
        con.commit()#

        # We can also close the connection if we are done with it.
        # Just be sure any changes have been committed or they will be lost.
#        con.close()

    def listTables(self):
        """
        @type c: qlite3.Cursor
        @rtype: [str | unicode]
        """
        con = self.connection
        c = con.cursor()
        c.execute('SELECT name FROM sqlite_master WHERE type = "table"')
        tupleList = c.fetchmany()
        return list((t[0] for t in tupleList))


    def connect(self):
        """
        @rtype: C{sqlite3.Connection}
        """
        try :
            self.connection.close()
        except Exception :
            pass
        con = sqlite3.connect(self.dbName)
        self.connection = con
        return con


    def disconnect(self) :
        if self.connection :
            self.connection.close()
            self.connection = None




    def _fillStaticData(self):
        con = self.connect()
        c = con.cursor()

        # Insert a row of data
        c.execute("INSERT INTO stocks VALUES ('2006-01-05','BUY','RHAT',100,35.14)")

        # Larger example that inserts many records at a time
        purchases = [('2006-03-28', 'BUY', 'IBM', 1000, 45.00),
                     ('2006-04-05', 'BUY', 'MSFT', 1000, 72.00),
                     ('2006-04-06', 'SELL', 'IBM', 500, 53.00),
                    ]

        c.executemany('INSERT INTO stocks VALUES (?,?,?,?,?)', purchases)

    def _queryStaticData(self) :
        con = self.connect()
        c = con.cursor()

        # Do this instead
        t = ('RHAT',)
        c.execute('SELECT * FROM stocks WHERE symbol=?', t)
        print c.fetchone()
        # (u'2006-01-05', u'BUY', u'RHAT', 100.0, 35.14)
