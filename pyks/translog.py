# -*- coding: utf-8 -*-

#---
#--- Extending Python Searchpath
#import sys
#sys.path.append(r'D:\Projekte\flask-sandbox\python-hkp-server')

#--- Python
import hashlib
#import datetime
import sqlite3 as lite
#import sys
import time
import os

#---
#--- .
from pyks import openpgp

#---
PERSISTENCE_SCHEMA_VERSION = "v01" #: current database schema version
PERSISTENCE_SCHEMA_FILE = "pyks/persistence/schema.%s.sql" % (PERSISTENCE_SCHEMA_VERSION,) #: where to read schema from
PERSISTENCE_DATA_BASE = "pyks/persistence/localdata.%s.db" % (PERSISTENCE_SCHEMA_VERSION,) #: where to write data to

#---
def connect_to_database():
    """
    @return: Connection to open SQLite database
    """
    conn = lite.connect(_absolutePath(PERSISTENCE_DATA_BASE))
    conn.row_factory = lite.Row
    if not schemaVersionMatches(conn, PERSISTENCE_SCHEMA_VERSION) :
        initializeSchemaVersion(conn, PERSISTENCE_SCHEMA_VERSION)
    return conn

def _absolutePath(relativePath) :
    cwd = os.getcwd()
    if cwd.endswith('pyks') :
        return os.path.join(cwd, '..', relativePath)
    return os.path.join(cwd, relativePath)


def schemaVersionMatches(conn, version) :
    """
    @param conn: Connection to open SQLite database
    @param version: may be used in future to select the initial database
        schema for schema migration
    @rtype: bool
    """
    c = conn.cursor()
    try :
        c.execute("""SELECT * FROM added_armors""")
        c.execute("""SELECT * FROM selectors_to_fingerprints""")
        return True
    except lite.OperationalError :
        return False

def initializeSchemaVersion(conn, version) :
    """
    @param conn: Connection to open SQLite database
    """
    query = open(PERSISTENCE_SCHEMA_FILE, 'r').read()
    c = conn.cursor()
    #c.execute(query) # for only one statement
    c.executescript(query) # for multiple statements
    conn.commit()
    c.close()
    #conn.close()
    return
#---
class TransactionLog(object) :
    """
    Central point to track all transactions.
    """

    _singleInstance = None #: Singleton Pattern

    @classmethod
    def GlobalInstance(cls) :
        if cls._singleInstance is None :
            cls._singleInstance = TransactionLog()
        return cls._singleInstance


    def __init__(self) :
        self.parser = PacketParser()
        return


    def add(self, op, search, keyAsc) :
        """
        @param keyAsc : might contain more than one key
            HOW CAN I RECOGNIZE THIS?
        @type  keyAsc : str

        @return: (success, details)
        @rtype:  (bool, str | Exception)
        """
        self.append('add', (op, search, keyAsc))
#        try :
        pubKeyInfos = list(self._addArmoredPublicKeyCertificate_PGPy(keyAsc))
        for singlePubKeyInfo in pubKeyInfos :
            #print singlePubKeyInfo
            (success, details) = self._processSelectors(singlePubKeyInfo)
            if not success :
                return (False, str(details))
#        except Exception as E :
#            print E
        return (True, 'OK')

    def _addArmoredPublicKeyCertificate_PGPy(self, keyAsc) :
        """
        @rtype: generator[dict]
        """
        k = openpgp.OpenPGPKeys(keyAsc, encoding = 'utf-8')
        emailAdresses = list(k.GetUserIdentityEmails())
        publicFingerprints = list(k.GetFingerprints())
        subkeyFingerprints = []

        headers = "todo"
        singlePubKeyInfo = {}
        singlePubKeyInfo['armor'] = keyAsc
        singlePubKeyInfo['headers'] = headers
        singlePubKeyInfo['emails'] = emailAdresses
        singlePubKeyInfo['fingerprints'] = publicFingerprints
        singlePubKeyInfo['subkeys'] = subkeyFingerprints
        yield singlePubKeyInfo

    def _processSelectors(self, singlePubKeyInfo):
        """
        @return: (success, details)
        @rtype:  (bool, str | Exception)
        """
        keyAsc = singlePubKeyInfo['armor']
        headers = singlePubKeyInfo['headers']
        emailAdresses = singlePubKeyInfo['emails']
        publicFingerprints = singlePubKeyInfo['fingerprints']
        subkeyFingerprints = singlePubKeyInfo['subkeys']

        DEBUG_VERBOSE = True
        if DEBUG_VERBOSE :
            #print keyAsc
            print emailAdresses
            print publicFingerprints
        nowTimestamp = int(time.time())

        con = connect_to_database()
        cur1 = con.cursor()
        #cur1.execute("CREATE TABLE Cars(Id INT, Name TEXT, Price INT)")

        # ... fill the lookup tables with them ...
        indizes = publicFingerprints + emailAdresses # + [repr(singlePubKeyInfo), 'abc']
        if indizes : # otherwise there is nothing to retrieve the key later on
            #keyArmor = self.parser.enarmor(keyBytes) # TODO: testen!
            #print headers, keyArmor
            keyArmor = keyAsc

            # public key fingerprint --> payload
            primaryFingerprint = indizes[0]
            try :
                unused_res = cur1.execute("INSERT INTO added_armors VALUES(NULL, ?, ?, ?, ?)", (keyArmor, headers, nowTimestamp, primaryFingerprint))
            except Exception as E :
                return (False, E)

            # email --> public key fingerprint
            cur2 = con.cursor()
            for (selectorType, selectorValues) in [('email', emailAdresses),
                                                   ('subkey_fp', subkeyFingerprints),
                                                   ('primary_fp', publicFingerprints),
                                                   ('keyid', ['0x' + pf[-8:] for pf in publicFingerprints]),
                                                   ] :
                for value in selectorValues :
                    unused_res2 = cur2.execute("INSERT INTO selectors_to_fingerprints VALUES(NULL, ?, ?, ?, ?)", (selectorType, value, primaryFingerprint, nowTimestamp))


        resCommit = con.commit()
        print resCommit

        return (True, 'OK')
#
#        for (headers, keyBytes) in listOfPairs :
#            self.parser.storePublicCertificate(keyBytes)
#
#            fn = r"D:\Projekte\flask-sandbox\python-hkp-server\upload\upload.txt"
#            with open(fn, "at") as f :
#                timestamp = datetime.datetime.now().strftime("%d.%m.%Y %M:%H:%S")
#                f.write('\n---------------- %(timestamp)s ----------------\n' % locals())
#                f.write('op = %(op)r\n' % locals())
#                f.write('search = %(search)r\n' % locals())
#                f.write('keyAsc :\n%(keyAsc )s\n' % locals())
#                f.write('keyBytes:\n%(keyBytes)s\n' % locals())


    def append(self, action, *args):
        print action, args


class PacketParser(object) :
    """
    This is the interface betweeen potential various OpenPGP implementation
    and 'pyks'.
    """

    def getEmailAdresses(self, keyBytes) :
        """
        @param keyBytes: unarmored OpenPGP public key certificate
        @rtype: [str]
        """
        packets = OpenPGP.Packet.getpackets(keyBytes)
        uidPackets = list((p for p in packets if p.__class__ == OpenPGP.UserIDPacket))
        return list((uip.email.lower() for uip in uidPackets))


    def enarmor(self, keyBytes):
        """
        @param keyBytes: unarmored OpenPGP public key certificate
        @rtype: str
        """
        return OpenPGP.enarmor(keyBytes)


    def getPublicKeyFingerprints(self, keyBytes):
        """
        @param keyBytes: unarmored OpenPGP public key certificate
        @rtype: [str]
        """
        fingerprints = []
        packets = OpenPGP.Packet.getpackets(keyBytes)
        publicKeyPackets = list((p for p in packets if p.__class__ == OpenPGP.PublicKeyPacket))
        for pkp in publicKeyPackets:
            fingerprints.append(pkp.fingerprint())

        return fingerprints


    def getSubkeyFingerprints(self, keyBytes):
        """
        @param keyBytes: unarmored OpenPGP public key certificate
        @rtype: [str]
        """
        fingerprints = []
        packets = OpenPGP.Packet.getpackets(keyBytes)
        publicSubkeyPackets = list((p for p in packets if p.__class__ == OpenPGP.PublicSubkeyPacket))
        for pskp in publicSubkeyPackets:
            fingerprints.append(pskp.fingerprint())

        return fingerprints


    def storePublicCertificate(self, keyBytes):
        """
        @type keyBytes: bytes
        """

        # lookup by fingerprint should be possible^
        publicFingerprints = self.getPublicKeyFingerprints(keyBytes)
        for fp in publicFingerprints :
            print fp

        subkeyFingerprints = self.getSubkeyFingerprints(keyBytes)
        for fp in subkeyFingerprints :
            print fp

        packets = OpenPGP.Packet.getpackets(keyBytes)
        # lookup by e-mail should be possible
        uidPackets = list((p for p in packets if p.__class__ == OpenPGP.UserIDPacket))
        for uip in uidPackets :
            #print uip.name, uip.email, uip.text
            print uip.email, hashlib.sha256(uip.email).hexdigest()

        # lookup by immages might be interessting
        userAttrPackets = list((p for p in packets if p.__class__ == OpenPGP.UserAttributePacket))
        imageAttrPackets = list((pp
                                 for p in userAttrPackets
                                 for pp in p.subpackets
                                 if pp.__class__ == OpenPGP.UserAttributePacket.ImageAttributeSubpacket))
        for iap in imageAttrPackets :
            continue
        return

#
#        with con:
#
#            cur = con.cursor()
#            cur.execute("CREATE TABLE Cars(Id INT, Name TEXT, Price INT)")
#
#            HOW_TO_INSERT = 0
#            if HOW_TO_INSERT == 0 :
#
#                cur.execute("INSERT INTO Cars VALUES(1,'Audi',52642)")
#                cur.execute("INSERT INTO Cars VALUES(2,'Mercedes',57127)")
#                cur.execute("INSERT INTO Cars VALUES(3,'Skoda',9000)")
#                cur.execute("INSERT INTO Cars VALUES(4,'Volvo',29000)")
#                cur.execute("INSERT INTO Cars VALUES(5,'Bentley',350000)")
#                cur.execute("INSERT INTO Cars VALUES(6,'Citroen',21000)")
#                cur.execute("INSERT INTO Cars VALUES(7,'Hummer',41400)")
#                cur.execute("INSERT INTO Cars VALUES(8,'Volkswagen',21600)")
#
#                lid = cur.lastrowid
#                print "The last Id of the inserted row is %d" % lid
#
#            elif HOW_TO_INSERT == 1 :
#
#                cars = (
#                    (1, 'Audi', 52642),
#                    (2, 'Mercedes', 57127),
#                    (3, 'Skoda', 9000),
#                    (4, 'Volvo', 29000),
#                    (5, 'Bentley', 350000),
#                    (6, 'Hummer', 41400),
#                    (7, 'Volkswagen', 21600),
#                )
#                cur.executemany("INSERT INTO Cars VALUES(?, ?, ?)", cars)
#
#            else :
#
#                cur.executescript("""
#                    DROP TABLE IF EXISTS Cars;
#                    CREATE TABLE Cars(Id INT, Name TEXT, Price INT);
#                    INSERT INTO Cars VALUES(1,'Audi',52642);
#                    INSERT INTO Cars VALUES(2,'Mercedes',57127);
#                    INSERT INTO Cars VALUES(3,'Skoda',9000);
#                    INSERT INTO Cars VALUES(4,'Volvo',29000);
#                    INSERT INTO Cars VALUES(5,'Bentley',350000);
#                    INSERT INTO Cars VALUES(6,'Citroen',21000);
#                    INSERT INTO Cars VALUES(7,'Hummer',41400);
#                    INSERT INTO Cars VALUES(8,'Volkswagen',21600);
#                    """)
##            if con:
##                con.rollback()
#            con.commit()

#    # Abrufen:

#    HOW_TO_FETCH = 0
#    #con.row_factory = lite.Row
#    cur = con.cursor()
#    cur.execute("SELECT * FROM Cars")
#    if  HOW_TO_FETCH == 0 :
#        rows = cur.fetchall()
#        for row in rows :
#            print row
#    else:
#        while True:
#            row = cur.fetchone()
#            if row == None:
#                break
#            print row[0], row[1], row[2]

        # Normalerweise als Tuple,
        # optional aber auch als Dict
        #ors1+> cur = con.cursor()
        #ors1+> con.row_factory = lite.Row
        #ors1+> cur.execute("SELECT * FROM user_profiles")
        #<sqlite3.Cursor object at 0x000000000EE75558>
        #ors1+> rows = cur.fetchall()
        #ors1+> for row in rows :
        #    print row
        #
        #
        #<sqlite3.Row object at 0x00000000084C0BF0>
        #<sqlite3.Row object at 0x00000000084C0ED0>
        #ors1+> row['profile_name']
        #u'DP_LIVE_CS_KeyUser'
        #ors1+> dict(row)
        #{'profile_name':
