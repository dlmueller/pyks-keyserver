# -*- coding: utf-8 -*-
"""
Facade for some OpenPGP functions done by PGPy or OpenPGP-Python
"""

#---
#--- Python
import itertools
import hashlib
import re
import sys

#---
#--- optional some path adjustments to work with modified packages
#sys.path.insert(0, r"D:\Projekte\PGPy-dlmueller")

#---
#--- Third Party
# by Michael Green
# https://github.com/SecurityInnovation/PGPy
import pgpy

# by Dan McGee
# https://github.com/toofishes/python-pgpdump
import pgpdump

#---
#--- local stuff
from pyks import cert_db
from pyks import hkp_internals
from pyks import util

#---
#--- constants
__version__ = 'PGPy %s' % (pgpy.__version__,)

#---
#def GetPublicKeySelectors(keyAsc, encoding = 'utf-8') :
#    """
#    @rtype: dict : str -> [unicode]
#    """
#    selectors = {}
#    selectors['fingerprint'] = list(GetAllFingerprints(keyAsc, encoding = encoding))
#    selectors['keyid'] = list(GetAllKeyIds(keyAsc, encoding = encoding))
#    identities = list(GetAllUserIdentities(keyAsc, encoding = encoding))
#    selectors['identities'] = identities
#    selectors['emails'] = filter(None, map(GetEmailFromIdentity, identities))
#    return selectors

#---
class OpenPGPKeys(object) :
    """
    Facade do decouple users of 'openpgp' from underlying implementation,
    currently 'PGPy'.
    """
    @classmethod
    def from_ascii_armor(cls, keyAsc) :
        """
        @param keyAsc: ASCII-armored key
        @type  keyAsc: str | bytes
        """
        return OpenPGPKeys(keyAsc)

    def __init__(self, keyAsc, encoding = 'utf-8'):
        """
        @param keyAsc: ASCII-armored key
        @type  keyAsc: str | bytes

        @param encoding: used for output, e.g. 'utf-8'
        @type  encoding: str
        """
        self._keyAsc = keyAsc
        self._loadedKeys = load_keys(keyAsc)
        self._encoding = 'utf-8'
        return


    def GetUserIdentityEmails(self) :
        """
        @rtype: [str]
        """
        return sorted(list(self._iterEmailsFromUserIdentities()))

    def _iterEmailsFromUserIdentities(self):
        for k in self._loadedKeys :
            for userId in k.userids :
                email = userId.email # unicode
                yield email.encode(self._encoding)

    def GetFingerprints(self) :
        """
        @rtype: [str]
        """
        return list(self._iterFingerprints())

    def _iterFingerprints(self):
        for k in self._loadedKeys :
            fingerprint = k.fingerprint
            yield fingerprint.replace(' ', '')
        return

#---
def normalizeLineEndings(keyAsciiArmoredText):
    """Makes line endings UNIX-style"""
    # PGPy does not want to handle '\r\n' line breaks
    return keyAsciiArmoredText.replace('\r\n', '\n')

#---
def load_keys(keydata) :
    """
    @param keydata: ASCII-armored key
    @type  keydata: str | bytes

    @rtype: [L{pgpy.PGPKey}]
    """
    empty_key = pgpy.PGPKey()
    s = normalizeLineEndings(keydata).strip()
    empty_key.parse(s)
    return [empty_key]

def iter_packet_sections(keyAsc, verbose = False) :
    """
    @param keyAsc: ASCII-armor
    @type  keyAsc: str

    @return: (offset, length, meaning)
    @rtype: generator[(int, int, str)]
    """
    asciiArmor = keyAsc
    ad = pgpdump.AsciiData(keyAsc) # may raise IndexError if keyAsc is too short!
    keyBytes = ascii_unarmor(asciiArmor)
    offset = 0
    for i, mainp in enumerate(ad.packets()) :
        packetName = mainp.name
        try :
            subpackets = mainp.subpackets
        except AttributeError :
            subpackets = []
        mainData = mainp.data
        if mainData :
            sectionStart = keyBytes.index(mainData, offset)
            sectionLength = mainp.length
            sectionEnd = sectionStart + sectionLength
            if i == 0 :
                # compute V4 fingerprint
                keyMaterial = keyBytes[0:sectionEnd]
                fingerprint = hashlib.sha1(keyMaterial).hexdigest()
                meaning = mainp.name + ' (%s)' % (fingerprint.upper(),)
            else :
                meaning = mainp.name
            mainSection = (sectionStart, sectionEnd, meaning)
        else :
            mainSection = None
        subSections = []
        if subpackets :
            for subData in subpackets :
                subpdata = subData.data
                if subpdata :
                    sectionStart = keyBytes.index(subpdata, offset)
                    sectionLength = subData.length
                    sectionEnd = sectionStart + sectionLength
                    meaning = subData.name
                    subSections += [(sectionStart, sectionEnd, meaning)]
        for sec in _mergeSections(mainSection, subSections) :
            yield sec
        offset = sectionEnd + 1

def _mergeSections(mainSection, subSections) :
    """
    Without subsections only the main section will be returned::

        >>> mainSection = (5, 56, 'a')
        >>> list(_mergeSections(mainSection, []))
        [(5, 56, 'a')]

    The mainSection will surround a single subsection::

        >>> mainSection = (5, 56, 'a')
        >>> list(_mergeSections(mainSection, [(7, 9, 'x')]))
        [(5, 6, 'a'), (7, 9, 'x'), (10, 56, 'a')]

    The mainSection will also surround and place inbetween  multiple subsections::

        >>> mainSection = (5, 56, 'a')
        >>> list(_mergeSections(mainSection, [(7, 9, 'x'), (13, 16, 'y')]))
        [(5, 6, 'a'), (7, 9, 'x'), (10, 12, 'a'), (13, 16, 'y'), (17, 56, 'a')]

    else
        >>> subSections = [(7, 9, 'x'), (13, 16, 'y'), (21, 29, 'z')]
        >>> list(_mergeSections(mainSection, subSections))
        [(5, 6, 'a'), (7, 9, 'x'), (10, 12, 'a'), (13, 16, 'y'), (17, 20, 'a'), (21, 29, 'z'), (30, 56, 'a')]

    """
    if not subSections :
        yield mainSection
        return
    # assert subSections
    mainStart = mainSection[0]
    mainEnd = mainSection[1]
    mainText = mainSection[2]

    FIRST = 0
    LAST = len(subSections) - 1

    prevStart = mainStart
    for i, subSec in enumerate(subSections) :
        subStart = subSec[0]
        subEnd = subSec[1]
        subText = subSec[2]
        yield (prevStart, subStart - 1, mainText)
        yield (subStart, subEnd, subText)
        prevStart = subEnd + 1
    yield (prevStart, mainEnd, mainText)

#---
def ascii_unarmor(text):
    """
    Takes an ASCII-armored PGP block and returns the decoded byte value.
    @rtype: bytes
    """
    empty_key = pgpy.PGPKey()
    t = normalizeLineEndings(text).strip()
    armorDict = empty_key.ascii_unarmor(t)
    body = armorDict.get('body', '')
    # m = {'magic': None, 'headers': None, 'body': bytearray(), 'crc': None}
    return body

def ascii_enarmor(body, block_type = 'PUBLIC KEY BLOCK', headers = None, lineWidth = 64):
    """
    Takes PGP block in byte representation and returns ASCII-armored encoded text.

    :param body: A PGP block in byte representation, to en-armor.
    :type  body: bytes

    :param block_type: The header line text is chosen based upon the type
        of data that is being encoded in Armor, and how it is being encoded.
        Header line texts include the following strings:
            - MESSAGE
            - PUBLIC KEY BLOCK
            - PRIVATE KEY BLOCK
            - MESSAGE, PART X/Y
            - MESSAGE, PART X
            - SIGNATURE
    :type  block_type: str

    :param headers: key value, e.g {'Version' : 'GnuPG v2.0.22 (MingW32)'}
    :type  headers: None | L{collections.OrderedDict}

    :param lineWidth: GnuPG uses 64 bit, RFC4880 limits to 76
    :type  lineWidth: int

    :rtype: str | bytes
    """
    import base64
    import struct
    import textwrap

    # m = {'magic': None, 'headers': None, 'body': bytearray(), 'crc': None}
    marker = block_type
    data = body
    def _iter_enarmor(data):
        """
        @type data: bytes

        @param marker: Specifies the kind of data to armor
        @type  marker: str

        @param headers: optional header fields
        @type  headers: None | L{collections.OrderedDict}

        @rtype: generator[str]
        """
        yield '-----BEGIN PGP ' + str(marker).upper() + '-----'
        headersDict = headers or {}
        try:
            headerItems = list(headersDict.iteritems())
            headerItems.sort()
        except AttributeError: # list has no 'iteritems'
            headerItems = list(headersDict) # already list of key-value.pairs
        for (key, value) in headerItems:
            yield "%(key)s: %(value)s" % locals()
        yield '' # empty line

        text = base64.b64encode(data) # bytes in Python 3!
        try:
            # Python 3
            textStr = text.decode('ascii')
        except Exception:
            # Python 2
            textStr = text
        # max 76 chars per line!
        for line in textwrap.wrap(textStr, width = lineWidth):
            yield line
        # unsigned long with 4 bypte/32 bit in byte-order Big Endian
        checksumBytes = struct.pack('>L', crc24(data))
        checksumBase64 = base64.b64encode(checksumBytes[1:])  # bytes in Python 3!
        try:
            # Python 3
            checksumStr = checksumBase64.decode('ascii')
        except Exception:
            # Python 2
            checksumStr = checksumBase64
        yield '=' + str(checksumStr) # take only the last 3 bytes
        yield '-----END PGP ' + str(marker).upper() + '-----'
        yield '' # final line break
        return

    return "\n".join(_iter_enarmor(data))

def crc24(data) :
    return pgpy.types.Armorable.crc24(data)

#---
def fingerprint(key) :
    """Fingerprint without any spaces."""
    return key.fingerprint.replace(' ', '')

def key_id(key):
    """Returns the last 8 bytes of L{fingerprint}"""
    fp = fingerprint(key)
    return fp[-8:]

#---
def GetAllEmailsFromUserIdentities(keyAsc, encoding = 'utf-8') :
    """@rtype: generator[unicode]"""
    k = OpenPGPKeys(keyAsc, encoding = encoding)
    return k.GetUserIdentityEmails()

def GetAllUserIdentities(keyAsc, encoding = 'utf-8') :
    """@rtype: generator[unicode]"""
    for k in load_keys(keyAsc) :
        for (unused_i, p) in enumerate(k.userids) :
            p_data = p # bytearray
            yield p_data.decode(encoding)


def GetAllFingerprints(keyAsc, encoding = 'utf-8') :
    """@rtype: generator[unicode]"""
    k = OpenPGPKeys(keyAsc, encoding = encoding)
    return k.GetFingerprints()


def GetAllKeyIds(keyAsc, encoding = 'utf-8') :
    """@rtype: generetor[unicode]"""
    return _iterAttributesByName(keyAsc, 'keyid', encoding)


def _iterAttributesByName(keyAsc, attrName, encoding):
    """
    @param encoding: usually 'utf-8'
    @rtype: generator[unicode]
    """
    for k in load_keys(keyAsc) :
        k_packets = k.packets
        for (unused_i, p) in enumerate(k_packets) :
            p_data = getattr(p, attrName, None) # bytearray
            if p_data is not None :
                yield p_data.decode(encoding)

#---
#---
# code taken from OpenPGP-Python <https://github.com/singpolyma/openpgp-python>
# which is based on openpgp-php <http://github.com/bendiken/openpgp-php>
# OpenPGP User ID packet (tag 13).
# http://tools.ietf.org/html/rfc4880#section-5.11
# http://tools.ietf.org/html/rfc2822
def GetEmailFromIdentity(userId) :
    """
    @param userId: Content of UserID packet e.g.
        - name (comment) <email>
        - name <email>
        - name
        - <email>
        u'Ubuntu CD Image Automatic Signing Key <cdimage@ubuntu.com>'
    @type  userId: unicode
    """
    self_text = userId
    self_name = None
    self_email = None
    self_comment = None
    # User IDs of the form: "name (comment) <email>"
    parts = re.findall('^([^\(]+)\(([^\)]+)\)\s+<([^>]+)>$', self_text)
    if len(parts) > 0:
        self_name = parts[0][0].strip()
        self_comment = parts[0][1].strip()
        self_email = parts[0][2].strip()
    else: # User IDs of the form: "name <email>"
        parts = re.findall('^([^<]+)\s+<([^>]+)>$', self_text)
        if len(parts) > 0:
            self_name = parts[0][0].strip()
            self_email = parts[0][1].strip()
        else: # User IDs of the form: "name"
            parts = re.findall('^([^<]+)$', self_text)
            if len(parts) > 0:
                self_name = parts[0][1].strip()
            else: # User IDs of the form: "<email>"
                parts = re.findall('^<([^>]+)>$', self_text)
                if len(parts) > 0:
                    self_email = parts[0][1].strip()

    return self_email # maybe None

#---
#--- Datenstruktur
def CreatePublicKeyCertificate(keyAsc):
    """
    @rtype: None | L{cert_db.PublicKeyCertificate}
    """
    normKeyAsc = normalizeLineEndings(keyAsc)
    k = pgpy.keys.PGPKey(normKeyAsc)
    for pubKey in k.keypkts:
        #
        cert = cert_db.PublicKeyCertificate(fingerprint = pubKey.fingerprint,
            algo = pubKey.key_algorithm.value,
            keylen = _getBitlength(pubKey),
            creationdate = pubKey.key_creation
            #expirationdate=
            #flags=
            )
        return cert # only emit primary key
    return None

def _getBitlength(pgpKey) :
    """
    @type pgpKey: L{pgpy.pgp.PGPKey}
    """
    keyMaterial = pgpKey.__key__
    try :
        # pgpy.packet.fields.RSAPub
        N = keyMaterial.n
    except Exception :
        # pgpy.packet.fields.DSAMPI
        N = keyMaterial.g
    hexN = "%X" % (N,)
    return 8 * len(hexN)

#---
#--- HKP
def hkp_iterLookupLines_keyAsc(keyAscRaw, machineReadable, encoding = 'utf-8'):
    """
    @param keyAscRawc: ASCII armor of public key certificate
    @type  keyAscRaw: str | unicode

    @type  machineReadable: bool

    @rtype: generator[str]
    """
    if machineReadable :
        pubLine = hkp_internals.pubLine_mr
        uidLine = hkp_internals.uidLine_mr
    else :
        pubLine = hkp_internals.pubLine_html
        uidLine = hkp_internals.uidLine_html

    # ---------------------------------------------------------------
    # GLOBAL HEADER
    # ---------------------------------------------------------------
    # keyAsc = util.normalizeLineBreaks(keyAscRaw) # TODO: Check duplicate code
    keyAsc = normalizeLineEndings(keyAscRaw)
    normKeyAsc = keyAsc
    for k in load_keys(normKeyAsc) :
        # ---------------------------------------------------------------
        # RECORD HEADER
        # ---------------------------------------------------------------
        #info:1:1
        #pub:586A2E13F52616561BFC32C95B964AE610D49726:1:4096:1386622420:1701982420:
        #uid:Max Mustermann:1386622420::
        #uid:Matthias Schreiber <schreiber-matti@web.de>:1398517869::
        #
        fingerprint = k.fingerprint.replace(' ', '') # '5E8C 8A78 8F26 85BB 1930  6180 890A 4614 4487 01A8'
        keyid = '0x%s' % fingerprint[-8:]
        algo = k.key_algorithm.value
        keylen = _getBitlength(k)
        creationdate = k.created
        expirationdate = k.expires_at
        flags = None
        yield pubLine(keyid, algo, keylen, creationdate, expirationdate, flags) # MUST if machineReadable

        # ---------------------------------------------------------------
        # RECORD LINES
        # ---------------------------------------------------------------
        #for keyIdentity in cert.identities :
        #    yield cert.uidLine(keyIdentity)
        for uid in k.userids :
            #name = uid.name # u'Max Mustermann'
            #email = uid.email # u'max.mustermann@localhost.de'
            #comment = uid.comment # u'Test User'
            uidData = uid.hashdata # 'Max Mustermann (Test User) <max.mustermann@localhost.de>'
            yield uidLine(uidData, creationdate, expirationdate, flags) # MUST if machineReadable

        break # only primary key

    # ---------------------------------------------------------------
    # GLOBAL FOOTER
    # ---------------------------------------------------------------
    return

