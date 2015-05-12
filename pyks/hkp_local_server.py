# -*- coding: utf-8 -*-
"""
Python HPK privacy server is an implementation of the
[OpenPGP HTTP Keyserver Protocol (HKP)](http://ietfreport.isoc.org/all-ids/draft-shaw-openpgp-hkp-00.txt)
in Python with a strong focus on privacy:

    - It allows you to change your public key for encryption frequently and
      publish it to your contacts without worrying about leaking your e-mail
      adresses(es) to spammers.

      You published keys are stored under your hashed e-mail address and are
      encrypted with a symmetric cipher that uses a key that is also derived
      from your e-mail address.

      When two HPK privacy servers synchronize their keys they cannot retrieve
      the original e-mails from the stored data. However people who already know
      your e-mail address are able to get get and decrypt your public keys

    - It allows you to does not leak your contacts to someone tapping your internet connection
      (synchronizing with SKS network is done in a PARCIMONIE-style)
      requires TORSOCKS.


Assumptions and Design decisions:

    - Note that you should use different public keys for encryption and
      signing (see FAQ). You the public key for encryption should be exchanged
      in regular intervalls.

    - Publishing your public keys via public synchronized keyserver (SKS) can
      leak your e-mail address to spammers and is therefor not suited for
      everybody.

    - Publishing public keys via e-mail, private website, USB-stick etc. is
      cumbersome.

    - Nevertheless publishing your key to a key server is easy with
      common OpenPGP clients. Therefore it should be easy to upload your keys
      via the quasi-standard Horowitz/HTTP Keyserver Protocol (HKP).

    - The motivation to keep the public keys of your contacts up-to-date will
      decline after your crypto hype. In the long term you will soon start to
      write unencrypted mails to get the communication running.

    - Synchronizing with other HPK privacy servers should be possible. Since
      there could be untrustworthy HPK servers out there the data must be
      encrypted, so that bad servers that are run by spammers collecting e-mails
      addresses are not able to retrieve mass of e-mails with ease.

    - Handling revocation and expiration can easily be managed by proven
      OpenPGP clients when the have a list of public keys.

    - Searching with wildcards leaks information so only direct matches should
      be supported.


Beside these advantages there are also several drawbacks:

    - This concept is not suitable to get produced "trusted keys" via for
      signing via the Web of Trust.
      Those
      Tho

## FAQ

Q: Why should I use different keys for encryption and signing?

    A: Signing messages, program code or binary is to ensure that those data
    is AUTHENTIC. That means that was produces/reviewed by YOU and was not
    manipulated


Q: Why should I sign my e-mails?

    A: When the receiver of your mail has trust into your public key for signing
    he can be sure the content was actually written/provided by you and no one
    is spoofing your identity. This is actually VERY simple with SMTP.

    A: This is also a way to fight spam. When your important contacts do sign
    their e-mails your mail client could reject unsigned e-mails.


Q: How can I make my public key for signing trusted?

    A: Publish your public key and make the receiver of your mail compare the
    fingerprint of it. You could check the fingerprint via a secure channel,
    i.e. via (telephone since your voice and phone habits are currently not easy
    to spoof or print it on your business card.

    A: Verifying keys in this way is time-consuming. Therefore you SHOULD NOT
    change your public key for singing like your underpants. Although you are
    able to revocate it, if someone has stolen/compromised your identity.


How to you prevent spammers Concept:

addresses the following privacy issues with

## Why should I want to run a


December 2004

 Copyright (C) 2013 Etienne Perot <etienne at perot dot me

It allows people to run a PGP keyserver in LAN without synchronizing the SKS
network (Synchronizing Key Servers).

[PLANNED]
Requesting keys from SKS
https://github.com/EtiennePerot/parcimonie.sh.git

on webservers with Python 2.4.


provided that the webserver has [GnuPG](http://www.gnupg.org/) and PHP with `exec()`
enabled. Searching, requesting and
submitting (optional) of keys are all supported.

When used as a proxy to a classic HKP server the proxy client role request to
the external HKP server is done via Python HKP Client by Dmitry Gladkov
(https://github.com/dgladkov/python-hkp.git)


## Usage

Simply point your gpg to the right keyserver and port. For example:

        gpg --keyserver hkp://example.com:80 --search-keys Remko
        gpg --keyserver hkp://example.com:80 --send-keys 8E041080
        gpg --keyserver hkp://example.com:80 --recv-keys 8E041080

## Known Issues

- Expiration and revocation is only detected with the english version
  of GnuPG. Other languages will omit this information.


## TODO

- Provide more information for uids in searches
- Return human readable output if 'mr' option is not set
- Make more robust, fool proof and secure
- Better logging
- More graceful calls to GnuPG
- Fine-tune GnuPG options (try to avoid creation of trustdb etc. if possible)
- Look at expiration date computation. Currently has a workaround to avoid
  being one day off.


## Disclaimer

This software is not production-ready. It probably contains
bugs and security leaks. Use at your own risk.


Installing:

# pip install python-hkp

Usage example::

    >>> from hkp import KeyServer
    >>> serv = KeyServer('http://pool.sks-keyservers.net')
    >>> serv.search('Dmitry Gladkov')
    [Key 28DFA7EC RSA (Encrypt or Sign), Key 473C57D9 RSA (Encrypt or Sign)]
    >>> serv.search('Dmitry Gladkov')[0].identities
    [Identity Dmitry Gladkov (dgl) <dmitry.gladkov@gmail.com>]



Copyright (c) 2014-2015 by David Lukas Müller.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

    * The names of the contributors may not be used to endorse or
      promote products derived from this software without specific
      prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

@author: dlmueller
"""

#---
#--- Python
import cgitb
import datetime
import hashlib
import os
import StringIO
import sys
import time

#---
#--- Extend Python search path
sys.path.append(os.getcwd())

#---
#--- .
import hkpd_config
import hkp_internals
import cert_db
import translog
import hexview

#---
#--- OpenPGP binding
import openpgp

#---
#--- Flask (flask.pocoo.org)
from flask import Flask
from flask import request
#from flask import url_for
from flask import Response
from flask import render_template
from flask import abort
from flask import g

#---
DEBUG_INDEX_SHOWS_SEARCH_PATTERN = False # True #: Flag for debugging index-operation
DEBUG_INDEX_SHOWS_FULL_ASCII_OF_STORED_KEYS = False # True #: Flag for debugging index-operation
DEBUG_INDEX_SHOW_COUNT = False #: Flag for debugging index-operation
DEBUG_SEPARATOR_MR = '\n---------------------------------------\n' #: Seperates productive/debugging output
DEBUG_SEPARATOR_HTML = '\n<br/><hr/><br/>\n' #: Seperates productive/debugging output
DEBUG_PRETEND_NON_EMPTY_DATABASE = False #: Should a sample key be returned on empty database?
DEBUG_KEY_ASC = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2.0.22 (MingW32)

mQENBFOEQaIBCADEw/+2wDJR8srlMR/nwwu5gOrwmZnnQLINUg/+BlXrizoGTiK4
BsQFEGkn5hF226gpX1YhK6wG187nzr0HNAEUGxtDWfth5hHBIm5zR3KhuvwlolMu
STVIMpoyuO9CbsXUsMuQz4UjYNmoKnGN+hyQQ+MjwE1zNEzQFLjEiq7osJA+Yb2Y
syCnsg1ue9WHRcWKhb88hT5vW/05+q69GoTV9DtehvSyux34EdU5tBXWVDHXDf5O
Ml7OBuN+58y9DVpqAstcbrunrb/vPvu3iLwcmiyePXPeBGKlhzDg0wqeIlby1pHI
lK8YNXw5Z9v4RfjPfgJsV1Qp7Qyrk9W0ew1jABEBAAG0OE1heCBNdXN0ZXJtYW5u
IChUZXN0IFVzZXIpIDxtYXgubXVzdGVybWFubkBsb2NhbGhvc3QuZGU+iQE1BBMB
AgAfBQJThEGiAhsDBgsJCAcDAgQVAggDAxYCAQIeAQIXgAAKCRCJCkYURIcBqMbT
CACGXW2+3h4FqB1Ft4Qg6H7kWdUHEgTqbOEIYtSl84qfJaRSAsd63jZybqdamDJX
h9dq/OyJ51vq2e+UKR0c8AsjvoSxb5NAQL1mSM52OOBVRWhPnTe9UNGTANFt0Xp2
VDXbKCWQpGeRXnYauGQMZOdDUylbkRIU2JQRw8AAqe88h1jimTywhLyaYcY9UsXt
gvUOyb3sl739QHP5sD1+SDWRH7hJzOn0QqA1DhXOsxOz+r1z5rNGl/E4qvfyWgxv
8iAXflYGfAhF8+bzvDDe2pK6a38DSDX5olc3/21pYaIWTcEn+8Iz/8Z65EiT+cEG
CdcJsaOyD0fxF71iw1LAiSd+
=WL2W
-----END PGP PUBLIC KEY BLOCK-----
""" #: used when Database is empty

#---
app = Flask(__name__)

#---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = translog.connect_to_database()
    return db

@app.teardown_appcontext
def teardown_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# The first time get_db() is called the connection will be established.
# To make this implicit a LocalProxy can be used:
from werkzeug.local import LocalProxy
db = LocalProxy(get_db)

@app.route('/')
def index():
    """
    Show short project description and provide links to local DB etc.
    """
    return render_template('local_index.html',
                           numbers = range(0, 10),
                           name = 'You')

@app.route('/test_cases')
def test_cases():
    """
    Static URLs for HKPs Query-API
    """
    #spc = hkpd_config.SitePageContent()
    #return "".join(spc.iterIndexPageLines())
    return render_template('local_test_cases.html',
                           numbers = range(0, 10),
                           name = 'You')

@app.route('/local_db')
def local_db():
    """Show the content of the local stored public keys."""
    return render_template('local_db.html',
                           numbers = range(0, 10),
                           name = 'You')

@app.route('/remote_db')
def remote_db():
    """Show the content of the protected stored public keys."""
    return "todo"

@app.route('/hello')
def hello():
    return 'Hello World'

#---
#--- Error Handling
@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404

#@app.errorhandler(404)
#def not_found(error):
#    resp = make_response(render_template('error.html'), 404)
#    resp.headers['X-Something'] = 'A value'
#    return resp

@app.route('/access_denied')
def access_denied():
    """
    401 means access denied
    """
    abort(401)
    #this_is_never_executed()

#---
#--- Requesting material
@app.route('/pks/lookup', methods = ['GET'])
def hkp_lookup() :
    """
    Testcode::

        #!python
        import urllib2
        w = "http://127.0.0.1:11371/pks/lookup?search=0xFBB75451&exact=off&options=mr&op=index"
        h = urllib2.urlopen(w)
        h.readlines()
    """

    # 3.1.1. The "search" Variable
    #
    # The search variable contains arbitrary text encoded as usual for a
    # HTTP URL.  This text may represent the key ID of the key being
    # sought or some text from a user ID on the key being sought.
    search = request.args.get('search', None) or ''

    # 3.1.2. The "op" (operation) Variable
    #
    # The op variable specifies the operation to be performed on the
    # keyserver.  The op variable is generally used with the "search"
    # variable to specify the keys that should be operated on.
    op = request.args.get('op', None) or ''

    # 3.2.1. The "options" Variable
    #
    # This variable takes one or more arguments, separated by commas.
    # These are used to modify the behavior of the keyserver on a
    # per-request basis.
    options = request.args.get('options', None) or ''
    # options may contain 'mr' for 'machine readable'

    # 3.2.2. The "fingerprint" Variable
    #
    # This variable takes one argument: "on" or "off".  If present and
    # on, it instructs the server to provide the key fingerprint for each
    # key in an "index" or "vindex" operation.  This variable has no
    # effect on any other operation.  The exact format of the displayed
    # fingerprint, like the "index" and "vindex" operations themselves,
    # is implementation defined.
    fingerprint = (request.args.get('fingerprint', None) or '').lower() == 'on'

    # 3.2.3. The "exact" Variable
    #
    # This variable takes one argument: "on" or "off".  If present and
    # on, it instructs the server to search for an exact match for the
    # contents of the "search" variable.  The exact meaning of "exact
    # match" is implementation defined.
    exact = (request.args.get('exact', None) or '').lower() == 'on'

    # 3.2.3. Other Variables
    #
    # Other site-specific or nonstandard variables can be indicated by
    # prefixing the variable name with the string "x-".

    searchPattern = normalize_search_variable(search, exact != 'off')

    certDB = cert_db.CertificateDB()

    if op.lower() == 'get' :
        content, mimeType = execute_operation_get(certDB, searchPattern, options)
        return Response(content, mimetype = mimeType)

    if op.lower() == 'index' :
        content, mimeType = execute_operation_index(certDB, searchPattern, options, fingerprint)
        return Response(content, mimetype = mimeType)

    if op.lower() == 'vindex' :
        content, mimeType = execute_operation_vindex(certDB, searchPattern, options, fingerprint)
        return Response(content, mimetype = mimeType)

    if op.lower() == 'stats' :
        content, mimeType = execute_operation_stats(certDB, searchPattern, options, fingerprint)
        return Response(content, mimetype = mimeType)

    if op.lower() == 'x-example' :
        content, mimeType = execute_operation_x_example(certDB, searchPattern)
        return Response(content, mimetype = mimeType)

    content = 'SERVER ERROR'
    mimeType = 'text/plain'
    return Response(content, mimetype = mimeType)


#---
#--- Decomposing the search variable
class OperationArguments(object) :
    """
    Holds the query details.
    """
    def __init__(self, search, exact) :
        """
        @param search: Search Pattern
        @type  search: str

        @param exact: perform exact or fuzzy queries
        @type  exact: bool
        """
        self.search = search
        self.exact = exact

    def __str__(self):
        return str(self.search)


def normalize_search_variable(search, exact):
    """
    The Internet-Draft 'OpenPGP HTTP Keyserver Protocol' (March 2003) David Shaw
    'docs/draft-shaw-openpgp-hkp-00.txt' defines::

        3.1.1. The "search" Variable::

        The search variable contains arbitrary text encoded as usual for a
        HTTP URL.  This text may represent the key ID of the key being
        sought or some text from a user ID on the key being sought.

        If any particular type of searching is not supported, the keyserver
        should return an appropriate HTTP error code such as 501 ("Not
        Implemented").  The server MUST NOT return an error code (such as
        404 ("Not Found")) that could be mistaken by the client for a valid
        response.

    @param search: There are multiple type of searching.
        Searching by Key ID or Fingerprint can be done with the following flavours:
            - Searching by Key ID with 8 digits (32-bit key ID) plus prefix '0x'
            - Searching by Key ID with 16 digits (64-bit key ID) plus prefix '0x'
            - Searching by Key ID with 40 digits (160-bit, V4 Fingerprint) plus prefix '0x'
            - Searching by Key ID with 32 digits (128-bit, V3 Fingerprint) plus prefix '0x'
        Searching by ...
            - ...
    @type  search: str

    @param exact: perform exact or fuzzy queries
    @type  exact: bool

    @rtype: L{OperationArguments}
    """
    return OperationArguments(search, exact)


#---
#--- Operations on search variable

def recordRequest(action, search, timestamp):
    """
    @type action, search: str
    @type timestamp: int
    """
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO local_requests
        (action, arguments, timestamp)
        VALUES
        (?, ?, ?)
    """, (action, search, timestamp))
    conn.commit()

def execute_operation_get(certDB, searchPattern, options) :
    """
    The Internet-Draft 'OpenPGP HTTP Keyserver Protocol' (March 2003) David Shaw
    'docs/draft-shaw-openpgp-hkp-00.txt' defines::

        3.1.2.1. The "get" operation

        The "get" operation requests keys from the keyserver.  A string that
        specifies which key(s) to return is provided in the "search"
        variable.

        The response to a successful "get" request is a HTTP document
        containing a keyring as specified in RFC-2440 [4], section 11.1, and
        ASCII armored as specified in section 6.2.

        The response may be wrapped in any HTML or other text desired, except
        that the actual key data consisting of an initial line break, the
        "-----BEGIN PGP PUBLIC KEY BLOCK-----" header, the armored key data
        itself, the "-----END PGP PUBLIC KEY BLOCK-----" header, and a final
        line break MUST NOT be modified from the form specified in [RFC 2880].

        If no keys match the request, the keyserver should return an
        appropriate HTTP error code such as 404 ("Not Found").

    @type searchPattern: L{OperationArguments}
    """
    recordRequest("get",
                  searchPattern.search,
                  int(time.time()))

    optionList = map(lambda o : o.lower(), (o for o in (options or '').split(',')))
    machineReadable = 'mr' in optionList
    hexView = 'hexview' in optionList

    asciiArmor = "\n".join(_iter_get_lines(certDB, searchPattern, options))
    if hexView :
        as_html = True
        if as_html :
            mimeType = 'text/html'
        else :
            mimeType = 'text/plain'
        buf = StringIO.StringIO()
        keyBytes = openpgp.ascii_unarmor(asciiArmor)
        sectionOffsets = []
        backgroundColors = ["khaki",
                            "LightBlue",
                            "LightSalmon",
                            "MediumAquaMarine",
                            "LightPink",
                            "LightSteelBlue",
                            "LightBlue",
                            ]
        meaning2color = {} # meaning -> bgcolor
        packetSections = openpgp.iter_packet_sections(asciiArmor)
        for i, (sectionStart, sectionEnd, meaning) in enumerate(packetSections) :
            try :
                bgcolor = meaning2color[meaning]
            except KeyError :
                bgcolor = backgroundColors[i % len(backgroundColors)]
                meaning2color[meaning] = bgcolor
            spanAttributes = {'style' : '"background-color:%s"' % (bgcolor,),
                              'title' : '"%s"' % (meaning,)}
            spanAttributes['title'] = '"%s"' % (meaning,)
            sectionOffsets.append((sectionStart, sectionEnd, spanAttributes))
        sectionOffsets.sort()
        hexview.hexdump(keyBytes, outstream = buf, as_html = as_html, sectionOffsets = sectionOffsets)
        content = ""
        if as_html :
            content += "<html><body>\n"
            content += "<pre>\n"
        content += buf.getvalue()
        if as_html :
            content += "\n</pre>\n"
            content += "</body></html>\n"
    else :
        mimeType = 'text/plain'
        content = asciiArmor
    #content = "\n".join(hkp_internals.iterLookupLines(cert))
    #content += '\n'
    #content += str(searchPattern)

#    conn = get_db()
#    c = conn.cursor()
#    c.execute("SELECT * FROM added_armors")
#    while True :
#        row = c.fetchone()
#        if row == None:
#            break
#        content += "%s %s %s" % (row[0], row[1], row[2])

    return content, mimeType

def _iter_get_lines(certDB, searchPattern, options):
    #cert = certDB.getTestCertificate()
    #BEGIN_PGP_PUBLIC_KEY_BLOCK = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    #END_PGP_PUBLIC_KEY_BLOCK = "-----END PGP PUBLIC KEY BLOCK-----"
    keys = _selectPublicKeysBySearchPattern(searchPattern)
    for k in keys :
        for line in k.split('\n') :
            yield line.rstrip()
    #yield BEGIN_PGP_PUBLIC_KEY_BLOCK
    #yield END_PGP_PUBLIC_KEY_BLOCK

#---
def radix64(binaryData) :
    """
    6.3.  Encoding Binary in Radix-64

    The encoding process represents 24-bit groups of input bits as output
    strings of 4 encoded characters.  Proceeding from left to right, a
    24-bit input group is formed by concatenating three 8-bit input
    groups.  These 24 bits are then treated as four concatenated 6-bit
    groups, each of which is translated into a single digit in the
    Radix-64 alphabet.  When encoding a bit stream with the Radix-64
    encoding, the bit stream must be presumed to be ordered with the most
    significant bit first.  That is, the first bit in the stream will be
    the high-order bit in the first 8-bit octet, and the eighth bit will
    be the low-order bit in the first 8-bit octet, and so on.

          +--first octet--+-second octet--+--third octet--+
          |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
          +-----------+---+-------+-------+---+-----------+
          |5 4 3 2 1 0|5 4 3 2 1 0|5 4 3 2 1 0|5 4 3 2 1 0|
          +--1.index--+--2.index--+--3.index--+--4.index--+

    Each 6-bit group is used as an index into an array of 64 printable
    characters from the table below.  The character referenced by the
    index is placed in the output string.

    Value Encoding  Value Encoding  Value Encoding  Value Encoding
        0 A            17 R            34 i            51 z
        1 B            18 S            35 j            52 0
        2 C            19 T            36 k            53 1
        3 D            20 U            37 l            54 2
        4 E            21 V            38 m            55 3
        5 F            22 W            39 n            56 4
        6 G            23 X            40 o            57 5
        7 H            24 Y            41 p            58 6
        8 I            25 Z            42 q            59 7
        9 J            26 a            43 r            60 8
       10 K            27 b            44 s            61 9
       11 L            28 c            45 t            62 +
       12 M            29 d            46 u            63 /
       13 N            30 e            47 v
       14 O            31 f            48 w         (pad) =
       15 P            32 g            49 x
       16 Q            33 h            50 y

    The encoded output stream must be represented in lines of no more
    than 76 characters each.
    """
    binaryData
    return


def iter_24_bit_octets(binaryData):
    """
    Doctests::
        >>> list(iter_24_bit_octets("ABCDEFGHIJK"))
        ['ABC', 'DEF', 'GHI', 'JK']
        >>> list(iter_24_bit_octets(map(ord, "ABCDEFGHIJK")))
        [[65, 66, 67], [68, 69, 70], [71, 72, 73], [74, 75]]
    """
    octet = []
    for (i, nextByte) in enumerate(binaryData) :
        octet += [nextByte]
        if len(octet) == 3 :
            yield octet
            octet = []
    yield octet


def pack24bit(byteTriple) :
    """
    Doctests::
        >>> map(ord, 'ABC')
        [65, 66, 67]

    @type byteTriple: [int]
    @rtype: str
    """
    if not byteTriple :
        return ''

    byteCount = len(byteTriple)
    if byteCount > 3 :
        raise ValueError("Only 24-bit = 3 Byte allowed!")

    byte1 = byteTriple[0]
    byte2 = byteTriple[1] if byteCount > 0 else 0
    byte3 = byteTriple[2] if byteCount > 1 else 0
    octet = (byte1 << 16) + (byte2 << 8) + byte3 # 24-bit number

    sevenBits = 63 # 2**6 - 1
    mask1 = sevenBits << 7 * 3
    mask2 = sevenBits << 7 * 2
    mask3 = sevenBits << 7
    mask4 = sevenBits

    value1 = octet & mask1
    value2 = octet & mask2
    value3 = octet & mask3 if byteCount > 1 else None
    value4 = octet & mask4 if byteCount > 2 else None

    RADIX64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    PADDING = "="
    char1 = RADIX64_ALPHABET[value1]
    char2 = RADIX64_ALPHABET[value2]
    char3 = PADDING if value3 is None else RADIX64_ALPHABET[value3]
    char4 = PADDING if value4 is None else RADIX64_ALPHABET[value4]
    return char1 + char2 + char3 + char4


#---
def execute_operation_index(certDB, searchPattern, options, fingerprint,
                            vindex = False) :
    """
    The Internet-Draft 'OpenPGP HTTP Keyserver Protocol' (March 2003) David Shaw
    'docs/draft-shaw-openpgp-hkp-00.txt' defines::

        3.1.2.2. The "index" Operation

        The "index" operation requests a list of keys on the keyserver that
        match the text or key ID in the "search" variable.  Historically, the
        "index" operation returned a human readable HTML document containing
        links for each found key, but this is not required.

        If the "index" operation is not supported, the keyserver should
        return an appropriate HTTP error code such as 501 ("Not
        Implemented").

    @type certDB: L{cert_db.CertificateDB}

    @type searchPattern: L{OperationArguments}

    @param options: comma separated string.
        May contain 'mr' for 'machine readable' output.
    @type  options: str

    @param vindex: to distignuish between 'index' and 'vindex' operation
    @type  vindex: bool
    """
    recordRequest("index",
                  searchPattern.search,
                  int(time.time()))

    keys = _selectPublicKeysBySearchPattern(searchPattern)
    optionList = map(lambda o : o.lower(), (o for o in (options or '').split(',')))
    machineReadable = 'mr' in optionList

    content = ""
    if DEBUG_INDEX_SHOW_COUNT :
        if machineReadable :
            content += "len(keys) = %r" % (len(keys),)
            content += DEBUG_SEPARATOR_MR
        else :
            content += "len(keys) = %r" % (len(keys),)
            content += DEBUG_SEPARATOR_HTML


    if DEBUG_INDEX_SHOWS_SEARCH_PATTERN :
        if searchPattern :
            if machineReadable :
                content += str(searchPattern)
                content += DEBUG_SEPARATOR_MR
            else :
                content += str(searchPattern)
                content += DEBUG_SEPARATOR_HTML

    content += "\n".join(list(_iter_index_content(certDB, keys, machineReadable)))

    if DEBUG_INDEX_SHOWS_FULL_ASCII_OF_STORED_KEYS :
        if machineReadable :
            content += DEBUG_SEPARATOR_MR
            for keyAsc in keys :
                content += keyAsc + '\n'
        else :
            content += DEBUG_SEPARATOR_HTML
            for keyAsc in keys :
                content += keyAsc + '<br/>'


    mimeType = 'text/plain' if machineReadable else 'text/html'
    return content, mimeType


def _selectPublicKeysBySearchPattern(searchPattern):
    """
    @type searchPattern: L{OperationArguments}
    @rtype: set(keyAsc)
    """
    value = searchPattern.search
    respectWhereClause = searchPattern.search.strip()
    keys = set()
    con = get_db()
    cur = con.cursor()
    querySELECT = """
        SELECT *
        FROM added_armors
    """
    if not respectWhereClause :
        query = querySELECT
        cur.execute(query)
    else:
        queryWHERE = """
            WHERE publickey_fingerprint IN
            (SELECT primary_fingerprint
             FROM selectors_to_fingerprints
             WHERE selector_value IS ?)
        """
        query = querySELECT + queryWHERE
        cur.execute(query, (value,))

    while True:
        row = cur.fetchone()
        if row == None:
            break
        keyAsc = row['armored_key']
        keys.add(keyAsc)

    if DEBUG_PRETEND_NON_EMPTY_DATABASE :
        if not keys :
            keys.add(DEBUG_KEY_ASC)

    return keys


def _iter_index_content(certDB, keys, machineReadable) :
    """
    @type certDB: L{cert_db.CertificateDB}

    @param keys: set(keyAsc)
    @type  keys: set(str)

    @type  machineReadable: bool

    @rtype: generator[str]
    """
    #pub:0x448701A8:1:4096:2014-05-27 06:41:22::
    #uid:Max Mustermann (Test User) <max.mustermann@localhost.de>:2014-05-27 06:41:22::
    lines = [] # [[str]]
    for keyAsc in keys :
        lineIterator = openpgp.hkp_iterLookupLines_keyAsc(keyAsc, machineReadable, encoding = 'utf-8')
        lines.append(list(lineIterator))

    def sortByFirstUID(keyLines) :
        if not keyLines :
            return ''
        try :
            return keyLines[1].strip()
        except IndexError :
            return keyLines[0].strip()

    lastHeading = None
    lines.sort(key = sortByFirstUID)
    for keyLines in lines :
        try :
            firstUID = keyLines[1]
            firstName = firstUID[4:]
            firstLetter = firstName[0]
        except IndexError :
            firstUID = None
            firstName = None
            firstLetter = None
        if not machineReadable :
            if firstLetter :
                if firstLetter != lastHeading :
                    yield ''
                    yield '<h1>%(firstLetter)s</h1>' % locals()
                    lastHeading = firstLetter
        if not machineReadable :
            yield '<p>'

        for line in keyLines :
            yield line
            if not machineReadable :
                yield '<br/>'

        # ---------------------------------------------------------------
        # RECORD FOOTER
        # ---------------------------------------------------------------
        if not machineReadable :
            yield '</p>'


def execute_operation_vindex(certDB, searchPattern, options, fingerprint) :
    """
    The Internet-Draft 'OpenPGP HTTP Keyserver Protocol' (March 2003) David Shaw
    'docs/draft-shaw-openpgp-hkp-00.txt' defines::

        3.1.2.3. The "vindex" (verbose index) Operation

        The "vindex" operation is similar to "index" in that it provides a
        list of keys on the keyserver that match the text of key ID in the
        "search" variable.  Historically, a "vindex" response was the same as
        "index" with the addition of showing the signatures on each key, but
        this is not required.

        If the "vindex" operation is not supported, the keyserver should
        return an appropriate HTTP error code such as 501 ("Not
        Implemented").

    @type searchPattern: L{OperationArguments}
    """
    recordRequest("vindex",
                  searchPattern.search,
                  int(time.time()))

    return execute_operation_index(certDB, searchPattern, options, fingerprint, vindex = True)


def execute_operation_stats(certDB, searchPattern, options, fingerprint) :
    """
    Not specified in the Internet-Draft 'OpenPGP HTTP Keyserver Protocol'
    (March 2003) David Shaw, but used by:

        - SKS Synchronizing Key Servers
          e.g. http://eu.pool.sks-keyservers.net:11371/pks/lookup?op=stats

        - Hockeypuck
          e.g. http://hockeypuck.gazzang.net:11371/pks/lookup?op=stats

    @type searchPattern: L{OperationArguments}
    """
    last24hUpdates = [# tests
                       {"date" : "2014-11-10 13:00 +0000", "newCount" : 0, "updateCount" : 0},
                       {"date" : "2014-11-10 10:00 +0000", "newCount" : 0, "updateCount" : 0},
                       ]
    last7dUpdates = [# tests
                       {"date" : "2014-11-10 13:00 +0000", "newCount" : 0, "updateCount" : 0},
                       {"date" : "2014-11-10 10:00 +0000", "newCount" : 0, "updateCount" : 0},
                       ]
    content = render_template('stats.html',
                              hostname = "localhost",
                              port = "11371",
                              version = "v0.1",
                              totalNumberOfKeys = 42,
                              last24hUpdates = last24hUpdates,
                              last7dUpdates = last7dUpdates)
    mimeType = 'text/html'
    return content, mimeType


def execute_operation_x_example(certDB, searchPattern, options) :
    """
    The Internet-Draft 'OpenPGP HTTP Keyserver Protocol' (March 2003) David Shaw
    'docs/draft-shaw-openpgp-hkp-00.txt' defines::

        3.1.2.4. Other Operations

        Other site-specific or nonstandard operations can be indicated by
        prefixing the operation name with the string "x-".

    @type searchPattern: L{OperationArguments}
    """
    recordRequest("x-example",
                  searchPattern.search,
                  int(time.time()))

    cert = certDB.getTestCertificate()
    content = "\n".join(hkp_internals.iterLookupLines(cert))
    content += '\n' + search
    mimeType = 'text/plain'
    return content, mimeType

#---
#--- Adding new material
@app.route('/pks/add', methods = ['POST'])
def hkp_add() :
    """
    Testcode::

        #!python
        import urllib2
        w = "http://127.0.0.1:11371/pks/add"
        h = urllib2.urlopen(w)
        h.readlines()
    """

    tlog = translog.TransactionLog.GlobalInstance()

    op = None # request.args.get(hkpd_config.HKP_VARIABLE_OPERATION, None) or ''
    search = None # request.args.get(hkpd_config.HKP_VARIABLE_SEARCH, None) or ''
    try :
        keyAsc = request.form[hkpd_config.HKP_VARIABLE_KEYTEXT]
    except Exception as E :
        keyAsc = repr(E)

    # requestVariables = request.args.keys()
    (success, details) = tlog.add(op, search, keyAsc) # , requestVariables)
    if success :
        lines = ['OK',
                 'openpgp binding %s' % openpgp.__version__, ]

        lines += map(str, openpgp.GetAllEmailsFromUserIdentities(keyAsc))
        #lines.append(keyAsc)
        content = '\n'.join(lines)
        response = Response(content, mimetype = 'text/plain')
    else :
        lines = ['internal server error',
                 str(details)]
        # internal server error
        content = '\n'.join(lines)
        response = Response(content, mimetype = 'text/plain')
        response.status_code = 500
    return response


#---
#--- Selbstauskunft
@app.route('/about')
def about():
    return render_template('about.html',
                           # environment details
                           currentWorkingDirectory = os.getcwd(),

                           # database details
                           schemaVersion = translog.PERSISTENCE_SCHEMA_VERSION,
                           schemaFile = translog.PERSISTENCE_SCHEMA_FILE,
                           databaseFile = translog.PERSISTENCE_DATA_BASE,

                           # OpenPGP library details
                           pgpyVersion = openpgp.pgpy.__version__,
                           pgpyPath = openpgp.pgpy.__file__)

@app.route('/background')
def background():
    return render_template('background.html')

@app.route('/motivation')
def motivation():
    return render_template('motivation.html')

@app.route('/related_work')
def related_work():
    return render_template('related_work.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/roadmap')
def roadmap():
    return render_template('roadmap.html')

# -----------------------------------------------------------------------------------
#--- main
# -----------------------------------------------------------------------------------

def main(argv):
    """
    @param argv: command line arguments
    """
    portNumber = hkpd_config.HKP_LOCAL_PROXY_PORT

    cgitb.enable(0, "log")
    app.run(debug = True,
            # host = '0.0.0.0', # make the server visible also with debug = True
            port = portNumber)
    if 1 :
        # at least under Windows
        url = "http://localhost:%s" % (portNumber,)
        os.startfile(url)

if __name__ == '__main__':
    main(sys.argv)
