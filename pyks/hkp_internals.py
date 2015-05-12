# -*- coding: utf-8 -*-
"""
"""

#---
#--- Python
import cgi

#---
#--- .
from pyks import util

#---
def iterLookupLines_cert(cert):
    """
    @param cert: Ein öffentliches Zertifikat
    @type  cert: L{cert_db.PublicKeyCertificate}

    @rtype: generator[str]
    """
    yield cert.pubLine()
    for keyIdentity in cert.identities :
        yield cert.uidLine(keyIdentity)

#---
def pubLine_mr(keyid, algo, keylen, creationdate, expirationdate, flags):
    """
    HKP specific formatting.

    @keyword algo: one of the L{PUBLIC_KEY_ALGORITHMS} constants
    @type    algo: int | str

    @keyword keylen: 1024, 2048, 4096 etc.
    @type    keylen: int | str

    @keyword creationdate: Seconds since 01.01.1970 (mandatory)
    @type    creationdate: datetime.datetime | int

    @keyword expirationdate: Seconds since 01.01.1970 (optional)
    @type    expirationdate: datetime.datetime | int | None

    @keyword flags: in any order
        r = revoked,
        d = disabled (implementation specific),
        e = expired
    @type    flags: None | str
    """
    #pubLine = "pub:%(keyid)s:%(algo)s:%(keylen)s:%(creationdate)s:%(expirationdate)s:%(flags)s" % (keyid, algo, keylen, creationdate, expirationdate, flags)
    createSeconds = util.datetime_totimestamp(creationdate)
    expireSeconds = util.datetime_totimestamp(expirationdate) # maybe None
    pubLine = "pub:%s:%s:%s:%s:%s:%s" % (keyid,
                                         algo,
                                         keylen,
                                         createSeconds,
                                         expireSeconds or '',
                                         flags or '')
    return pubLine

pubLine = pubLine_mr #: machine readable is the default


def pubLine_html(keyid, algo, keylen, creationdate, expirationdate, flags):
    """
    see L{publine_mr}
    """
    #pubLine = "pub:%(keyid)s:%(algo)s:%(keylen)s:%(creationdate)s:%(expirationdate)s:%(flags)s" % (keyid, algo, keylen, creationdate, expirationdate, flags)
    createSeconds = util.datetime_totimestamp(creationdate)
    expireSeconds = util.datetime_totimestamp(expirationdate) # maybe None
    createDT = util.datetime_fromtimestamp(createSeconds)
    expireDT = util.datetime_fromtimestamp(expireSeconds) or '' # maybe None
    flagsString = flags or ''
    pubLine = 'pub:%(keyid)s (<a href="http://localhost:11371/pks/lookup?op=get&options=hexview&search=%(keyid)s">hex</a>, <a href="http://localhost:11371/pks/lookup?op=get&options=mr&search=%(keyid)s">mr</a>):%(algo)s:%(keylen)s:%(createDT)s:%(expireDT)s:%(flagsString)s' % locals()
    return pubLine

def uidLine_mr(uid_line, creationdate, expirationdate = None, flags = None):
    #uidLine = "uid:%(uid_line)s:%(creationdate)s:%(expirationdate)s:%(flags)s" % locals()
    createSeconds = util.datetime_totimestamp(creationdate)
    expireSeconds = util.datetime_totimestamp(expirationdate) # maybe None
    uidLine = "uid:%s:%s:%s:%s" % (uid_line,
                                   createSeconds,
                                   expireSeconds or '',
                                   flags or '')
    return uidLine

uidLine = uidLine_mr #: machine readable is the default

def uidLine_html(uid_line, creationdate, expirationdate = None, flags = None):
    createSeconds = util.datetime_totimestamp(creationdate)
    expireSeconds = util.datetime_totimestamp(expirationdate) # maybe None
    createDT = util.datetime_fromtimestamp(createSeconds)
    expireDT = util.datetime_fromtimestamp(expireSeconds) # maybe None
    uidLine = "uid:%s:%s:%s:%s" % (cgi.escape(uid_line),
                                   createDT,
                                   expireDT or '',
                                   flags or '')
    return uidLine
