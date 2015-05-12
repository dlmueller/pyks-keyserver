# -*- coding: utf-8 -*-
"""
Useful helpers
"""

#---
#--- Python
import calendar
import datetime

#---
#--- datetime.datetime
def datetime_fromtimestamp(secondsSince1970) :
    """
    Doctests::
        >>> datetime_totimestamp(datetime_fromtimestamp(1000000000))
        1000000000
    """
    if secondsSince1970 is None :
        return None
    return datetime.datetime.utcfromtimestamp(secondsSince1970)

#
#def datetime_totimestamp(aDateTime) :
#    """
#    Doctests::
#        >>> datetime_totimestamp(datetime_fromtimestamp(1000000000))
#        1000000000
#    """
#    zero = datetime.datetime.utcfromtimestamp(0)
#    diff = aDateTime - zero
#    return diff.days * 24 * 60 * 60 + diff.seconds

def datetime_totimestamp(d):
    """
    Doctests::

        >>> datetime_totimestamp(datetime_fromtimestamp(1000000000))
        1000000000

    @type d: datetime.datetime | None
    @return: Seconds since 01.01.1970
    @rtype:  int | None
    """
    if d is None :
        return None
    try :
        timeShift = (d.now() - d.utcnow()).seconds
        return calendar.timegm(d.timetuple()) - timeShift
    except Exception :
        return d

#---
#--- line endings
def normalizeLineBreaks(keyAscRaw) :
    """
    CR LF --> LF
    """
    keyAsc = keyAscRaw.replace('\r\n', '\n')
    return '\n%s\n' % (keyAsc.strip())
