# -*- coding: utf-8 -*-
"""
Functions for generating a hexview of binary data withh colorization
"""

#---
#--- Python
import cgi

#---
def hexdump(buf, outstream = None, sectionOffsets = None, as_html = False):
    """
    SOURCE: https://github.com/n0fate/walitean/blob/master/sqlitePage.py
    respectivly: http://mwultong.blogspot.com/2007/04/python-hex-viewer-file-dumper.html

    @param outstream: if not specified, sys.stdout will be used
    @type  outstream: file | None

    @param sectionOffsets: optional list of offset positions where to
        add a 'line break' in visualization.
    @type  sectionOffsets: None | [int]
    """
    out = outstream or sys.stdout
    #'style' : '"color:red"',
    spanAttributes = {'style' : '"background-color:yellow"',
                      'title' : '"Tooltip"'}
    so2 = [#(8, 19, spanAttributes),
           #(47, 67, spanAttributes),
           ]
    for line in _iter_hexdump_lines(buf, sectionOffsets = sectionOffsets or so2, as_html = as_html) :
        print >> out, line

def _iter_hexdump_lines(buf, sectionOffsets, as_html = False):
    """
    CSS for colorizing::

        <span class="myClass">test</span>
        css

        .myClass
        {
        color:red;
        }
        2nd preference inline style

        <span style="color:red">test</span>

    @param sectionOffsets: optional list of offset positions where to
        add a 'line break' in visualization.
    @type  sectionOffsets: [(int, int, dict-str-str)]
    """

    sectionOffsets.sort()

    FORMAT_OFFSET = "%08X: "
    FORMAT_HEXBYTE = "%02X "
    FORMAT_OCTET_SEPARATOR = " " # "| "
    FORMAT_HEXBYTES_SEPARATOR = " " # "| "
    UNPRINTABLE_CHAR = "."
    BYTES_PER_ROW = 16

    offset = 0
    while offset < len(buf):
        offsetEOL = offset + BYTES_PER_ROW

        buf16 = buf[offset:offsetEOL]
        buf16Len = len(buf16)
        rightPadding = BYTES_PER_ROW - buf16Len
        if buf16Len == 0:
            break

        #---------------------------------
        # line number
        # -------------------------------
        offsetOutput = FORMAT_OFFSET % (offset,)

        hexOutput = ""
        textOutput = ""
        for i in range(buf16Len):
            effectiveOffset = offset + i

            buf16_i = buf16[i] # str | int
            charOrd = ordbuf(buf16_i)
            theChar = chrbuf(buf16_i)

            # section details
            secDetails = getSectionDetails(sectionOffsets, as_html, offset, effectiveOffset, offsetEOL) # maybe None
            if secDetails :
                (startColor, endColor, SPAN_BEGIN, SPAN_END) = secDetails
            else :
                (startColor, endColor, SPAN_BEGIN, SPAN_END) = (None, None, '', '')

            # line details
            lineStartColor = max(startColor, offset)
            if endColor < offset :
                lineStartColor = None #lineEndColor = min(endColor, offsetEOL)
            if lineStartColor :
                lineEndColor = min(endColor, offsetEOL)
            else :
                lineEndColor = None

            # begin marker
            if effectiveOffset == lineStartColor :
                hexOutput += SPAN_BEGIN
                textOutput += SPAN_BEGIN

            # hex and text output
            if (i == 8):
                hexOutput += FORMAT_OCTET_SEPARATOR
            hexOutput += FORMAT_HEXBYTE % (charOrd,)

            # text output
            if (charOrd >= 0x20 and charOrd <= 0x7E):
                pass
            else:
                theChar = UNPRINTABLE_CHAR
            if as_html :
                theChar = cgi.escape(theChar)
            textOutput += theChar

            # ebd marker
            if effectiveOffset == lineEndColor:
                hexOutput += SPAN_END
                textOutput += SPAN_END

        if lineStartColor and not hexOutput.endswith(SPAN_END):
            hexOutput += SPAN_END
            textOutput += SPAN_END

        hexOutput += " " *3 * rightPadding
        if (buf16Len < 9):
            hexOutput += " "*len(FORMAT_OCTET_SEPARATOR)

        output = offsetOutput
        output += hexOutput
        output += FORMAT_HEXBYTES_SEPARATOR
        output += textOutput
        offset += BYTES_PER_ROW
        yield output

    if (offset == 0):
        yield "%08X: " % (offset)

def getSectionDetails(sectionOffsets, as_html, offset, effectiveOffset, offsetEOL) :
    """
    Doctests::
        >>> spanAttributes = {}
        >>> sectionOffsets = [(8, 19, spanAttributes), (47, 67, spanAttributes),]
        >>> as_html = False
        >>> getSectionDetails(sectionOffsets, as_html, 0, 0, 16)
        >>> getSectionDetails(sectionOffsets, as_html, 0, 8, 16)
        (8, 19, '', '')
        >>> getSectionDetails(sectionOffsets, as_html, 16, 16, 32)
        (8, 19, '', '')
        >>> getSectionDetails(sectionOffsets, as_html, 16, 19, 32)
        (8, 19, '', '')
        >>> getSectionDetails(sectionOffsets, as_html, 16, 20, 32)
        >>> getSectionDetails(sectionOffsets, as_html, 32, 47, 48)
        (47, 67, '', '')

    @param sectionOffsets: sorted list of offset positions where to
        add a 'line break' in visualization.
    @type  sectionOffsets: [(int, int, dict-str-str)]
    """
    SPAN_BEGIN = ''
    SPAN_END = ''
    for theTriple in sectionOffsets :
        (startColor, endColor, spanAttributes) = theTriple
        if as_html :
            attrList = list("%s=%s" % (k, v)
                            for (k, v) in spanAttributes.iteritems()
                            if k.strip() and v.strip())
            attrString = " ".join(sorted(attrList[:2]))
            SPAN_BEGIN = '<span %s>' % (attrString,)
            SPAN_END = '</span>'
        if startColor > effectiveOffset :
            return None
        if effectiveOffset <= endColor :
            return (startColor, endColor, SPAN_BEGIN, SPAN_END)
    return None

#---
#--- Helperfunctions to handle strings, bytearrays and lists of ints
def ordbuf(buf16_i) :
    try :
        charOrd = ord(buf16_i)
    except TypeError :
        charOrd = buf16_i
    return charOrd

def chrbuf(buf16_i) :
    if type(buf16_i) == type(0) :
        theChar = chr(buf16_i)
    else :
        theChar = buf16_i
    return theChar
