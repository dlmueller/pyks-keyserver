# -*- coding: utf-8 -*-
"""
Useful helpers for unittests.
"""

#---
#--- Python
import os.path
import sys

#---
#--- File IO
def readTextFile(filename):
    """
    @type filename: str
    @rtype: str
    """
    return readFile(filename, "r")


def readBinaryFile(filename):
    """
    @type filename: str
    @rtype: str
    """
    return readFile(filename, "rb")


def readFile(filename, readmode):
    """
    @type filename: str
    @param readmode: r | rb
    @type  readmode: str
    @rtype: str
    """
    fname = GetAbsolutePath(filename)
    with open(fname, readmode) as f:
        fileContent = "".join(f.xreadlines())
    return fileContent


def GetAbsolutePath(filename):
    """
    @rtype: str
    """
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


#---
#--- import handling
def AddLocalSearchPath(thePath):
    """Extends sys.path"""
    sys.path.append(GetAbsolutePath(thePath))

#def DiscardLocalSearchPath(thePath):
#    pass

#---
#--- Test Flavour
def SetTestMethodPrefix(newPrefix):
    """
    @param newPrefix: either 'test' (classic) or 'should' (BDD-style)
    """
    from unittest import loader
    loader.TestLoader.testMethodPrefix = newPrefix
