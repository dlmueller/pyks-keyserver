# -*- coding: utf-8 -*-
"""
Integrationstests that makes system calls to GnuPG to fetch/store public keys
on the key server


How to execute the tests manually::

    #!python
    gpg = GnuPGWrapper()

@author: dlmueller
"""

#---
#--- Python
import os
import subprocess
#import timer
import sys

#---
#--- Extend Python search path
sys.path.append(os.getcwd())

#---
#--- PyKS
from pyks import simple_gnupg

#---
class GnuPGWrapper(object) :
    """
    Wrapps only the keyserver functions
    """
    def __init__(self, hostAndPort) :
        """
        @param hostAndPort: e.g. 'hkp://localhost:11371'
        @type  hostAndPort: str
        """
        self.executable = ['gpg']
        self.keyserverOptions = ['--keyserver', hostAndPort]


    def searchKeys(self, searchData):
        """
        /pks/lookup op=index
        /pks/lookup?search=0xFBB75451&exact=off&options=mr&op=index
        """
        proc = self.run(['--search-keys', searchData])
        return


    def receiveKeys(self):
        """
        /pks/lookup op=get
        /pks/lookup?search=0xFBB75451&exact=off&options=mr&op=get
        """
        # gpg --keyserver hkp://localhost:11371 --recv-keys 0xFBB75451
        return


    def listKeys(self):
        # gpg --list-keys
        proc = self.run(['--list-keys'])
        proc.wait()
        return "".join(proc.stdout.readlines())


    def deleteKeys(self):
        # gpg --delete-keys 0x448701A8
        return


    def dontKnowWhatThisShouldBe(self):
        """
        /pks/lookup op=vindex
        /pks/lookup?search=0xFBB75451&exact=off&options=mr&op=vindex
        """
        # gpg --keyserver hkp://localhost:11371 --search-keys 0xFBB75451
        return


    def sendKeys(self):
        """
        /pks/add
        /pks/add
        """
        # gpg --keyserver hkp://localhost:11371 --recv-keys 0xFBB75451 --> sollte nichts liefern
        # gpg --keyserver hkp://localhost:11371 --send-keys 0xFBB75451
        # gpg --keyserver hkp://localhost:11371 --recv-keys 0xFBB75451
        return


    def run(self, args):
        """
        @param args: e.g. ['--search-keys', '0xFBB75451']
        @type  args: [str]

        @rtype: subprocess.Popen
        """
        allArgs = self.executable + self.keyserverOptions + args
        proc = subprocess.Popen(allArgs, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        return proc

def main() :
    gpg = GnuPGWrapper('hkp://localhost:11371')

    # gpg --keyserver hkp://localhost:11371 --search-keys 0xFBB75451
    gpg.searchKeys('0xFBB75451')
    # gpg --keyserver hkp://localhost:11371 --search-keys 0x4E4D8ABFD1AD524D
    # gpg --keyserver hkp://localhost:11371 --search-keys willi
    return
