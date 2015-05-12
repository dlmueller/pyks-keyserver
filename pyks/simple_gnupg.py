# -*- coding: utf-8 -*-
"""
Simple Python wrapper for GnuPG with strong focus on key management.

Usage::

    #!python
    from pyks import simple_gnupg
    gpg = simple_gnupg.GnuPGWrapper('hkp://localhost:11371')

    print gpg.listKeys()

    gpg.searchKeys('0xFBB75451')

    gpg.receiveKeys('0xFBB75451')

    print gpg.listKeys()

    gpg.deleteKeys('0xFBB75451')

    gpg.sendKeys('0xE132C902')
"""

#---
#--- Python
import subprocess
#import StringIO

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
        self.executable = ['gpg', '--utf8-strings', '--display-charset', 'utf-8']
        self.keyserverOptions = ['--keyserver', hostAndPort]


    def searchKeys(self, searchData):
        """
        /pks/lookup op=index
        /pks/lookup?search=0xFBB75451&exact=off&options=mr&op=index
        """
        proc = self.run(['--search-keys', searchData])
#        proc.wait()
#        buf = 'q' # StringIO.StringIO('q')
#        proc.communicate(buf)
        return


    def receiveKeys(self, searchData):
        """
        /pks/lookup op=get
        /pks/lookup?search=0xFBB75451&exact=off&options=mr&op=get
        """
        # gpg --keyserver hkp://localhost:11371 --recv-keys 0xFBB75451
        proc = self.run(['--recv-keys', searchData])
        return


    def listKeys(self):
        # gpg --list-keys
        proc = self.run(['--list-keys'])
        proc.wait()
        return "".join((l.decode('utf8') for l in proc.stdout.readlines()))


    def deleteKeys(self, keyId):
        # gpg --delete-keys 0x448701A8
        proc = self.run(['--delete-keys', keyId])
#        proc.wait()
#        buf = 'j' # StringIO.StringIO('q')
#        proc.communicate(buf)
        return


#    def dontKnowWhatThisShouldBe(self):
#        """
#        /pks/lookup op=vindex
#        /pks/lookup?search=0xFBB75451&exact=off&options=mr&op=vindex
#        """
#        # gpg --keyserver hkp://localhost:11371 --search-keys 0xFBB75451
#        return


    def sendKeys(self, keyId):
        """
        /pks/add
        /pks/add
        """
        # gpg --keyserver hkp://localhost:11371 --recv-keys 0xFBB75451 --> sollte nichts liefern
        # gpg --keyserver hkp://localhost:11371 --send-keys 0xFBB75451
        # gpg --keyserver hkp://localhost:11371 --recv-keys 0xFBB75451
        proc = self.run(['--send-keys', keyId])
        return


    def run(self, args):
        """
        @param args: e.g. ['--search-keys', '0xFBB75451']
        @type  args: [str]

        @rtype: subprocess.Popen
        """
        allArgs = self.executable + self.keyserverOptions + args
        proc = subprocess.Popen(allArgs,
                                stdin = subprocess.PIPE,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.PIPE)
        return proc
