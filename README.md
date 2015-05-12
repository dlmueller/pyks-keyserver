pyks-keyserver
==============

.. contents::
   :local:

Overview
--------

PyKS is an OpenPGP keyserver that is intended to run on localhost
or in small intranets. It is a proof-of-concept implementation of
some ideas to make harvesting e-mail addresses and social graphs
from public keyserver data more expensive for an adversary.

Features
--------

- Supports HKP/web-based querying, and machine readable indices 
  (therefor compatible  for instance with GnuPG and Thunderbird)

Installation
------------

Clone this git repository an start the local HTTP server listening
on port 11371 (HTTP Keyserver Protocol - HKP):

.. code:: bash

    python pyks/hkp_local_server.py

Usage
-----

You can export all public keys from your keyring using the following
GnuPG command line:

.. code:: bash

    gpg --list-keys | grep pub | cut -d"/" -f2 | cut -d" " -f1 > keyids.txt
    cat keyids.txt | xargs gpg --keyserver hkp://localhost --send-keys

You will find the exported keys in ASCII armor format in an 
`SQLlite <https://www.sqlite.org/>` database located in your PyKS
installation folder at ``pyks/persistence/localdata.v01.db``.
