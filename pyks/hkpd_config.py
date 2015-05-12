# -*- coding: utf-8 -*-
"""
"""

#Tests are isolated from network, so keyserver is not really hit.
HKP_LOCAL_PROXY_HOST = 'http://127.0.0.1'
HKP_LOCAL_PROXY_PORT = 11371

HKP_REMOTE_PROXY_HOST = 'http://127.0.0.1'
HKP_REMOTE_PROXY_PORT = 11370

# abs_path
HKP_REQUEST_LOOKUP = '/pks/lookup'
HKP_REQUEST_ADD = '/pks/add'

# variables and value
HKP_VARIABLE_OPERATION = 'op' # 'get' or 'index' or 'vindex'
HKP_VARIABLE_SEARCH = 'search'
HKP_VARIABLE_OPTIONS = 'options' # 'mr' or 'nm'
HKP_VARIABLE_FINGERPRINT = 'fingerprint' # 'on' or 'off'
HKP_VARIABLE_EXACT = 'exact' # 'on' or 'off'
HKP_VARIABLE_KEYTEXT = 'keytext' # within the body of the POST message on submit

KEY_SERVER = 'http://pool.sks-keyservers.net'

PORT = 11371


class SitePageContent(object) :

    def iterIndexPageLines(self) :

        baseurl = 'http://127.0.0.1:11371'

        SOME_KEY_ID = '0xFBB75451'
        SOME_SEARCH_STRING = SOME_KEY_ID # 'Remko'

        yield '<meta http-equiv="content-type" content="text/html; charset=utf-8">'

        yield '<html>'
        yield '<head>'
        yield '<title>PyKS - Test Cases</title>'
        yield '</head>'

        yield '<body>'
        yield '<h1>PyKS - Test Cases</h1>'

        yield '''<p>This page presents examples of possible query URLs defined\
 by the <b>The OpenPGP HTTP Keyserver Protocol (HKP)</b> which is currently (2014)\
 available as an Internet-Draft from David Shaw from March 2003 and is implemented\
 bei OpenPGP implementation such as GnuPG or PGP.\
 These query URLs are also used by the keyserver features of\
 your OpenPGP implementation, e.g.
 <ul>
 <li>Mozilla Thunderbird with the Enigmail plugin</li>
 <li>GnuPG command line tool</li>
 <li>Android App APG - Android Privacy Guard</li>
 <li>etc...</li>
 </ul>
 Therefore you should point your OpenPGP client to this keyserver (probably\
 running at <a href="http://localhost:11371">http://localhost:11371</a>.\
 Unfortunally not all of the currently existing OpenPGP clients allow you to\
 configure your own keyserver. Instead they have a built-in list of predefined\
 keyservers, such as
 <ul>
 <li>pool.sks-keyservers.net</li>
 <li>subkeys.pgp.net</li>
 <li>pgp.mit.edu</li>
 <li>etc...</li>
 </ul>
 </p>'''

        yield '<h2>/pks/lookup op=index</h2>'
        pks_lookup_index = '/pks/lookup?search=0xFBB75451&exact=off&options=mr&op=index'
        yield '<a href="%(baseurl)s%(pks_lookup_index)s">%(pks_lookup_index)s</a>' % locals()
        yield "<pre>"
        yield "gpg --keyserver hkp://localhost:11371 --search-keys 0xFBB75451" % locals()
        yield "gpg --keyserver hkp://localhost:11371 --search-keys 0x4E4D8ABFD1AD524D" % locals()
        yield "gpg --keyserver hkp://localhost:11371 --search-keys willi" % locals()
        # /pks/lookup?op=index&options=mr&search=andre.fritzsche-schwalbe%40orsoft.de HTTP/1.1" 200 -
        yield "</pre>"

        yield '<h2>/pks/lookup op=get</h2>'
        pks_lookup_get = '/pks/lookup?search=0xFBB75451&exact=off&options=mr&op=get'
        yield '<a href="%(baseurl)s%(pks_lookup_get)s">%(pks_lookup_get)s</a>' % locals()
        yield "<pre>"
        yield "gpg --keyserver hkp://localhost:11371 --recv-keys %(SOME_KEY_ID)s" % locals()
        yield "</pre>"

        yield '<h2>/pks/lookup op=vindex</h2>'
        pks_lookup_index = '/pks/lookup?search=0xFBB75451&exact=off&options=mr&op=vindex'
        yield '<a href="%(baseurl)s%(pks_lookup_index)s">%(pks_lookup_index)s</a>' % locals()
        yield "<pre>"
        yield "gpg --keyserver hkp://localhost:11371 --search-keys %(SOME_SEARCH_STRING)s" % locals()
        yield "</pre>"

        yield '<h2>/pks/add</h2>'
        pks_add = '/pks/add'
        yield '<a href="%(baseurl)s%(pks_add)s">%(pks_add)s</a>' % locals()
        yield "<pre>"
        yield "gpg --keyserver hkp://localhost:11371 --send-keys %(SOME_KEY_ID)s" % locals()
        yield "</pre>"

        yield '<hr/>'

        yield '</body>'
        yield '</html>'



