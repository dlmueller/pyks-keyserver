# -*- coding: utf-8 -*-
"""
This is the reference implementation of the remote part of the key serving system,
that has no clear text access to user ids (i.e. e-mail adresses) etc.

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
import datetime
import cgitb
import sys
import time
import os

#---
#--- Extend Python search path
sys.path.append(os.getcwd())

#---
#--- .
import hkpd_config
import hkp_internals
import cert_db
import translog


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
    return render_template('remote_index.html',
                           numbers = range(0, 10),
                           name = 'You')

@app.route('/test_cases')
def test_cases():
    """
    Static URLs for HKPs Query-API
    """
    #spc = hkpd_config.SitePageContent()
    #return "".join(spc.iterIndexPageLines())
    return render_template('remote_test_cases.html',
                           numbers = range(0, 10),
                           name = 'You')


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
    search = request.args.get('search', None) or ''

    # 3.1.2. The "op" (operation) Variable
    op = request.args.get('op', None) or ''

    # 3.2.1. The "options" Variable
    options = request.args.get('options', None) or ''
    # options may contain 'mr' for 'machine readable'

    # 3.2.2. The "fingerprint" Variable
    fingerprint = (request.args.get('fingerprint', None) or '').lower() == 'on'

    # 3.2.3. The "exact" Variable
    exact = (request.args.get('exact', None) or '').lower() == 'on'

    # 3.2.3. Other Variables

    searchPattern = normalize_search_variable(search, exact != 'off')

    content = 'SERVER ERROR'
    mimeType = 'text/plain'
    return Response(content, mimetype = mimeType)


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


# -----------------------------------------------------------------------------------
#--- main
# -----------------------------------------------------------------------------------

def main(argv):
    """
    @param argv: command line arguments
    """
    portNumber = hkpd_config.HKP_REMOTE_PROXY_PORT

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
