
[![Code Health](https://landscape.io/github/leifj/pyeleven/master/landscape.png)](https://landscape.io/github/leifj/pyeleven/master)
[![Travis](https://travis-ci.org/identitypython/pyeleven.svg?branch=master)](https://travis-ci.org/leifj/pyeleven)
[![Coverage Status](https://coveralls.io/repos/identitypython/pyeleven/badge.png)](https://coveralls.io/r/leifj/pyeleven)

Python PKCS11 REST Proxy
========================

A flask REST proxy for talking to a PKCS11 token wo having access to a native pkcs11 shim layer. Useful for cripled languages.

Getting started
---------------

1. build a virtualenv
2. install gunicorn
3. install this application
4. create config for your token

Checkout code
-------------

    # git clone <this github url>

Build a virtualenv
------------------

    # apt-get install python-virtualenv
    # virtualenv /path/to/venv
    # . /path/to/venv/bin/activate

Install packages
----------------

    # pip install -r requirements.txt
    # pip install gunicorn

Install this application
------------------------

    # ./setup develop

Create config
-------------

In the examples directory there is a script (gen-token.sh) that builds a sample config based on softhsm. Install softhsm first, then run gen-token.sh to create token, generate keys and create config.py. Finally start pyeleven in the same directory as the config.py file:

    # apt-get install libhsm-bin
    # cd examples
    # make
    # ls
    config.py  gen-token.sh  Makefile  openssl.conf  softhsm.conf  softhsm.db  test.crt  test.der
    # env SOFTHSM_CONF=softhsm.conf gunicorn --log-level debug -b :8080 pyeleven:app

This should start pyeleven on port 8080. Now try to sign something by POSTing a JSON object with 'mech' and 'data' fields. Currently 'mech' is silently ignored and RSASHA1 is used for everything. This will change soon.

API
---

**Sign**

POST a JSON object to

    /<slot>/<keyalias>/sign
    
with the following pattern:
    
    {'mech': 'RSAPKCS1', 'data': base64(<to be signed>)}
    
if successful the response will be a JSON object:

    {'mech': 'RSAPKCS1', 'slot': <slot>, 'signed': base64(<signed bytes>)}

**Slot Info**

GET
    /<slot>

returns a JSON datastructure representing information.
