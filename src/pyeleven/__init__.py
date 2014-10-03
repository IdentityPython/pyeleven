from flask import Flask, request, jsonify
from .pk11 import pkcs11, intarray2bytes, mechanism, find_key, library
import os

__author__ = 'leifj'

app = Flask(__name__)
app.debug = True
app.config.from_pyfile(os.path.join(os.getcwd(), 'config.py'))
app.secret_key = app.config.get("SECRET_KEY")
print app.config
import sys

import logging
logging.basicConfig(level=logging.DEBUG)

@app.route("/info")
def _info():
    libn = app.config['PKCS11MODULE']
    return jsonify(dict(library=libn))

@app.route("/<int:slot>/<keyname>/sign", methods=['POST'])
def _sign(slot, keyname):
    msg = request.get_json()
    if not type(msg) is dict:
        raise ValueError("request must be a dict")

    msg.setdefault('mech', 'RSAPKCS1')
    if 'data' not in msg:
        raise ValueError("missing 'data' in request")
    data = msg['data'].decode('base64')
    libn = app.config['PKCS11MODULE']
    mech = mechanism(msg['mech'])
    pin = app.config.get('PKCS11PIN', None)
    with pkcs11(libn, slot, pin=pin) as session:
        key, cert = find_key(session, keyname)
        return jsonify(dict(slot=slot,
                            mech=msg['mech'],
                            signed=intarray2bytes(session.sign(key, data, mech)).encode('base64')))

@app.route("/<int:slot>", methods=['GET'])
def _slot(slot):
    lib = library(app.config['PKCS11MODULE'])
    r = dict()
    r['mechanisms'] = lib.getMechanismList(slot)
    r['slot'] = lib.getSlotInfo(slot).to_dict()
    r['token'] = lib.getTokenInfo(slot).to_dict()
    return jsonify(r)

@app.route("/", methods=['GET'])
def _token():
    lib = library(app.config['PKCS11MODULE'])
    r = dict()
    r['slots'] = lib.getSlotList()
    return jsonify(r)


if __name__ == "__main__":
    app.run()

main = app.run