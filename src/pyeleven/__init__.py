from flask import Flask, request, jsonify
from .pk11 import pkcs11, intarray2bytes, mechanism, find_key, library
import os
import sys
import logging

__author__ = 'leifj'

app = Flask(__name__)
app.debug = True
app.config.from_pyfile(os.path.join(os.getcwd(), 'config.py'))
app.secret_key = app.config.get("SECRET_KEY")
print app.config

logging.basicConfig(level=logging.DEBUG)


@app.route("/info")
def _info():
    libn = app.config['PKCS11MODULE']
    return jsonify(dict(library=libn))


def _find_slot(label):
    slots = []
    lib = library(app.config['PKCS11MODULE'])
    for slot in lib.getSlotList():
        slot_info = lib.getSlotInfo(slot)
        if slot_info.get('label') == label:
            slots.append(slot)
    return slots


@app.route("/<slot_or_label>/<keyname>/sign", methods=['POST'])
def _sign(slot_or_label, keyname):

    slots = []
    try:
        slot = int(slot_or_label)
        slots = [slot]
    except ValueError:
        slots = _find_slot(slot_or_label)

    if not slots:
        raise ValueError("No slot found matching %s" % slot_or_label)

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
    for slot in slots:
        try:
            with pkcs11(libn, slot, pin=pin) as si:
                key, cert = find_key(si, keyname)
                assert key is not None
                assert cert is not None
                return jsonify(dict(slot=slot,
                                    mech=msg['mech'],
                                    signed=intarray2bytes(si.session.sign(key, data, mech)).encode('base64')))
        except Exception, ex:
            logging.error(ex)
            with pkcs11(libn, slot, pin=pin) as si:
                si.exception = ex  # invalidate it

    raise ValueError("Unable to sign using any of the matching slots")


@app.route("/<slot_or_label>", methods=['GET'])
def _slot(slot_or_label):
    slot = -1
    try:
        slot = int(slot_or_label)
    except ValueError:
        slot = _find_slot(slot_or_label)

    lib = library(app.config['PKCS11MODULE'])
    r = dict()
    try:
        r['mechanisms'] = lib.getMechanismList(slot)
    except:
        pass
    try:
        r['slot'] = lib.getSlotInfo(slot).to_dict()
    except:
        pass
    try:
        r['token'] = lib.getTokenInfo(slot).to_dict()
    except:
        pass
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