from base64 import b64decode
from flask import Flask, request, jsonify
from .pk11 import pkcs11, load_library, slots_for_label
from .utils import mechanism, intarray2bytes
import os
import logging
from .pool import allocation
from retrying import retry
from PyKCS11 import PyKCS11Error

__author__ = 'leifj'

app = Flask(__name__)
app.debug = True
app.config.from_pyfile(os.path.join(os.getcwd(), 'config.py'))
max_retry = app.config.get('MAX_RETRY', 7)


def pin():
    return app.config.get('PKCS11PIN', None)


def secret_key():
    return app.config.get("SECRET_KEY")


def library_name():
    return str(app.config['PKCS11MODULE'])


#print app.config

logging.basicConfig(level=logging.DEBUG)


@app.route("/info")
def _info():
    return jsonify(dict(library=library_name()))


@retry(stop_max_attempt_number=max_retry)
def _do_sign(label, keyname, mech, data, include_cert=True, require_cert=False):
    if require_cert:
        include_cert = True

    with pkcs11(library_name(), label, pin()) as si:
        key, cert = si.find_key(keyname, find_cert=include_cert)
        assert key is not None
        result = dict(slot=label,signed=intarray2bytes(si.session.sign(key, data, mech)).encode('base64'))
        if require_cert:
            assert cert is not None
        if cert and include_cert:
            result['cert'] = cert
        return result


@app.route("/<slot_or_label>/<keyname>/sign", methods=['POST'])
def _sign(slot_or_label, keyname):

    msg = request.get_json()
    if not type(msg) is dict:
        raise ValueError("request must be a dict")

    msg.setdefault('mech', 'RSAPKCS1')
    if 'data' not in msg:
        raise ValueError("missing 'data' in request")
    data = b64decode(msg['data'])
    mech = mechanism(msg['mech'])
    return jsonify(_do_sign(slot_or_label, keyname, mech, data, require_cert=True))


@app.route("/<slot_or_label>/<keyname>/rawsign", methods=['POST'])
def _rawsign(slot_or_label, keyname):

    msg = request.get_json()
    if not type(msg) is dict:
        raise ValueError("request must be a dict")

    msg.setdefault('mech', 'RSAPKCS1')
    if 'data' not in msg:
        raise ValueError("missing 'data' in request")
    data = b64decode(msg['data'])
    mech = mechanism(msg['mech'])
    return jsonify(_do_sign(slot_or_label, keyname, mech, data, include_cert=False))


@app.route("/<slot_or_label>", methods=['GET'])
def _slot(slot_or_label):
    lib = load_library(library_name())
    slots = slots_for_label(slot_or_label, lib)
    result = []
    for slot in slots:
        r = dict()
        try:
            r['mechanisms'] = lib.getMechanismList(slot)
        except (PyKCS11Error, KeyError, ValueError, IOError) as ex:
            r['mechanisms'] = {'error': str(ex)}
        try:
            r['slot'] = lib.getSlotInfo(slot).to_dict()
        except (PyKCS11Error, KeyError, ValueError, IOError) as ex:
            r['slot'] = {'error': str(ex)}
        try:
            r['token'] = lib.getTokenInfo(slot).to_dict()
        except (PyKCS11Error,  KeyError, ValueError, IOError) as ex:
            r['token'] = {'error': str(ex)}

        result.append(r)

    return jsonify(dict(slots=result))


@app.route("/", methods=['GET'])
def _token():
    lib = load_library(library_name())
    r = dict()
    token_labels = dict()
    slots = []
    for slot in lib.getSlotList():
        try:
            ti = lib.getTokenInfo(slot)
            lst = token_labels.setdefault(ti.label.strip(), [])
            lst.append(slot)
            slots.append(slot)
        except Exception, ex:
            logging.warning(ex)
    r['labels'] = token_labels
    r['slots'] = slots
    return jsonify(r)


if __name__ == "__main__":
    app.run()

main = app.run
