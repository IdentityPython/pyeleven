import logging
import os
from base64 import b64decode, b64encode

import six
from PyKCS11 import PyKCS11Error
from flask import Flask, request, jsonify
from retrying import retry

from pyeleven.pk11 import pkcs11, load_library, slots_for_label
from pyeleven.pool import allocation
from pyeleven.utils import mechanism, intarray2bytes

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


class PKCS11Exception(Exception):
    pass


def retryable_errors(ex):
    return isinstance(ex, IOError) or isinstance(ex, PKCS11Exception)


@retry(stop_max_attempt_number=max_retry, retry_on_exception=retryable_errors, wait_random_min=100, wait_random_max=500)
def _do_sign(label, keyname, mech, data, include_cert=True, require_cert=False):
    if require_cert:
        include_cert = True

    with pkcs11(library_name(), label, pin()) as si:
        logging.debug('Looking for key with keyname {!r}'.format(keyname))
        key, cert = si.find_key(keyname, find_cert=include_cert)
        if key is None:
            logging.warning('Found no key using label {!r}, keyname {!r}'.format(label, keyname))
            raise PKCS11Exception("Key %s not found" % keyname)
        if require_cert and cert is None:
            logging.warning('Found no certificate using label {!r}, keyname {!r}'.format(label, keyname))
            raise PKCS11Exception("Certificate for %s is required but missing" % keyname)
        logging.debug('Signing {!s} bytes using key {!r}'.format(len(data), keyname))
        result = dict(slot=label, signed=b64encode(intarray2bytes(si.session.sign(key, data, mech))).decode('utf-8'))
        if cert and include_cert:
            result['cert'] = cert
        return result


@app.route("/<slot_or_label>/<keyname>/sign", methods=['POST'])
def _sign(slot_or_label, keyname):

    msg = request.get_json()
    if not type(msg) is dict:
        raise ValueError("request must be a dict")

    logging.debug('Signing data with slot_or_label {!r} and keyname {!r}\n'.format(slot_or_label, keyname))
    msg.setdefault('mech', 'RSAPKCS1')
    if 'data' not in msg:
        raise ValueError("missing 'data' in request")
    data = b64decode(msg['data'])
    if six.PY3:
        data = data.decode('utf-8')
    mech = mechanism(msg['mech'])
    result = _do_sign(slot_or_label, keyname, mech, data, require_cert=True)
    return jsonify(result)


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


@app.route("/<slot_or_label>/objects", methods=['GET'])
def _slot_keys(slot_or_label):
    res = {}
    with pkcs11(library_name(), slot_or_label, pin()) as si:
        res['session'] = si.session.getSessionInfo().to_dict()
        res['objects'] = []
        for this in si.session.findObjects():
            try:
                attrs = si.get_object_friendly_attrs(this)
                res['objects'].append(attrs)
            except Exception as ex:
                logging.error('Failed fetching attributes for object, error: {!s}'.format(ex))
    return jsonify(res)


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
        except Exception as ex:
            logging.warning(ex)
    r['labels'] = token_labels
    r['slots'] = slots
    return jsonify(r)


if __name__ == "__main__":
    app.run()

main = app.run
