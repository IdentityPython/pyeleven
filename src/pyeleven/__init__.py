from flask import Flask, request, jsonify
from .pk11 import pkcs11, intarray2bytes, mechanism

__author__ = 'leifj'

app = Flask(__name__)
app.config.from_pyfile('config.py')

@app.route("/info")
def info():
    library = app.config['PKCS11MODULE']
    return jsonify(dict(library=library))

@app.route("/<slot>/sign", methods=['POST'])
def sign(slot):
    msg = request.get_json()
    if not type(msg) is dict:
        raise ValueError("request must be a dict")

    msg.setdefault('mech', 'RSAPKCS1')
    if 'data' not in msg:
        raise ValueError("missing 'data' in request")
    data = msg['data']
    library = app.config['PKCS11MODULE']
    mech = mechanism(msg['mech'])
    pin = app.config.get('PKCS11PIN', None)
    with pkcs11(library, slot, pin=pin) as session:
        return jsonify(dict(slot=slot,
                            mech=msg['mech'],
                            signed=intarray2bytes(session.sign(data, mech))))
