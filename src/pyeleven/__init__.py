from flask import Flask, request, jsonify
from .pk11 import pkcs11, intarray2bytes, mechanism, find_key
import os

__author__ = 'leifj'

app = Flask(__name__)
app.debug = True
app.config.from_pyfile(os.path.join(os.getcwd(), 'config.py'))
app.secret_key = app.config.get("SECRET_KEY")
print app.config

@app.route("/info")
def info():
    library = app.config['PKCS11MODULE']
    return jsonify(dict(library=library))

@app.route("/<slot>/<keyname>/sign", methods=['POST'])
def sign(slot, keyname):
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
        key, cert = find_key(session, keyname)
        return jsonify(dict(slot=slot,
                            mech=msg['mech'],
                            signed=intarray2bytes(session.sign(key, data, mech))))


if __name__ == "__main__":
    app.run()

main = app.run