import base64
import PyKCS11


def intarray2bytes(x):
    return ''.join(chr(i) for i in x)


def mechanism(mech):
    mn = "Mechanism%s" % mech
    return getattr(PyKCS11, mn)


def cert_der2pem(der):
    x = base64.standard_b64encode(der)
    r = "-----BEGIN CERTIFICATE-----\n"
    while len(x) > 64:
        r += x[0:64]
        r += "\n"
        x = x[64:]
    r += x
    r += "\n"
    r += "-----END CERTIFICATE-----"
    return r
