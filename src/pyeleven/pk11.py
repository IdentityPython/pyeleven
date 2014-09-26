import base64
import threading

__author__ = 'leifj'

import logging
import PyKCS11

from PyKCS11.LowLevel import CKA_ID, CKA_LABEL, CKA_CLASS, CKO_PRIVATE_KEY, CKO_CERTIFICATE, CKK_RSA, \
    CKA_KEY_TYPE, CKA_VALUE

all_attributes = PyKCS11.CKA.keys()

# remove the CKR_ATTRIBUTE_SENSITIVE attributes since we can't get
all_attributes.remove(PyKCS11.LowLevel.CKA_PRIVATE_EXPONENT)
all_attributes.remove(PyKCS11.LowLevel.CKA_PRIME_1)
all_attributes.remove(PyKCS11.LowLevel.CKA_PRIME_2)
all_attributes.remove(PyKCS11.LowLevel.CKA_EXPONENT_1)
all_attributes.remove(PyKCS11.LowLevel.CKA_EXPONENT_2)
all_attributes.remove(PyKCS11.LowLevel.CKA_COEFFICIENT)
all_attributes = [e for e in all_attributes if isinstance(e, int)]

thread_data = threading.local()
_session_lock = threading.RLock()


def _modules():
    if not hasattr(thread_data, 'modules'):
        thread_data.modules = dict()
    return thread_data.modules


def _sessions():
    if not hasattr(thread_data, 'sessions'):
        thread_data.sessions = dict()
    return thread_data.sessions


def mechanism(mech):
    mn = "Mechanism%s" % mech
    return getattr(PyKCS11, mn)


def library(lib_name):
    modules = _modules()
    if not lib_name in modules:
        logging.debug("loading library %s" % lib_name)
        lib = PyKCS11.PyKCS11Lib()
        assert type(lib_name) == str  # lib.load does not like unicode
        lib.load(lib_name)
        modules[lib_name] = lib

    return modules[lib_name]


class pkcs11():

    def __init__(self, library, slot, pin=None):
        self.library = library
        self.slot = slot
        self.pin = pin

    def __enter__(self):
        _session_lock.acquire()

        s = _sessions()
        if self.library not in s:
            s.setdefault(self.library, dict())

        if self.slot not in s[self.library]:
            s[self.library].setdefault(self.slot, dict())

            lib = library(self.library)
            session = lib.openSession(self.slot)
            if self.pin is not None:
                session.login(self.pin)
            s[self.library][self.slot] = session

        if self.slot not in s[self.library]:
            raise EnvironmentError("Unable to open session")

        return s[self.library][self.slot]

    def __exit__(self, exc_type, exc_val, exc_tb):
        #s = _sessions()
        #if self.library not in s:
        #    s.setdefault(self.library, dict())

        #if self.slot in s[self.library]:
        #    session = s[self.library][self.slot]
        #    session.logout()
        #    session.closeSession()
        #    del s[self.library][self.slot]
        _session_lock.release()


def intarray2bytes(x):
    return ''.join(chr(i) for i in x)


def find_object(session, template):
    for o in session.findObjects(template):
        logging.debug("Found pkcs11 object: %s" % o)
        return o
    return None


def get_object_attributes(session, o):
    attributes = session.getAttributeValue(o, all_attributes)
    return dict(zip(all_attributes, attributes))


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


def find_key(session, keyname):
    key = find_object(session, [(CKA_LABEL, keyname), (CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA)])
    if key is None:
        return None, None
    key_a = get_object_attributes(session, key)
    cert = find_object(session, [(CKA_ID, key_a[CKA_ID]), (CKA_CLASS, CKO_CERTIFICATE)])
    cert_pem = None
    if cert is not None:
        cert_a = get_object_attributes(session, cert)
        cert_pem = cert_der2pem(intarray2bytes(cert_a[CKA_VALUE]))
        logging.debug(cert)
    return key, cert_pem

