import threading
from .pool import ObjectPool, allocation
from .utils import intarray2bytes, cert_der2pem
from random import Random
import time
import logging
import PyKCS11
from PyKCS11.LowLevel import CKA_ID, \
    CKA_LABEL, \
    CKA_CLASS, \
    CKO_PRIVATE_KEY, \
    CKO_CERTIFICATE, \
    CKK_RSA, \
    CKA_KEY_TYPE, \
    CKA_VALUE

__author__ = 'leifj'

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


def _modules():
    if not hasattr(thread_data, 'modules'):
        thread_data.modules = dict()
    return thread_data.modules


def _sessions():
    if not hasattr(thread_data, 'sessions'):
        thread_data.sessions = dict()
    return thread_data.sessions


def _pools():
    if not hasattr(thread_data, 'pools'):
        thread_data.pools = dict()
    return thread_data.pools


def reset():
    _pools()
    _sessions()
    _modules()
    thread_data.pools = dict()
    thread_data.sessions = dict()
    thread_data.modules = dict()


def load_library(lib_name):
    modules = _modules()
    if lib_name not in modules:
        logging.debug("loading load_library %s" % lib_name)
        lib = PyKCS11.PyKCS11Lib()
        assert type(lib_name) == str  # lib.load does not like unicode
        lib.load(lib_name)
        lib.lib.C_Initialize()
        modules[lib_name] = lib

    return modules[lib_name]


class SessionInfo(object):
    def __init__(self, session, slot):
        self.session = session
        self.slot = slot
        self.keys = {}
        self.use_count = 0

    @property
    def priority(self):
        return self.use_count

    def __str__(self):
        return "SessionInfo[session=%s,slot=%d,use_count=%d,keys=%d]" % (
        self.session, self.slot, self.use_count, len(self.keys))

    def __cmp__(self, other):
        return cmp(self.use_count, other.use_count)

    def find_object(self, template):
        for o in self.session.findObjects(template):
            return o
        return None

    def get_object_attributes(self, o, attrs=all_attributes):
        attributes = self.session.getAttributeValue(o, attrs)
        return dict(zip(attrs, attributes))

    def find_key(self, keyname, find_cert=True):
        if keyname not in self.keys:
            key = self.find_object([(CKA_LABEL, keyname), (CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA)])
            if key is None:
                logging.debug('Private RSA key with CKA_LABEL {!r} not found'.format(keyname))
                return None, None
            cert_pem = None
            if find_cert:
                key_a = self.get_object_attributes(key, attrs = [CKA_ID])
                logging.debug('Looking for certificate with CKA_ID {!r}'.format(key_a[CKA_ID]))
                cert = self.find_object([(CKA_ID, key_a[CKA_ID]), (CKA_CLASS, CKO_CERTIFICATE)])
                if cert is not None:
                    cert_a = self.get_object_attributes(cert)
                    cert_pem = cert_der2pem(intarray2bytes(cert_a[CKA_VALUE]))
                    logging.debug('Certificate found:\n{!r}'.format(cert))
                else:
                    logging.warning('Found no certificate for key with keyname {!r}'.format(keyname))
            self.keys[keyname] = (key, cert_pem)

        return self.keys[keyname]

    @staticmethod
    def open(lib, slot, pin=None):
        sessions = _sessions()
        if slot not in sessions:
            session = lib.openSession(slot)
            if pin is not None:
                try:
                session.login(pin)
                except PyKCS11.PyKCS11Error as ex:
                    logging.debug('Login failed: {!r}'.format(ex))
                    if 'CKR_USER_ALREADY_LOGGED_IN' not in str(ex):
                        raise
            si = SessionInfo(session=session, slot=slot)
            sessions[slot] = si
        # print "opened session for %s:%d" % (lib, slot)
        return sessions[slot]

    @staticmethod
    def close_slot(slot):
        sessions = _sessions()
        if slot in sessions:
            del sessions[slot]

    def close(self):
        SessionInfo.close_slot(self.slot)


def _find_slot(label, lib):
    slots = []
    for slot in lib.getSlotList():
        try:
            token_info = lib.getTokenInfo(slot)
            if label == token_info.label.strip():
                slots.append(int(slot))
        except Exception, ex:
            pass
    return slots


def slots_for_label(label, lib):
    try:
        slot = int(label)
        return [slot]
    except ValueError:
        return _find_slot(label, lib)


seed = Random(time.time())


def pkcs11(library_name, label, pin=None, max_slots=None):
    pools = _pools()
    sessions = _sessions()

    if max_slots is None:
        max_slots = len(slots_for_label(label, load_library(library_name)))

    def _del(*args, **kwargs):
        si = args[0]
        sd = kwargs['slots']
        if si.slot in sd:
            del sd[si.slot]
        si.close()

    def _bump(si):
        si.use_count += 1

    def _get(*args, **kwargs):
        lib = load_library(library_name)
        sd = kwargs['slots']

        def _refill():  # if sd is getting a bit light - fill it back up
            if len(sd) < max_slots:
                for slot in slots_for_label(label, lib):
                    # print "found slot %d during refill" % slot
                    sd[slot] = True

        random_slot = None
        while True:
            _refill()
            k = sd.keys()
            random_slot = seed.choice(k)
            # print random_slot
            try:
                return SessionInfo.open(lib, random_slot, pin)
            except Exception, ex:  # on first suspicion of failure - force the slot to be recreated
                if random_slot in sd:
                    del sd[random_slot]
                SessionInfo.close_slot(random_slot)
                time.sleep(50 / 1000)  # TODO - make retry delay configurable
                logging.error('Failed opening session (retry: {!r}): {!s}'.format(retry, ex))

    return allocation(pools.setdefault(label, ObjectPool(_get, _del, _bump, maxSize=max_slots, slots=dict())))
