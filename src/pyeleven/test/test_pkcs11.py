import os
import random
import time
from collections import Counter
from unittest import TestCase

import pkg_resources
from retrying import retry

from pyeleven import pk11
from pyeleven.test import P11_MODULE, TemporarySoftHSM
from pyeleven.test.utils import ThreadPool
from pyeleven.utils import mechanism, intarray2bytes


class TestPKCS11(TestCase):

    def setUp(self):
        self.softhsm = TemporarySoftHSM.get_instance()
        datadir = pkg_resources.resource_filename(__name__, 'data')

    def test_open_session(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()
        with pk11.pkcs11(P11_MODULE, 'test', "secret1") as session:
            self.assertIsNotNone(session)

    def test_multislot(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()
        lib = pk11.load_library(P11_MODULE)
        slots = pk11.slots_for_label('test', lib)
        self.assertEqual(len(slots), 2)

    def test_find_key(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()
        with pk11.pkcs11(P11_MODULE, 'test', "secret1") as si:
            self.assertIsNotNone(si)
            key, cert = si.find_key('test')
            self.assertIsNotNone(key)
            self.assertIsNotNone(cert)

    def test_find_key_spread(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()
        hits = Counter()

        @retry(stop_max_attempt_number=20)
        def _try_sign():
            with pk11.pkcs11(P11_MODULE, 'test', 'secret1') as si:
                self.assertIsNotNone(si)
                key, cert = si.find_key('test')
                self.assertIsNotNone(key)
                self.assertIsNotNone(cert)
                self.assertIsNotNone(si.slot)
                hits[si.slot] += 1
                if si.slot == random.choice([0, 1]):
                    raise ValueError("force a retry...")

        for i in range(0, 99):
            _try_sign()

        self.assertEqual(len(hits.keys()), 2)
        for k in hits.keys():
            self.assertGreater(hits[k], 30)

    def test_find_key_by_label(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()
        with pk11.pkcs11(P11_MODULE, 'test', "secret1") as si:
            self.assertIsNotNone(si)
            key, cert = si.find_key('test')
            self.assertIsNotNone(key)
            self.assertIsNotNone(cert)

    def test_exception_reopen_session(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()
        for i in range(0, 10):
            try:
                with pk11.pkcs11(P11_MODULE, 'test', "secret1") as si:
                    self.assertIsNotNone(si)
                    raise ValueError("oops...")
            except ValueError:
                pass

    def test_sign(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()
        with pk11.pkcs11(P11_MODULE, 'test', "secret1") as si:
            key, cert = si.find_key('test')
            self.assertIsNotNone(key)
            self.assertIsNotNone(cert)
            signed = intarray2bytes(si.session.sign(key, 'test', mechanism('RSAPKCS1')))
            self.assertIsNotNone(signed)

    def test_1000_sign(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()
        print('test_1000_sign')

        ts = time.time()
        for i in range(0, 999):
            print('test_1000_sign_%d' % i)
            with pk11.pkcs11(P11_MODULE, 'test', 'secret1') as si:
                print(si)
                self.assertIsNotNone(si)
                key, cert = si.find_key('test')
                self.assertIsNotNone(key)
                self.assertIsNotNone(cert)
                signed = intarray2bytes(si.session.sign(key, 'test', mechanism('RSAPKCS1')))
                self.assertIsNotNone(signed)
        te = time.time()
        print("1000 signatures (p11): %2.3f sec (speed: %2.5f sec/s)" % (te - ts, (te - ts) / 1000))

    def test_stress_sign_sequential(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()

        def _sign(msg):
            with pk11.pkcs11(P11_MODULE, 'test', "secret1") as si:
                self.assertIsNotNone(si)
                key, cert = si.find_key('test')
                self.assertIsNotNone(key)
                self.assertIsNotNone(cert)
                signed = intarray2bytes(si.session.sign(key, msg, mechanism('RSAPKCS1')))
                self.assertIsNotNone(signed)

        for i in range(0, 999):
            _sign("message %d" % i)

    def test_stress_sign_parallell_20(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()

        def _sign(msg):
            with pk11.pkcs11(P11_MODULE, 'test', "secret1") as si:
                key, cert = si.find_key('test', find_cert=False)
                signed = intarray2bytes(si.session.sign(key, msg, mechanism('RSAPKCS1')))
                self.assertIsNotNone(signed)

        ts = time.time()
        tp = ThreadPool(20)
        for i in range(0, 999):
            tp.add_task(_sign, "message %d" % i)
        tp.wait_completion()
        te = time.time()
        print("1000 signatures (p11 parallell): %2.3f sec (speed: %2.5f sec/s)" % (te - ts, (te - ts) / 1000))

    def test_stress_sign_parallell_20_with_failovers(self):
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        pk11.reset()

        @retry(stop_max_attempt_number=10)
        def _sign(i):
            msg = "message %d" % i
            with pk11.pkcs11(P11_MODULE, 'test', "secret1") as si:
                key, _ = si.find_key('test', find_cert=False)
                signed = intarray2bytes(si.session.sign(key, msg, mechanism('RSAPKCS1')))
                self.assertIsNotNone(signed)

        ts = time.time()
        tp = ThreadPool(20)
        for i in range(0, 999):  # simulate 10 failures on each slot
            tp.add_task(_sign, i)
        tp.wait_completion()
        te = time.time()
        print("1000 signatures (p11 parallell): %2.3f sec (speed: %2.5f sec/s)" % (te - ts, (te - ts) / 1000))
