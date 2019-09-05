"""
Testing the PKCS#11 shim layer
"""
import os
import time
from base64 import b64encode
from unittest import TestCase

import six
from flask import json

from pyeleven.test import P11_MODULE
from pyeleven.test.utils import TemporarySoftHSM

__author__ = 'leifj'


class FlaskTestCase(TestCase):
    softhsm = TemporarySoftHSM.get_instance()

    def setUp(self):
        from .. import app
        os.environ['SOFTHSM2_CONF'] = self.softhsm.softhsm_conf
        app.config['TESTING'] = True
        app.config['PKCS11MODULE'] = P11_MODULE
        app.config['PKCS11PIN'] = 'secret1'
        self.app = app.test_client()

    def test_info(self):
        rv = self.app.get("/info")
        self.assertIsNotNone(rv.data)
        d = json.loads(rv.data)
        self.assertIsNotNone(d)
        self.assertIn('library', d)
        self.assertEqual(d['library'], P11_MODULE)

    def test_sign(self):
        data = b64encode(b"test")
        if six.PY3:
            data = data.decode('utf-8')
        rv = self.app.post("/test/test/sign",
                           content_type='application/json',
                           data=json.dumps(dict(mech='RSAPKCS1', data=data)))
        self.assertIsNotNone(rv.data)
        d = json.loads(rv.data)
        self.assertIsNotNone(d)
        self.assertIn('slot', d)
        self.assertIn('signed', d)

    def test_bad_sign(self):
        exception_thrown = False
        try:
            data = b64encode(b"test")
            if six.PY3:
                data = data.decode('utf-8')
            rv = self.app.post("/test/doesnotexist/sign",
                               content_type='application/json',
                               data=json.dumps(dict(mech='RSAPKCS1', data=data)))
        except Exception as ex:
            exception_thrown = True
            from traceback import print_exc
            if six.PY2:
                print_exc(ex)
            else:
                print_exc()
        self.assertTrue(exception_thrown)

    def test_1000_sign(self):
        ts = time.time()
        data = b64encode(b"test")
        if six.PY3:
            data = data.decode('utf-8')
        for i in range(0, 999):
            rv = self.app.post("/test/test/sign",
                               content_type='application/json',
                               data=json.dumps(dict(mech='RSAPKCS1', data=data)))
            self.assertIsNotNone(rv.data)
            d = json.loads(rv.data)
            self.assertIsNotNone(d)
            self.assertIn('slot', d)
            self.assertIn('signed', d)
        te = time.time()
        print("1000 signatures (http): %2.3f sec (speed: %2.5f s/sig)" % (te - ts, (te - ts) / 1000))

    def test_label_sign(self):
        data = b64encode(b"test")
        if six.PY3:
            data = data.decode('utf-8')
        rv = self.app.post("/test/test/sign",
                           content_type='application/json',
                           data=json.dumps(dict(mech='RSAPKCS1', data=data)))
        self.assertIsNotNone(rv.data)
        d = json.loads(rv.data)
        self.assertIsNotNone(d)
        self.assertIn('slot', d)
        self.assertIn('signed', d)
        self.assertIsNotNone(d['signed'])

    def test_bad_sign_request(self):
        try:
            rv = self.app.post("/test/test/sign",
                               content_type='application/json',
                               data=json.dumps('foo'))
            assert False
        except ValueError:
            pass

    def test_slot_info(self):
        rv = self.app.get("/test")
        self.assertIsNotNone(rv.data)
        d = json.loads(rv.data)
        self.assertIsNotNone(d)
        self.assertIn('slots', d)
        for nfo in d['slots']:
            self.assertIn('mechanisms', nfo)
            self.assertIn('slot', nfo)
            self.assertIn('token', nfo)
            self.assertIn('manufacturerID', nfo['slot'])
            self.assertIn('SoftHSM', nfo['slot']['manufacturerID'])
            self.assertIn('label', nfo['token'])
            self.assertIn('test', nfo['token']['label'])

    def test_token_info(self):
        rv = self.app.get("/")
        assert rv.data
        d = json.loads(rv.data)
        self.assertIsNotNone(d)
        self.assertIn('slots', d)
        self.assertEqual(len(d['slots']), 3)  # SoftHSM2 lists an additional slot that is uninitialized
        self.assertIn('labels', d)
        self.assertIn('test', d['labels'])
        test_slots = d['labels']['test']
        self.assertEqual(len(test_slots), 2)

    def test_slot_objects(self):
        rv = self.app.get("/test/objects")
        assert rv.data
        d = json.loads(rv.data)
        self.assertIsNotNone(d)
        self.assertIn('session', d)
        self.assertIn('objects', d)
        self.assertNotEqual(d['objects'], [])
