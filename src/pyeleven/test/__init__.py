import os
import unittest

__author__ = 'leifj'


def _find_alts(alts):
    for a in alts:
        if os.path.exists(a):
            return a
    return None


P11_MODULE = _find_alts([
    '/usr/lib/libsofthsm2.so',
    '/usr/lib/softhsm/libsofthsm2.so',
    '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so'
])
P11_ENGINE = _find_alts(['/usr/lib/engines/engine_pkcs11.so', '/usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so'])
P11_SPY = _find_alts(['/usr/lib/pkcs11/pkcs11-spy.so'])
PKCS11_TOOL = _find_alts(['/usr/bin/pkcs11-tool'])
OPENSC_TOOL = _find_alts(['/usr/bin/opensc-tool'])
SOFTHSM = _find_alts(['/usr/bin/softhsm', '/usr/bin/softhsm2-util'])
OPENSSL = _find_alts(['/usr/bin/openssl'])

if OPENSSL is None:
    raise unittest.SkipTest("OpenSSL not installed")

if SOFTHSM is None:
    raise unittest.SkipTest("SoftHSM not installed")

if OPENSC_TOOL is None:
    raise unittest.SkipTest("OpenSC not installed")

if PKCS11_TOOL is None:
    raise unittest.SkipTest("pkcs11-tool not installed")

if P11_ENGINE is None:
    raise unittest.SkipTest("libengine-pkcs11-openssl is not installed")
