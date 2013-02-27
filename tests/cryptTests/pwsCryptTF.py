#!/usr/bin/env python
#===============================================================================
# This file is part of PyPWSafe.
#
#    PyPWSafe is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    PyPWSafe is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with PyPWSafe.  If not, see http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
#===============================================================================
''' Test the twofish libs distributed with this package
Created on Feb, 18 2013

@author: Paulson McIntyre (GpMidi) <paul@gpmidi.net>
@license: GPLv2
@version: 0.1
'''
import unittest
import os, os.path, sys


class TwofishCryptPythonTestsDynamic(unittest.TestCase):
    TEST_KEY_LEN = 32
    MAX_DATA_LEN = 65536
    DATA_LEN_TESTS = [
                      8,
                      16,
                      20,
                      2040,
                      ]
    
    def setUp(self):
        self.key = os.urandom(self.TEST_KEY_LEN)
        self.iv = os.urandom(16)
        self.data = os.urandom(self.MAX_DATA_LEN)
    
    def test_tests(self):
        """ Make sure the test vars are set right """
        self.assertTrue(self.TEST_KEY_LEN%16==0, "The test key length must be a multiple of 16")
        self.assert_(len(self.data) > 8192, "Test data must be at least 8192 bytes long")

    def test_tf_ecb_enc_length(self):
        from pypwsafe.crypt import TwofishECBCEncryption
        crypt = TwofishECBCEncryption(key = self.key)
        for length in self.DATA_LEN_TESTS:
            out = crypt.encrypt(data = self.data[:length])
            self.assertEqual(len(out) % 16, 0, "Output length must be a multiple of 16 (the block size)")

    def test_tf_cbc_enc_length(self):
        from pypwsafe.crypt import TwofishCBCEncryption
        crypt = TwofishCBCEncryption(key = self.key, iv = self.iv)
        for length in self.DATA_LEN_TESTS:
            out = crypt.encrypt(data = self.data[:length])
            self.assertEqual(len(out) % 16, 0, "Output length must be a multiple of 16 (the block size)")

    def test_tf_cbc(self):
        from pypwsafe.crypt import TwofishCBCEncryption, TwofishCBCDecryption
        crypt=TwofishCBCEncryption('\xf2\xe9\x8ap\x9b0i/\xb5\xe2>(\x03VA\xee[\r:\xbeS6?\xef\xa8F\x0c\x06\xf7\x84\x01\x14','\x1a\xc3\x1fI\xe4\xaa\x07g\xa1\xc3z!Z\xfc>\x17')
        self.assertEqual(
                         crypt.encrypt('\xf4\x04\xb5\xaea7:*\xcap\x99\x03\x83\x81\x8b72\xc1E\xb5\xe9X<\xcc\x05\x0c\x93\xae\xbe\x82'),
                         '\xd4)\xa5\x96\xe0.*\x97-\x12\xa1\xf2\x07\xc5\xe7\x93O\x1d\n\xb1!3p=\xb7s\xcc\xfb\x11\xa6\xba\x0b',
                         "Encryption produced the wrong cipher text",
                         )
        self.assertEqual(
                         crypt.encrypt('\xf4\x04\xb5\xaea7:*\xcap\x99\x03\x83\x81\x8b72\xc1E\xb5\xe9X<\xcc\x05\x0c\x93\xae\xbe\x82'),
                         '\xff\x08\xe4\x10g\x15&9\xc6lN\xf8\xe9\xd2\x1e\x8a\x08\x16\xba\x1f\x91\xb6\xb9\xaa\xd8`#\x13$V\xe5\xbb',
                         "Encrypting the same value a second time resulted in the wrong cipher text",
                         )
        decrypt = TwofishCBCDecryption('\xf2\xe9\x8ap\x9b0i/\xb5\xe2>(\x03VA\xee[\r:\xbeS6?\xef\xa8F\x0c\x06\xf7\x84\x01\x14', '\x1a\xc3\x1fI\xe4\xaa\x07g\xa1\xc3z!Z\xfc>\x17')
        self.assertEqual(
                         decrypt.decrypt('\xd4)\xa5\x96\xe0.*\x97-\x12\xa1\xf2\x07\xc5\xe7\x93O\x1d\n\xb1!3p=\xb7s\xcc\xfb\x11\xa6\xba\x0b'),
                         '\xf4\x04\xb5\xaea7:*\xcap\x99\x03\x83\x81\x8b72\xc1E\xb5\xe9X<\xcc\x05\x0c\x93\xae\xbe\x82\x00\x00',
                         "Decrypted data incorrectly",
                         )
        self.assertEqual(
                         decrypt.decrypt('\xff\x08\xe4\x10g\x15&9\xc6lN\xf8\xe9\xd2\x1e\x8a\x08\x16\xba\x1f\x91\xb6\xb9\xaa\xd8`#\x13$V\xe5\xbb'),
                         '\xf4\x04\xb5\xaea7:*\xcap\x99\x03\x83\x81\x8b72\xc1E\xb5\xe9X<\xcc\x05\x0c\x93\xae\xbe\x82\x00\x00',
                         "Decrypted data incorrectly",
                         )
