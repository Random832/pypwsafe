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
        self.iv = os.urandom(self.TEST_KEY_LEN)
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
        crypt = TwofishCBCEncryption(key = self.key)
        for length in self.DATA_LEN_TESTS:
            out = crypt.encrypt(data = self.data[:length])
            self.assertEqual(len(out) % 16, 0, "Output length must be a multiple of 16 (the block size)")




