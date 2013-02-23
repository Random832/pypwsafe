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


class TwofishPurePythonTests(unittest.TestCase):
    TEST_DATA_LENS=[
                    32,
                    512,
                    8192,
                    ]
    TEST_KEY_LEN=32
    
    def setUp(self):
        self.testData = [os.urandom(x) for x in self.TEST_DATA_LENS]
        self.key = os.urandom(self.TEST_KEY_LEN)
        self.iv = os.urandom(16)
    
    def test_tests(self):
        """ Make sure the test vars are set right """
        self.assertTrue(self.TEST_KEY_LEN%16==0, "The test key length must be a multiple of 16")
        self.assertTrue(len(self.TEST_DATA_LENS)>0,"Expected at least one data length to test")
        for l in self.TEST_DATA_LENS:
            self.assertTrue(l%16==0,"Expected test data len %d to be a multiple of 16"%l)
    
    def test_ecb(self):
        from twofish import Twofish
        tw=Twofish(self.key)
        for testData in self.testData:
            self.assertTrue(len(testData)%16==0,"Test data length needs to be evenly divisible by 16. Got %r"%len(testData))
            # Can take multiple blocks
            cipherText = tw.encrypt(testData)
            self.assertNotEqual(cipherText,testData,"Plain and cipher text should not be the same")
            decrypted = tw.decrypt(cipherText)
            self.assertEqual(decrypted, testData, "The encrypted and then decrypted text should match the original text")
    
    def test_cbc(self):
        from twofishcbc import TwofishCBCEncryption,TwofishCBCDecryption
        for testData in self.testData:
            enc=TwofishCBCEncryption(self.key,self.iv)
            cipherText = enc.encrypt(testData)
            self.assertNotEqual(testData,cipherText,"Plain and cipher text should not be the same")
            dec=TwofishCBCDecryption(self.key,self.iv)
            decrypted = dec.decrypt(cipherText)
            self.assertEqual(decrypted, testData, "The encrypted and then decrypted text should match the original text. Got %r and %r. "%(decrypted, testData))
            
            
            
            
            
            
            
            
            
            
            
            
            
            