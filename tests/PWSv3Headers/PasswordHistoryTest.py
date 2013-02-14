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
''' Test the password history for entries
Created on Jan 19, 2013

@author: Paulson McIntyre (GpMidi) <paul@gpmidi.net>
@license: GPLv2
@version: 0.1
'''
import unittest
import os, os.path, sys

from TestSafeTests import TestSafeTestBase, STANDARD_TEST_SAFE_PASSWORD


class PasswordHistoryTest_DBLevel(TestSafeTestBase):
    # Should be overridden with a test safe file name. The path should be relative to the test_safes directory.
    # All test safes must have the standard password (see above) 
    testSafe = 'PasswordHistory.psafe3'
    # Automatically open safes
    autoOpenSafe = False
    # How to open the safe
    autoOpenMode = "RW"

    def _openSafe(self):
        from pypwsafe import PWSafe3
        self.testSafeO = PWSafe3(
                                 filename = self.ourTestSafe,
                                 password = STANDARD_TEST_SAFE_PASSWORD,
                                 mode = self.autoOpenMode,
                                 )

    def test_open(self):
        self.testSafeO = None
        self._openSafe()
        self.assertTrue(self.testSafeO, "Failed to open the test safe")

    def test_save(self):
        self.testSafeO = None
        self._openSafe()
        self.testSafeO.save()
        

class PasswordHistoryTest_RecordLevel(TestSafeTestBase):
    # Should be overridden with a test safe file name. The path should be relative to the test_safes directory.
    # All test safes must have the standard password (see above) 
    testSafe = 'PasswordHistory.psafe3'
    # Automatically open safes
    autoOpenSafe = True
    # How to open the safe
    autoOpenMode = "RW"
    
    
    def test_history(self):
        for record in self.testSafeO.records:
            if record.getTitle() == "Test One":
                self.assertEqual(len(record.getHistory()), 2, "Test One entry should have two history entries")
                for hist in record.getHistory():
                    self.assertTrue('password' in hist, "Should have a password key")
                    self.assertTrue('saved' in hist, "Should have a saved key")


    def test_update_history(self):
        oldpw = '0q34utoaaiwerg'
        for record in self.testSafeO.records:
            if record.getTitle() == "Test One":
                import datetime
                record.appendHistory(oldpw, datetime.datetime.now())
        
        self.testSafeO.save()
        self.testSafeO.close()
        from pypwsafe import PWSafe3
        
        self.testSafe1 = PWSafe3(
                                 filename = self.ourTestSafe,
                                 password = STANDARD_TEST_SAFE_PASSWORD,
                                 mode = self.autoOpenMode,
                                 )
        found = False
        for record in self.testSafeO.records:
            if record.getTitle() == "Test One":
                found = False
                for hist in record.getHistory():
                    if hist['password'] == oldpw:
                        found = True
        self.assertTrue(found, "Didn't find the old password in the psafe")
        
        
    def test_update_password(self):
        newpw = '094wtjagfoj'
        oldpw = None
        for record in self.testSafeO.records:
            if record.getTitle() == "Test One":
                oldpw = record.getPassword()
                record.setPassword(newpw, updatePWModified = True, updateEntryModified = True, addToHistory = True)
        self.assertTrue(oldpw, "Should have found a 'Test One' record to modify")
        
        self.testSafeO.save()
        self.testSafeO.close()
        from pypwsafe import PWSafe3
        self.testSafe1 = PWSafe3(
                                 filename = self.ourTestSafe,
                                 password = STANDARD_TEST_SAFE_PASSWORD,
                                 mode = self.autoOpenMode,
                                 )
        for record in self.testSafeO.records:
            if record.getTitle() == "Test One":
                self.assertEqual(record.getPassword(), newpw, "The new password wasn't saved")
                found = False
                for hist in record.getHistory():
                    if hist['password'] == oldpw:
                        found = True
        self.assertTrue(found, "Didn't find the old password in the psafe")

