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
''' Test the version fields
Created on Jan 19, 2013

@author: Paulson McIntyre (GpMidi) <paul@gpmidi.net>
@license: GPLv2
@version: 0.1
'''
import unittest
import os, os.path, sys

from TestSafeTests import TestSafeTestBase, STANDARD_TEST_SAFE_PASSWORD


class UnicodeTest_DBLevel(TestSafeTestBase):
    # Should be overridden with a test safe file name. The path should be relative to the test_safes directory.
    # All test safes must have the standard password (see above) 
    testSafe = 'UnicodeTest.psafe3'
    # Automatically open safes
    autoOpenSafe = False
    # How to open the safe
    autoOpenMode = "RO"

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


class UnicodeTest_RecordLevel(TestSafeTestBase):
    # Should be overridden with a test safe file name. The path should be relative to the test_safes directory.
    # All test safes must have the standard password (see above) 
    testSafe = 'UnicodeTest.psafe3'
    # Automatically open safes
    autoOpenSafe = True
    # How to open the safe
    autoOpenMode = "RW"
    
    def test_unicode_fields(self):
        for record in self.testSafeO.records:
            if record.getGroup() == 'Test Password':
                self.assertTrue(record.getPassword(), "Didn't get a valid password where one should be present")
            elif record.getGroup() == 'Test Title':
                self.assertTrue(record.getTitle(), "Didn't get a valid title where one should be present")
            elif record.getGroup() == 'Test User':
                self.assertTrue(record.getUser(), "Didn't get a valid username where one should be present")
            elif record.getTitle() == 'Test Group':
                self.assertTrue(record.getGroup(), "Didn't get a valid group where one should be present")
    
    def test_unicode_write_db(self):
        self.testSafeO.setDbName(u'Test Name \xe2')
        self.testSafeO.save()
        self.testSafeO.close()
        from pypwsafe import PWSafe3
        self.testSafeO = PWSafe3(
                                 filename = self.ourTestSafe,
                                 password = STANDARD_TEST_SAFE_PASSWORD,
                                 mode = self.autoOpenMode,
                                 )
        self.assertTrue('Test Name' in self.testSafeO.getDbName(), "DB Name didn't start with correct text")
        self.assertTrue(u'Test Name \xe2' == self.testSafeO.getDbName(), "DB Name didn't match")
    
    def test_many_chars_db(self):
        chrs = []
        for i in xrange(350, 1024):
            chrs.append(unichr(i))
        chrs = u''.join(chrs)
        self.testSafeO.setDbDesc(chrs)
        self.testSafeO.save()
        self.testSafeO.close()
        del self.testSafeO
        from pypwsafe import PWSafe3
        self.testSafeO = PWSafe3(
                                 filename = self.ourTestSafe,
                                 password = STANDARD_TEST_SAFE_PASSWORD,
                                 mode = self.autoOpenMode,
                                 )
        self.assertTrue(self.testSafeO.getDbDesc() == chrs, "Expected DB Desc to match after save")
    
    def test_unicode_entry_write(self):
        chrs = []
        for i in xrange(350, 1024):
            chrs.append(unichr(i))
        chrs = u''.join(chrs)
        
        from pypwsafe import Record
        from uuid import uuid4
        self.testSafeO[0] = Record()
        self.testSafeO[0].setGroup(chrs)
        self.testSafeO[0].setTitle(chrs)
        self.testSafeO[0].setUsername(chrs)
        self.testSafeO[0].setPassword(chrs)
        self.testSafeO[0].setUUID(uuid4())
        self.testSafeO[0].setNote(chrs)
        self.testSafeO[0].setURL(chrs)
        self.testSafeO[0].setEmail(chrs)
        
        self.testSafeO.save()
        self.testSafeO.close()
        del self.testSafeO
        from pypwsafe import PWSafe3
        self.testSafeO = PWSafe3(
                                 filename = self.ourTestSafe,
                                 password = STANDARD_TEST_SAFE_PASSWORD,
                                 mode = self.autoOpenMode,
                                 )
        
        self.assertEquals(self.testSafeO[0].getGroup(), chrs, "Group should match post-save")
        self.assertEquals(self.testSafeO[0].getTitle(), chrs, "Title should match post-save")
        self.assertEquals(self.testSafeO[0].getUsername(), chrs, "Username should match post-save")
        self.assertEquals(self.testSafeO[0].getPassword(), chrs, "Password should match post-save")
        self.assertTrue(self.testSafeO[0].getUUID(), "Should have an entry UUID")
        self.assertEquals(self.testSafeO[0].getNote(), chrs, "Note should match post-save")
        self.assertEquals(self.testSafeO[0].getURL(), chrs, "URL should match post-save")
        self.assertEquals(self.testSafeO[0].getEmail(), chrs, "Email should match post-save")
        
        
        
