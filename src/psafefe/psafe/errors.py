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
'''
Created on Aug 17, 2011

@author: gpmidi
'''

class PasswordSafeDoesntExist(IndexError):
    """ The requested psafe object doesn't exist in the DB """
    
    
class NoAccessToPasswordSafe(IOError):
    """ Can't read the requested psafe file """
    
class DuplicateUUIDError(ValueError):
    """ Duplicate UUID found in entries """

class NoPasswordForPasswordSafe(ValueError):
    """ The user's personal safe doesn't have the password for
    the requested password safe """
    
class CantLocateHelperFiles(ValueError):
    """ Can't find the directory that holds the test psafe files, static,
    media, and other needed files for testing. 
    """
class EntryNotCached(KeyError):
    """ Can't find a cached entry for the requested PasswordSafe """
    
