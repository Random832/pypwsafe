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
''' Tasks to handle interacting with a user's personal psafe
Created on Aug 16, 2011

@author: Paulson McIntyre <paul@gpmidi.net>
'''
#from celery.task import task #@UnresolvedImport
from celery.decorators import task #@UnresolvedImport
from psafefe.psafe.models import *
from psafefe.psafe.errors import *
from psafefe.psafe.tasks.load import loadSafe

from pypwsafe import PWSafe3

import stat



