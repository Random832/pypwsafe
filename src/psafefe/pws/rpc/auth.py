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
''' XML-RPC Authentication helpers. The rpc4django module can do auth its self
but to do so means that all users must have cookie aware transport for their XML-RPC
client. This way is more of a pain (and manual) but ensures that any XML-RPC client
will work. 

@author: Paulson McIntyre <paul@gpmidi.net>
'''
from django.contrib.auth import authenticate
from psafefe.psafe.rpc.errors import *

def _auth(username, password):
    user = authenticate(username = username, password = password)
    if user is None:
        raise BadUsernamePasswordError, "Incorrect username and/or password"
    if user.is_active:
        return user
    raise InactiveUserError, "User %r is not active" % username

def auth(function):
    """ Wrap an RPC function and force credentials to be in the args """
    def newfunc(username, password, *args, **kw):
        kw['user'] = _auth(username, password)
        return function(username, password, *args, **kw)
    # Save docstring
    newfunc.__doc__ = getattr(function, '__doc__', '')
    return newfunc
        
    

