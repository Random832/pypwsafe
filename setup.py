#!/usr/bin/python
''' Install pypwsafe
Created on Jul 23, 2011

@author: paulson mcintyre <paul@gpmidi.net>
'''
from distutils.core import setup, Extension
import sys
VERSION = "0.1"

# Generate docs
import os
sys.path.append('src')

def wlk(drs):
	ret=[]
	for dr in drs:
		for (dirpath, dirnames, filenames) in os.walk(dr):
			print repr(dirpath)
			ret.append(('share/psafefe/'+dirpath,map(lambda fil: "%s/%s"%(dirpath,fil),filenames)))
	return ret

setup(name = "python-pypwsafe",
      version = VERSION,
      description = "Python interface to Password Safe files",
      author = "Paulson McIntyre",
      author_email = "paul@gpmidi.net",
      license = "GPL",
      long_description = \
"""
Python interface to Password Safe files. 
""",
      url = 'https://github.com/ronys/pypwsafe',
      packages = [
                'pypwsafe',
		'psafefe',
		'psafefe.pws',
		'psafefe.pws.rpc',
		'psafefe.pws.tasks',
                  ],
      package_dir = {
                   '':'src',
                     },
      scripts = [
                 "pwsafecli/pwsafecli.py",
                 "psafedump",
                 ],
      data_files = wlk([
			'media',
			'templates',
			'static',
			])
      )
