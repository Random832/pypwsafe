''' Use the pure-python twofish library to implement 
twofish in CBC mode. 
 
Created on Feb 18, 2013

@author: Paulson McIntyre <paul@gpmidi.net>
'''
import logging

class TwofishCBCEncryption(object):
    def __init__(self,key,iv):
        self.log = logging.getLogger("twofish.cbc.%s"%type(self).__name__)
        self.log.debug('initing')
        from twofish import Twofish
        self.key=key
        self.iv=iv
        self.tw = Twofish(self.key)
    
    def encrypt(self,block):
        self.iv=self.tw.encrypt(self.iv ^ block)
        return self.iv

class TwofishCBCDecryption(object):
    def __init__(self,key,iv):
        self.log = logging.getLogger("twofish.cbc.%s"%type(self).__name__)
        self.log.debug('initing')
        from twofish import Twofish
        self.key=key
        self.iv=iv
        self.tw = Twofish(self.key)
    
    def decrypt(self,block):
        plain=self.tw.decrypt(block)
        iv=self.iv
        self.iv=plain
        return iv ^ plain
