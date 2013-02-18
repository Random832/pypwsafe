''' Abstract away the various crypto algorithms so that it's easy
to switch between different implementations/modules. 

Created on Feb 18, 2013

@author: Paulson McIntyre <paul@gpmidi.net>
'''
import logging

class TwofishECBCEncryption(object):
    def __init__(self,key):
        self.log = logging.getLogger("twofish.ecb.%s"%type(self).__name__)
        self.log.debug('initing')
        
        self.key=key
        
        try:
            from mcrypt import MCRYPT  # @UnresolvedImport
            self.twf = MCRYPT('twofish', 'ecb')
            self.twf.init(self.key)
            self.mode='Native (MCrypt)'
        except Exception,e:
            self.log.warn("Failed to import native Twofish implementation with %r"%e)
            self.log.debug("Falling back to pure-Python Twofish library")
            from twofish import Twofish
            self.mode = 'Pure-Python'
            self.twf = Twofish(self.key)
    
    def encrypt(self,block):
        return self.twf.encrypt(block)
    
    def __repr__(self):
        return "<%s %s>"%(type(self).__name__,self.mode)


class TwofishECBCDecryption(object):
    def __init__(self,key):
        self.log = logging.getLogger("twofish.ecb.%s"%type(self).__name__)
        self.log.debug('initing')
        
        self.key=key
        
        try:
            from mcrypt import MCRYPT  # @UnresolvedImport
            self.twf = MCRYPT('twofish', 'ecb')
            self.twf.init(self.key)
            self.mode='Native (MCrypt)'
        except Exception,e:
            self.log.warn("Failed to import native Twofish implementation with %r"%e)
            self.log.debug("Falling back to pure-Python Twofish library")
            from twofish import Twofish
            self.mode = 'Pure-Python'
            self.twf = Twofish(self.key)
    
    def decrypt(self,block):
        return self.twf.decrypt(block)
    
    def __repr__(self):
        return "<%s %s>"%(type(self).__name__,self.mode)

class TwofishCBCEncryption(object):
    def __init__(self,key,iv):
        self.log = logging.getLogger("twofish.cbc.%s"%type(self).__name__)
        self.log.debug('initing')
        
        self.key=key
        self.iv=iv
        
        try:
            from mcrypt import MCRYPT  # @UnresolvedImport
            self.twf = MCRYPT('twofish', 'cbc')
            self.twf.init(self.key,self.iv)
            self.mode='Native (MCrypt)'
        except Exception,e:
            self.log.warn("Failed to import native Twofish implementation with %r"%e)
            self.log.debug("Falling back to pure-Python Twofish library")
            from twofishcbc import TwofishCBCEncryption
            self.mode = 'Pure-Python'
            self.twf = TwofishCBCEncryption(self.key,self.iv)
    
    def encrypt(self,block):
        return self.twf.encrypt(block)
    
    def __repr__(self):
        return "<%s %s>"%(type(self).__name__,self.mode)

class TwofishCBCDecryption(object):
    def __init__(self,key,iv):
        self.log = logging.getLogger("twofish.cbc.%s"%type(self).__name__)
        self.log.debug('initing')
        
        self.key=key
        self.iv=iv
        
        try:
            from mcrypt import MCRYPT  # @UnresolvedImport
            self.twf = MCRYPT('twofish', 'cbc')
            self.twf.init(self.key,self.iv)
            self.mode='Native (MCrypt)'
        except Exception,e:
            self.log.warn("Failed to import native Twofish implementation with %r"%e)
            self.log.debug("Falling back to pure-Python Twofish library")
            from twofishcbc import TwofishCBCEncryption
            self.mode = 'Pure-Python'
            self.twf = TwofishCBCEncryption(self.key,self.iv)
    
    def decrypt(self,block):
        return self.twf.decrypt(block)
    
    def __repr__(self):
        return "<%s %s>"%(type(self).__name__,self.mode)
    