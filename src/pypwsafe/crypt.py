''' Abstract away the various crypto algorithms so that it's easy
to switch between different implementations/modules. 

Created on Feb 18, 2013

@author: Paulson McIntyre <paul@gpmidi.net>
'''
import logging


class SHA256(object):
    def __init__(self, data=None):
        self.log = logging.getLogger("psafe.lib.crypt.%s" % type(self).__name__)
        self.log.log(5, 'initing')

        try:
            from hashlib import sha256 as sha256_func
            self.hsh = sha256_func()
            self.mode = "Python 2.6"
        except Exception as e:
            self.log.warn("Failed to import FIXME libs with %r", e)
            try:
                from hashlib import sha256_func  # @UnresolvedImport @Reimport
                self.hsh = sha256_func()
                self.mode = "Python 2.5"  # FIXME: Validate
            except Exception as e:
                self.log.warn("Failed to import FIXME libs with %r", e)
                try:
                    from Crypto.Hash.SHA256 import new as sha256_func  # @UnresolvedImport @Reimport
                    self.hsh = sha256_func()
                    self.mode = "Python 2.4"  # FIXME: Validate
                except Exception as e:
                    self.log.warn("Failed to import FIXME libs with %r", e)
                    raise ImportError("Failed to find a valid SHA256 library")

        if data is not None:
            self.update(data)

    def update(self, data):
        return self.hsh.update(data)

    def digest(self):
        return self.hsh.digest()

    def hexdigest(self):
        return self.hsh.hexdigest()


class SHA256HMAC(object):
    def __init__(self, key, data):
        self.mode = None
        self.key = key
        self.data = data

        self.log = logging.getLogger("psafe.lib.crypt.%s" % type(self).__name__)
        self.log.debug('initing')

        self.python26()
        if not self.mode:
            self.python24()
        if not self.mode:
            self.pythonSomething()
        if not self.mode:
            raise ImportError("Failed to find a valid HMAC+SHA256 library")

    def digest(self):
        # All the same...for now....
        if self.mode == 'Python 2.6':
            return self.hmac.digest()
        elif self.mode == 'Python 2.4':
            return self.hmac.digest()
        elif self.mode == 'Python ???':
            return self.hmac.digest()

    def hexdigest(self):
        # All the same...for now....
        if self.mode == 'Python 2.6':
            return self.hmac.hexdigest()
        elif self.mode == 'Python 2.4':
            return self.hmac.hexdigest()
        elif self.mode == 'Python ???':
            return self.hmac.hexdigest()

    def pythonSomething(self):
        try:
            from Crypto.Hash.SHA256 import new as sha256_func  # @UnresolvedImport @Reimport
            from hmac import new as HMAC
            self.mode = "Python ???"
            self.hmac = HMAC(self.key, self.data, sha256_func)
        except Exception as e:
            self.log.warn("Failed to import vFIXME libs with %r", e)

    def python25(self):
        # FIXME: Validate that this is actually for Python 2.4 
        # Could be 2.5 - Not sure yet
        try:
            from hashlib import sha256_func  # @UnresolvedImport
            from hmac import new as HMAC
            self.mode = "Python 2.4"
            self.hmac = HMAC(self.key, self.data, sha256_func)
        except Exception as e:
            self.log.warn("Failed to import v2.4 libs with %r", e)

    def python26(self):
        try:
            from hmac import new as HMAC
            from hashlib import sha256 as sha256_func
            self.mode = "Python 2.6"
            self.hmac = HMAC(self.key, self.data, sha256_func)
            return True
        except Exception as e:
            self.log.warn("Failed to import v2.6 libs with %r", e)
            return False


class TwofishECBCEncryption(object):
    def __init__(self, key):
        self.log = logging.getLogger("psafe.lib.crypt.%s" % type(self).__name__)
        self.log.debug('initing')

        self.key = key

        try:
            from mcrypt import MCRYPT  # @UnresolvedImport
            self.twf = MCRYPT('twofish', 'ecb')
            self.twf.init(self.key)
            self.mode = 'Native (MCrypt)'
        except Exception as e:
            self.log.warn("Failed to import native Twofish implementation with %r" % e)
            self.log.debug("Falling back to pure-Python Twofish library")
            from twofish import Twofish
            self.mode = 'Pure-Python'
            self.twf = Twofish(self.key)

    def encrypt(self, data):
        m = len(data) % 16
        if m != 0:
            data += "\x00" * (16 - m)
        ret = b''
        while len(data) > 0:
            block = data[:16]
            data = data[16:]
            ret += self.encryptBlock(block=block)
        return ret

    def encryptBlock(self, block):
        """Encrypt exactly one block"""
        assert len(block) == 16
        return self.twf.encrypt(block)

    def __repr__(self):
        return "<%s %s>" % (type(self).__name__, self.mode)


class TwofishECBCDecryption(object):
    def __init__(self, key):
        self.log = logging.getLogger("psafe.lib.crypt.%s" % type(self).__name__)
        self.log.debug('initing')

        self.key = key

        try:
            from mcrypt import MCRYPT  # @UnresolvedImport
            self.twf = MCRYPT('twofish', 'ecb')
            self.twf.init(self.key)
            self.mode = 'Native (MCrypt)'
        except Exception as e:
            self.log.warn("Failed to import native Twofish implementation with %r" % e)
            self.log.debug("Falling back to pure-Python Twofish library")
            from twofish import Twofish
            self.mode = 'Pure-Python'
            self.twf = Twofish(self.key)

    def decrypt(self, block):
        return self.twf.decrypt(block)

    def __repr__(self):
        return "<%s %s>" % (type(self).__name__, self.mode)


class TwofishCBCEncryption(object):
    def __init__(self, key, iv):
        self.log = logging.getLogger("psafe.lib.crypt.%s" % type(self).__name__)
        self.log.debug('initing')

        self.key = key
        self.iv = iv

        try:
            from mcrypt import MCRYPT  # @UnresolvedImport
            self.twf = MCRYPT('twofish', 'cbc')
            self.twf.init(self.key, self.iv)
            self.mode = 'Native (MCrypt)'
        except Exception as e:
            self.log.warn("Failed to import native Twofish implementation with %r" % e)
            self.log.debug("Falling back to pure-Python Twofish library")
            from twofishcbc import TwofishCBCEncryption
            self.mode = 'Pure-Python'
            self.twf = TwofishCBCEncryption(self.key, self.iv)

    def encrypt(self, data):
        if not isinstance(data, bytes):
            raise TypeError("Expected a string, got %r" % type(data))
        m = len(data) % 16
        if m != 0:
            data += "\x00" * (16 - m)
        ret = b''
        while len(data) > 0:
            block = data[:16]
            data = data[16:]
            ret += self.encryptBlock(block=block)
        return ret

    def encryptBlock(self, block):
        """Encrypt exactly one block"""
        assert len(block) == 16
        return self.twf.encrypt(block)

    def __repr__(self):
        return "<%s %s>" % (type(self).__name__, self.mode)


class TwofishCBCDecryption(object):
    def __init__(self, key, iv):
        self.log = logging.getLogger("psafe.lib.crypt.%s" % type(self).__name__)
        self.log.debug('initing')

        self.key = key
        self.iv = iv

        try:
            from mcrypt import MCRYPT  # @UnresolvedImport
            self.twf = MCRYPT('twofish', 'cbc')
            self.twf.init(self.key, self.iv)
            self.mode = 'Native (MCrypt)'
        except Exception as e:
            self.log.warn("Failed to import native Twofish implementation with %r" % e)
            self.log.debug("Falling back to pure-Python Twofish library")
            from twofishcbc import TwofishCBCDecryption
            self.mode = 'Pure-Python'
            self.twf = TwofishCBCDecryption(self.key, self.iv)

    def decrypt(self, block):
        return self.twf.decrypt(block)

    def __repr__(self):
        return "<%s %s>" % (type(self).__name__, self.mode)
