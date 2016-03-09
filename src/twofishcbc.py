''' Use the pure-python twofish library to implement 
twofish in CBC mode. 
 
Created on Feb 18, 2013

@author: Paulson McIntyre <paul@gpmidi.net>
'''
import logging


def xor(s1, s2):
    assert len(s1) == len(s2)
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


class TwofishCBCEncryption(object):
    def __init__(self, key, iv):
        self.log = logging.getLogger("twofish.cbc.%s" % type(self).__name__)
        self.log.debug('initing')
        assert len(iv) == 16
        from twofish import Twofish
        self.key = key
        self.iv = iv
        self.tw = Twofish(self.key)

    def encrypt(self, blocks):
        assert len(blocks) % 16 == 0
        ret = ''
        while len(blocks) > 0:
            block = blocks[:16]
            blocks = blocks[16:]
            ret += self.encryptBlock(block)
        return ret

    def encryptBlock(self, block):
        assert len(block) == 16
        self.iv = self.tw.encrypt(xor(self.iv, block))
        return self.iv


class TwofishCBCDecryption(object):
    def __init__(self, key, iv):
        self.log = logging.getLogger("twofish.cbc.%s" % type(self).__name__)
        self.log.debug('initing')
        assert len(iv) == 16
        from twofish import Twofish
        self.key = key
        self.iv = iv
        self.tw = Twofish(self.key)

    def decrypt(self, blocks):
        assert len(blocks) % 16 == 0, "Expected cipher text length to be a multiple of 16. Got %r. " % len(blocks)
        ret = ''
        while len(blocks) > 0:
            block = blocks[:16]
            blocks = blocks[16:]
            ret += self.decryptBlock(block)
        return ret

    def decryptBlock(self, block):
        assert len(block) == 16
        intr = self.tw.decrypt(block)
        oldIV = self.iv
        self.iv = block
        return xor(oldIV, intr)
