'''
Manage RSA encryption via pycrypto

The keydata consists of the following:

    pub: PEM encoded public key
    priv: PEM encoded private key
'''

SEC_BACKEND = 'pycrypto_aes'

# Import pycrypto libs
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
import Crypto.Util.number

# Import table libs
import table


class Key(object):
    '''
    The management interface for rsa keys
    '''
    def __init__(self, keydata=None, **kwargs):
        self.kwargs = kwargs
        self.__generate(keydata)

    def __generate(self, keydata):
        '''
        Generate the pycrypto rsa object
        '''
        if keydata:
            if 'components' not in keydata:
                raise ValueError('Invalid keydata, no components')
            key = RSA.construct(keydata['components'])
            if key.has_private():
                self.priv = key
                self.pub = key.publickey()
                self.sign_key = PKCS1_PSS.new(self.priv)
                self.verify_key = PKCS1_PSS.new(self.pub)
                self.decrypter = PKCS1_OAEP.new(self.priv)
            else:
                self.pub = key
                self.verify_key = PKCS1_PSS.new(self.pub)
            self.keydata = keydata
        else:
            self.priv = self._gen_key()
            self.pub = self.priv.publickey()
            self.sign_key = PKCS1_PSS.new(self.priv)
            self.verify_key = PKCS1_PSS.new(self.pub)
            self.keydata = self._gen_keydata(self.priv)
            self.decrypter = PKCS1_OAEP.new(self.priv)
        self.encrypter = PKCS1_OAEP.new(self.pub)
        self.max_msg_size = self.get_max_msg_size()
        self.enc_chunk_size = self.get_enc_chunk_size()

    def _gen_keydata(self, key):
        '''
        Return the keydata of a given key
        '''
        keydata = {'components': []}
        for attr in key.keydata:
            keydata['components'].append(getattr(key, attr))
        keydata['ctime'] = table.now()
        return keydata

    def _gen_key(self):
        '''
        Generate an RSA key, ensure that it is no smaller than 2048 bits
        '''
        size = self.kwargs.get('size', 2048)
        if size < 2048:
            raise ValueError('Key size too small')
        return RSA.generate(size)

    def _string_chunks(self, msg, size, i=None):
        '''
        Yield the message in the sized chunks
        '''
        if i is None:
            i = 0
        msg_len = len(msg)
        while i < msg_len:
            top = i + size
            if top > msg_len:
                top = msg_len
            yield msg[i:top]
            i = top

    def get_max_msg_size(self):
        '''
        Return the max size of a message chunk
        '''
        return (Crypto.Util.number.size(self.pub.n) / 8) -2 - (SHA.digest_size * 2)

    def get_enc_chunk_size(self):
        '''
        Return the size of all encrypted chunks
        '''
        return Crypto.Util.number.size(self.pub.n) / 8

    def encrypt(self, pub, msg):
        '''
        Sign and encrypt a message
        '''
        ret = ''
        hash_ = SHA.new()
        hash_.update(msg)
        ret += self.sign_key.sign(hash_)
        for chunk in self._string_chunks(msg, pub._key.max_msg_size):
            ret += pub._key.encrypter.encrypt(chunk)
        return ret

    def decrypt(self, pub, msg):
        '''
        Decrypt the given message against the given public key
        '''
        c_size = pub._key.get_enc_chunk_size()
        sig = msg[0:c_size]
        clear = ''
        for chunk in self._string_chunks(msg, c_size, c_size):
            clear += self.decrypter.decrypt(chunk)
        return pub._key.verify(sig + clear)

    def sign(self, msg):
        '''
        Sign a message
        '''
        hash_ = SHA.new()
        hash_.update(msg)
        sig = self.sign_key.sign(hash_)
        return sig + msg

    def verify(self, msg):
        '''
        Verify a message
        '''
        sig = msg[0:self.enc_chunk_size]
        msg = msg[self.enc_chunk_size:]
        hash_ = SHA.new()
        hash_.update(msg)
        if self.verify_key.verify(hash_, sig):
            return msg
        return False
