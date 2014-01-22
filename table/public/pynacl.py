'''
Manage encryption with the pynacl bindings to libsodium

The keydata consists of the following:

    priv: <HEX private keys>
    pub: <HEX public key>
    sign: <HEX signing key>
    verify: <HEX verify key>
'''

# Import table libs
import table

# Import Cyptographic libs
import nacl.public
import nacl.signing
import nacl.encoding


class Key(object):
    '''
    Used to manage high level nacl operations
    '''
    def __init__(self, keydata=None, **kwargs):
        self.kwargs = kwargs
        self.__generate(keydata)

    def __generate(self, keydata):
        '''
        Build the key objects, if the keydata is present load the objects from
        said keys, otherwise generate a full set of keys
        '''
        if keydata:
            if 'priv' in keydata:
                self.priv = nacl.public.PrivateKey(
                        keydata['priv'],
                        nacl.encoding.HexEncoder)
                self.pub = self.priv.public_key
            elif 'pub' in keydata:
                self.pub = nacl.public.PublicKey(
                        keydata['pub'],
                        nacl.encoding.HexEncoder)
            else:
                self.priv = nacl.public.PrivateKey.generate()
                self.pub = self.priv.public_key
            if 'sign' in keydata:
                self.sign = nacl.signing.SigningKey(
                        keydata['sign'],
                        nacl.encoding.HexEncoder)
                self.verify = self.sign.verify_key
            elif 'verify' in keydata:
                self.verify = nacl.signing.VerifyKey(
                        keydata['verify'],
                        nacl.encoding.HexEncoder)
            self.keydata = keydata
        else:
            self.keydata = {}
            self.priv = nacl.public.PrivateKey.generate()
            self.keydata['priv'] = self.priv.encode(nacl.encoding.HexEncoder)
            self.pub = self.priv.public_key
            self.keydata['pub'] = self.pub.encode(nacl.encoding.HexEncoder)
            self.sign = nacl.signing.SigningKey.generate()
            self.keydata['sign'] = self.sign.encode(nacl.encoding.HexEncoder)
            self.verify = self.sign.verify_key
            self.keydata['verify'] = self.verify.encode(nacl.encoding.HexEncoder)
            self.keydata['ctime'] = table.now()

    def encrypt(self, pub, msg):
        '''
        Encrypt the message intended for the owner of the passed in pubic key
        '''
        box = nacl.public.Box(self.priv, pub._key.pub)
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        return box.encrypt(msg, nonce)

    def decrypt(self, pub, msg):
        '''
        Decrypt a message from the given pub intended for this private key
        '''
        box = nacl.public.Box(self.priv, pub._key.pub)
        return box.decrypt(msg)

    def sign(self, msg):
        '''
        Sign the message
        '''
        return self.sign.sign(msg)

    def verify(self, vkey, msg):
        '''
        Verify the message
        '''
        vkey = nacl.signing.VerifyKey(vkey, encoder=nacl.encoding.HexEncoder)
        try:
            vkey.verify(msg)
        except nacl.signing.BadSignatureError:
            return False
        return True
