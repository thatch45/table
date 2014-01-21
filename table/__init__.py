'''
Bring the cryptography to the table. This package aims to make a single very
high level cryptographic interface which abstracts many underlying algorithms.

The keys all contain "keydata", a few keydata, this keydata includes a few
standard fields and can be expanded:

    ctime: Timestamp
'''

# Import python libs
import os
import json

# Try to import serialization libs
try:
    import msgpack
    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False

def gather_backend(backend, sec_backend):
    '''
    Return the table object which abstracts the backend's functionality
    '''
    if sec_backend is None:
        sec_backend = backend
    pubname = 'table.public.{0}'.format(backend)
    pubmod = __import__(pubname)
    secname = 'table.secret.{0}'.format(sec_backend)
    secmod = __import__(secname)
    return (getattr(pubmod.public, backend),
            getattr(secmod.secret, backend))


class Serial(object):
    '''
    Serialization normalizing class
    '''
    def __init__(self, serial):
        self.serial = serial

    def loads(self, data):
        '''
        Load the serialized data from the string passed in
        '''
        return {'msgpack': self.loads_msgpack,
                'json': self.loads_json}[self.serial](data)

    def dumps(self, data):
        '''
        Dump a data structure
        '''
        return {'msgpack': self.dumps_msgpack,
                'json': self.dumps_json}[self.serial](data)
        
    def loads_msgpack(self, data):
        '''
        Load msgpack serialized string
        '''
        return msgpack.loads(data)

    def loads_json(self, data):
        '''
        Load JSON string
        '''
        return json.loads(data)

    def dumps_msgpack(self, data):
        '''
        Dump msgpack serialized string
        '''
        return msgpack.dumps(data)

    def dumps_json(self, data):
        '''
        Dump JSON string
        '''
        return json.dumps(data)


class Public(object):
    '''
    Returns a public key interface
    '''
    def __init__(
            self,
            backend='pynacl',
            keyfile=None,
            keyfile_secret=None,
            serial='json',
            sec_backend=None,
            **kwargs):
        self.serial = Serial(serial)
        self.kwargs = kwargs
        self.public, self.secret = gather_backend(backend, sec_backend)
        self.key = self.__generate(keyfile, keyfile_secret)

    def __generate(self, keyfile, keyfile_secret):
        '''
        Return the key from the keyfile, or generate a new key
        '''
        if keyfile:
            if os.path.isfile(keyfile):
                # Keyfiles are small, read it all in
                with open(keyfile, 'r') as fp_:
                    keydata = fp_.read()
                if keyfile_secret:
                    keydata = self.secret.decrypt(keydata, keyfile_secret)
                keydata = self.serial.loads(keydata)
            else:
                raise ValueError('Keyfile {0} Not Found'.format(keyfile))
            return self.public.Key(keydata)
        return self.public.Key(None, **self.kwargs)

    def save(self, path):
        '''
        Save the serialized keydata to the given path
        '''
        current = os.umask(191)
        with open(path, 'w+') as fp_:
            fp_.write(self.serial.dumps(self.key.keydata))
        os.umask(current)

    def encrypt(self, pub, data):
        '''
        Pass in the remote target's public key object, and the data to
        encrypt, an encrypted string will be returned
        '''
        return self.key.encrypt(pub, data)

    def decrypt(self, pub, data):
        '''
        Pass in the remote reciever's public key object and the data to
        decrypt, an encrypted string will be returned
        '''
        return self.key.decrypt(pub, data)

    def sign(self, msg):
        '''
        Return a signature for the given data
        '''
        return self.key.sign(msg)

    def verify(self, verify_key, signed):
        return self.key.veriify(verify_key, signed)


class Secret(object):
    '''
    Returns a secret object, used to encrypt and decrypt secret messages
    '''
    # TODO: Make a generator to encrypt messages in chains so we can load blocks
    # into memory
    def __init__(self, backend='pynacl'):
        self.public, self.secret = gather_backend(backend)

    def generate_key(self, size=None):
        '''
        Return n symetric key
        '''
        return self.secret.generate(size)

    def encrypt(self, key, data):
        '''
        Encrypt the data using the given key
        '''
        return self.secret.encrypt(key, data)

    def decrypt(self, key, data):
        '''
        Decrypt the data using the given key
        '''
        return self.secret.decrypt(key, data)
