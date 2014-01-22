'''
Bring the cryptography to the table. This package aims to make a single very
high level cryptographic interface which abstracts many underlying algorithms.

The keys all contain a "keydata" dict, the following keydata keys MUST be in
the underlying keydata dict from the backend:

    ctime: Timestamp
'''

# Import python libs
import os
import json
import datetime

# Try to import serialization libs
try:
    import msgpack
    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False


def now():
    '''
    Return now as a date list
    '''
    return date_to_list(datetime.datetime.now())


def list_to_date(date):
    '''
    Convert a list to a datetime
    '''
    return datetime.datetime(*date)


def date_to_list(date):
    '''
    Convert a datetime object into a list
    '''
    return [date.year,
            date.month,
            date.day,
            date.hour,
            date.minute,
            date.second]


def _gather_backend(backend, sec_backend):
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
        self.public, self.secret = _gather_backend(backend, sec_backend)
        self.__key = self.__generate(keyfile, keyfile_secret)
        self.keydata = self.__key.keydata

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
            fp_.write(self.serial.dumps(self.__key.keydata))
        os.umask(current)

    def encrypt(self, pub, msg):
        '''
        Pass in the remote target's public key object, and the data to
        encrypt, an encrypted string will be returned
        '''
        return self.__key.encrypt(pub, msg)

    def decrypt(self, pub, msg):
        '''
        Pass in the remote reciever's public key object and the data to
        decrypt, an encrypted string will be returned
        '''
        return self.__key.decrypt(pub, msg)

    def sign(self, msg):
        '''
        Return a signature for the given data
        '''
        return self.__key.sign(msg)

    def verify(self, verify_key, signed):
        '''
        Given a remote verification key, verify that the signed message is
        valid
        '''
        return self.__key.verify(verify_key, signed)


class Secret(object):
    '''
    Returns a secret object, used to encrypt and decrypt secret messages
    '''
    # TODO: Make a generator to encrypt messages in chains so we can load blocks
    # into memory
    def __init__(self, backend='pynacl', key=None):
        self.public, self.secret = _gather_backend(backend)
        self.__key = self.secret.Key(key)

    def encrypt(self, msg):
        '''
        Encrypt the data using the given key
        '''
        return self.__key.encrypt(msg)

    def decrypt(self, msg):
        '''
        Decrypt the data using the given key
        '''
        return self.__key.decrypt(msg)
