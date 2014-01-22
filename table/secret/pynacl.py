'''
pynacl secret key encryption
'''

# Import cryptographic libs
import nacl.secret
import nacl.utils

def generate(size):
    '''
    Generate a random key
    '''
    if size is None or size < 24:
        size = nacl.secret.SecretBox.KEY_SIZE
    return nacl.utils.random(size)

def encrypt(key, msg):
    '''
    Using the given key, encrypt a message
    '''
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    box = nacl.secret.SecretBox(key)
    return box.encrypt(msg, nonce)


def decrypt(key, msg):
    '''
    Using the given key, decrypt a message
    '''
    box = nacl.secret.SecretBox(key)
    return box.decrypt(msg)
