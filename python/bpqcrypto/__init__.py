#!/usr/bin/env python3

#
# python wrapper for BPQ Crypto Library
# 
# Copyright (c) 2018 The Bitcoin Post-Quantum developers

import sys
import os
import ctypes


class KeyType(object):
    UNDEFINED = 0
    ECDSA_COMPRESSED = 2
    ECDSA_UNCOMPRESSED = 4
    XMSS_256_H10 = 110
    XMSS_256_H16 = 116
    XMSS_256_H20 = 120


#
# Module initialization
#
if sys.platform == 'darwin':
    _libname = 'libbpqcrypto.dylib'
elif sys.platform == 'win32':
    _libname = 'bpqcrypto.dll'
else:
    _libname = 'libbpqcrypto.so'

_bpqcryptodll = ctypes.CDLL(os.path.join(os.path.dirname(__file__), _libname))


_bpqcryptodll.get_version.restype = ctypes.c_char_p

_version = str(_bpqcryptodll.get_version(), "ascii")


def is_xmss_pubkey(x:bytes):

    if not isinstance(x, bytes):
        return False

    _x = ctypes.create_string_buffer(x)
    return _bpqcryptodll.is_xmss_pubkey(_x, ctypes.c_long(len(x))) != 0


def is_xmss_short_key(x:bytes):

    if not isinstance(x, bytes):
        return False

    _x = ctypes.create_string_buffer(x)
    return _bpqcryptodll.is_xmss_short_key(_x, ctypes.c_long(len(x))) != 0


def is_xmss_key(x:bytes):

    if not isinstance(x, bytes):
        return False

    _x = ctypes.create_string_buffer(x)
    return _bpqcryptodll.is_xmss_key(_x, ctypes.c_long(len(x))) != 0
    

def is_xmss_signature(x:bytes, strict:bool=True):
    """
    checks for valid der signature
    strict=False: allow extra bytes after signature data
    """

    if not isinstance(x, bytes):
        return False

    _x = ctypes.create_string_buffer(x)
    return _bpqcryptodll.is_xmss_signature(_x, ctypes.c_long(len(x)), ctypes.c_bool(strict)) != 0


def xmss_get_long_key(key:bytes):
    """
    @return full key with hashtree included
    """

    if not isinstance(key, bytes):
        raise TypeError()

    _key_size = ctypes.c_long(len(key))
    _key = ctypes.create_string_buffer(key)

    key2_size = _bpqcryptodll.xmss_get_key_size(_key, _key_size)
    if key2_size == _key_size.value:
        return key

    _key2 = ctypes.create_string_buffer(key2_size)
    if not _bpqcryptodll.xmss_get_long_key(_key, _key_size, _key2, ctypes.c_long(key2_size)):
        raise RuntimeError()

    return _key2.raw    


def xmss_get_short_key(key:bytes):
    """
    @return full key with hashtree included
    """

    if not isinstance(key, bytes):
        raise TypeError()

    _key_size = ctypes.c_long(len(key))
    _key = ctypes.create_string_buffer(key)

    key2_size = _bpqcryptodll.xmss_get_short_key_size(_key, _key_size)
    if key2_size == _key_size.value:
        return key

    _key2 = ctypes.create_string_buffer(key2_size)
    if not _bpqcryptodll.xmss_get_short_key(_key, _key_size, _key2, ctypes.c_long(key2_size)):
        raise RuntimeError()

    return _key2.raw    


def _xmss_generate(keytype):
    
    key_size = ctypes.c_ulong()
    _bpqcryptodll.xmss_generate(ctypes.c_int(keytype), None, ctypes.byref(key_size))

    if key_size.value == 0:
        raise NotImplementedError()

    key = ctypes.create_string_buffer(key_size.value)
    if not _bpqcryptodll.xmss_generate(ctypes.c_int(keytype), key, ctypes.byref(key_size)):
        raise RuntimeError()

    return key.raw


def _xmss_generate_from_seed(keytype, sk_seed, prf_seed, pub_seed):

    _sk_seed = ctypes.create_string_buffer(sk_seed)
    _prf_seed = ctypes.create_string_buffer(prf_seed)
    _pub_seed = ctypes.create_string_buffer(pub_seed)

    key_size = ctypes.c_ulong()
    _bpqcryptodll.xmss_generate_from_seed(ctypes.c_int(keytype),
                                          None, None, None,
                                          None, ctypes.byref(key_size))

    if key_size.value == 0:
        raise NotImplementedError()

    key = ctypes.create_string_buffer(key_size.value)
    if not _bpqcryptodll.xmss_generate_from_seed(ctypes.c_int(keytype),
                                                 _sk_seed, _prf_seed, _pub_seed,
                                                 key, ctypes.byref(key_size)):
        raise RuntimeError()

    return key.raw


def xmss_estimate_signature_size(key):

    if isinstance(key, str):
        key = bytes.fromhex(key)
    elif not isinstance(key, bytes):
        raise TypeError("key must be byte array or hex string")

    _key_size = ctypes.c_long(len(key))
    _key = ctypes.create_string_buffer(key)
    return _bpqcryptodll.xmss_get_signature_size(_key, _key_size)


def _xmss_sign(message:bytes, key:bytes, key_index:int):

    if not isinstance(message, bytes) or not isinstance(key, bytes) or not isinstance(key_index, int):
        raise TypeError()

    _key_size = ctypes.c_long(len(key))
    _key = ctypes.create_string_buffer(key)
    sign_size = _bpqcryptodll.xmss_get_signature_size(_key, _key_size)
    if sign_size == 0:
        raise RuntimeError()

    _msg_size = ctypes.c_long(len(message))
    _msg = ctypes.create_string_buffer(message)

    _key_index = ctypes.c_ulong(key_index)

    _sign = ctypes.create_string_buffer(sign_size)
    _sign_size = ctypes.c_long(sign_size)
    res = _bpqcryptodll.xmss_sign(_msg, _msg_size, _key, _key_size, ctypes.byref(_key_index), _sign, ctypes.byref(_sign_size))
    if res <= 0:
        raise RuntimeError("bpqcrypto.xmss_sign error: %d", res)

    return _sign.raw[:_sign_size.value], _key_index.value


def xmss_verify(msg:bytes, sig:bytes, pubkey:bytes):

    if not isinstance(msg, bytes) or not isinstance(sig, bytes) or not isinstance(pubkey, bytes):
        raise TypeError()

    _msg_size = ctypes.c_long(len(msg))
    _msg = ctypes.create_string_buffer(msg)

    _sig_size = ctypes.c_long(len(sig))
    _sig = ctypes.create_string_buffer(sig)

    _pub_size = ctypes.c_long(len(pubkey))
    _pub = ctypes.create_string_buffer(pubkey)

    return _bpqcryptodll.xmss_verify(_msg, _msg_size, _sig, _sig_size, _pub, _pub_size) != 0


def xmss_get_pubkey(key:bytes):

    if not isinstance(key, bytes):
        raise TypeError()

    _key_size = ctypes.c_long(len(key))
    _key = ctypes.create_string_buffer(key)
    pub_size = _bpqcryptodll.xmss_get_pubkey_size(_key, _key_size)
    if pub_size == 0:
        raise RuntimeError()

    _pub = ctypes.create_string_buffer(pub_size)
    _pub_size = ctypes.c_long(pub_size)
    if not _bpqcryptodll.xmss_get_pubkey(_key, _key_size, _pub, _pub_size):
        raise RuntimeError()

    return _pub.raw


def xmss_split_msgsig(msgsig: bytes):

    pubkey = xmss_get_pubkey(msgsig)
    if not pubkey:
        return None, msgsig

    return pubkey, msgsig[len(pubkey):]


def Hash256_SHA2(msg:bytes):

    if not isinstance(msg, bytes):
        raise TypeError()

    _msg_size = ctypes.c_long(len(msg))
    _msg = ctypes.create_string_buffer(msg)

    _hash = ctypes.create_string_buffer(32)
    if not _bpqcryptodll.hash_sha256(_msg, _msg_size, _hash):
        raise RuntimeError()

    return _hash.raw


def Hash256_SHAKE128(msg:bytes):
    if not isinstance(msg, bytes):
        raise TypeError()

    _msg_size = ctypes.c_long(len(msg))
    _msg = ctypes.create_string_buffer(msg)

    _hash = ctypes.create_string_buffer(32)
    if not _bpqcryptodll.hash256_shake128(_msg, _msg_size, _hash):
        raise RuntimeError()

    return _hash.raw


def Hash_SHAKE128(msg:bytes, output_bits):
    if not isinstance(msg, bytes):
        raise TypeError()

    _msg_size = ctypes.c_long(len(msg))
    _msg = ctypes.create_string_buffer(msg)

    _hash = ctypes.create_string_buffer(output_bits//8)
    if not _bpqcryptodll.hash_shake128(_msg, _msg_size, ctypes.c_long(output_bits), _hash):
        raise RuntimeError()

    return _hash.raw


class _KeyInfo(ctypes.Structure):
    _fields_ = [
        ('keytype', ctypes.c_int),
        ('is_xmss', ctypes.c_int),
        ('hash_size', ctypes.c_size_t),
        ('tree_height', ctypes.c_size_t),
        ('key_size', ctypes.c_size_t),
        ('pubkey_size', ctypes.c_size_t),
        ('sig_size', ctypes.c_size_t),
        ('key_index', ctypes.c_size_t),
    ]


def get_key_info(key):

    if isinstance(key, str):
        key = bytes.fromhex(key)
    elif not isinstance(key, bytes):
        raise TypeError("key must be byte array or hex string")

    _key_size = ctypes.c_long(len(key))
    _key = ctypes.create_string_buffer(key)
    _keyinfo = _KeyInfo()
    _bpqcryptodll.get_key_info(_key, _key_size, ctypes.pointer(_keyinfo))
    return {
        'key_type': _keyinfo.keytype,
        'is_xmss': _keyinfo.is_xmss,
        'hash_size': _keyinfo.hash_size,
        'tree_height': _keyinfo.tree_height,
        'pubkey_size': _keyinfo.pubkey_size,
        'key_size': _keyinfo.key_size,
        'sig_size': _keyinfo.sig_size,
        'key_index': _keyinfo.key_index,
    }


class _SigInfo(ctypes.Structure):
    _fields_ = [
        ('is_xmss', ctypes.c_int),
        ('sig_size', ctypes.c_size_t),
        ('key_index', ctypes.c_size_t),
    ]


def get_sig_info(sig):

    if isinstance(sig, str):
        sig = bytes.fromhex(sig)
    elif not isinstance(sig, bytes):
        raise TypeError("sig must be byte array or hex string")

    _sig_size = ctypes.c_long(len(sig))
    _sig = ctypes.create_string_buffer(sig)
    _siginfo = _SigInfo()
    _bpqcryptodll.get_sig_info(_sig, _sig_size, ctypes.pointer(_siginfo))
    return {
        'is_xmss': _siginfo.is_xmss,
        'sig_size': _siginfo.sig_size,
        'subkey': _siginfo.key_index
    }


class BPQPublicKey(object):

    def __init__(self, data:bytes):

        if not isinstance(data, bytes):
            raise TypeError()

        self.pub_data = data
        pass

    def to_bytes(self):
        return self.pub_data

    def verify(self, message, signature):
        return xmss_verify(message, signature, self.pub_data)


class BPQKey(object):
    
    # key types:
    ECDSA_COMPRESSED = 3 # not implemented
    XMSS_256_H10 = 110
    XMSS_256_H16 = 116
    XMSS_256_H20 = 120

    def __init__(self, arg, seed=None):
        """
        """

        self.key_index = 0
        
        if arg is None:
            # empty key
            self.key_data = None
            return

        if isinstance(arg, bytes):
            # from raw key data
            self.key_data = xmss_get_long_key(arg)
            return

        if arg == BPQKey.ECDSA_COMPRESSED: 
            # generate new key
            raise NotImplementedError()
        
        if seed is not None:
            if not isinstance(seed, tuple) or len(seed) != 3:
                raise TypeError("BPQKey: invalid seed")
            sk_seed, prf_seed, pub_seed = seed
            self.key_data = _xmss_generate_from_seed(arg, sk_seed, prf_seed, pub_seed)
            return

        if arg == BPQKey.XMSS_256_H10:
            self.key_data = _xmss_generate(arg)
            return

        if arg == BPQKey.XMSS_256_H16:
            self.key_data = _xmss_generate(arg)
            return

        raise Exception("BPQKey: invalid argument")

    def set_subkey(self, index):
        if not isinstance(index, int):
            raise TypeError()
        self.key_index = index

    def get_subkey(self):
        return self.key_index

    def sign(self, message: bytes):
        """
        @return  signature:bytes
        """
        sign, self.key_index = _xmss_sign(message, self.key_data, self.key_index)
        return sign

    def to_bytes(self):
        return self.key_data
   
    def to_short_bytes(self):
        return xmss_get_short_key(self.key_data)
   
    def public_key(self):
        return BPQPublicKey(xmss_get_pubkey(self.key_data))


