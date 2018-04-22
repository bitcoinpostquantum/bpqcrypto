# Copyright (c) 2018 The Bitcoin Post-Quantum developers

import unittest
import random
from . import *
from . import _version


class Test_1(unittest.TestCase):

    def test_version(self):
        self.assertTrue(isinstance(_version, str) and len(_version) > 0)
        print("version: bpqcrypto", _version)

    def test_main(self):
          
        key1 = BPQKey(BPQKey.XMSS_256_H10)
        key2 = BPQKey(BPQKey.XMSS_256_H10)

        xkey1 = key1.to_bytes()
        xkey2 = key2.to_bytes()

        self.assertTrue(len(xkey1) > 0)
        self.assertTrue(len(xkey2) > 0)

        self.assertTrue(is_xmss_key(xkey1))
        self.assertTrue(is_xmss_key(xkey2))

        msg1 = b'message 1'
        msg2 = b'message 2'

        sign11 = key1.sign(msg1)
        sign12 = key1.sign(msg2)
        
        sign21 = key2.sign(msg1)
        sign22 = key2.sign(msg2)
        
        self.assertTrue(is_xmss_signature(sign11))
        self.assertTrue(is_xmss_signature(sign12))
        self.assertTrue(is_xmss_signature(sign21))
        self.assertTrue(is_xmss_signature(sign22))

        pkey1 = key1.public_key()
        pkey2 = key2.public_key()

        xpkey1 = pkey1.to_bytes()
        xpkey2 = pkey2.to_bytes()

        self.assertTrue(is_xmss_pubkey(xpkey1))
        self.assertTrue(is_xmss_pubkey(xpkey2))

        self.assertTrue(pkey1.verify(msg1, sign11))
        self.assertTrue(pkey1.verify(msg2, sign12))
        self.assertFalse(pkey1.verify(msg1, sign12))
        self.assertFalse(pkey1.verify(msg2, sign11))
        self.assertFalse(pkey1.verify(msg1, sign21))
        self.assertFalse(pkey1.verify(msg2, sign22))

        self.assertTrue(pkey2.verify(msg1, sign21))
        self.assertTrue(pkey2.verify(msg2, sign22))
        self.assertFalse(pkey2.verify(msg1, sign22))
        self.assertFalse(pkey2.verify(msg2, sign21))
        self.assertFalse(pkey2.verify(msg1, sign11))
        self.assertFalse(pkey2.verify(msg2, sign12))

    def test_gen_from_seed(self):

        key_type = BPQKey.XMSS_256_H10

        sk_seed = bytes([random.randint(0, 255) for i in range(32)])
        prf_seed = bytes([random.randint(0, 255) for i in range(32)])
        pub_seed = bytes([random.randint(0, 255) for i in range(32)])

        print("sk_seed:  ", sk_seed.hex())
        print("prf_seed: ", prf_seed.hex())
        print("pub_seed: ", pub_seed.hex())

        key = BPQKey(key_type, seed=(sk_seed, prf_seed, pub_seed))

        xkey = key.to_short_bytes()

        self.assertTrue(len(xkey) > 0)

        msg1 = b'message 1'
        msg2 = b'message 2'

        sign1 = key.sign(msg1)
        sign2 = key.sign(msg2)

        self.assertTrue(is_xmss_signature(sign1))
        self.assertTrue(is_xmss_signature(sign2))

        pkey = key.public_key()

        xpkey = pkey.to_bytes()
        self.assertTrue(is_xmss_pubkey(xpkey))

        self.assertTrue(pkey.verify(msg1, sign1))
        self.assertTrue(pkey.verify(msg2, sign2))
        self.assertFalse(pkey.verify(msg1, sign2))
        self.assertFalse(pkey.verify(msg2, sign1))

        key2 = BPQKey(key_type, seed=(sk_seed, prf_seed, pub_seed))
        xkey2 = key2.to_short_bytes()
        xpkey2 = key2.public_key().to_bytes()

        print("pubkey1: ", xpkey.hex())
        print("pubkey2: ", xpkey2.hex())

        print("key1: ", xkey.hex())
        print("key2: ", xkey2.hex())

        self.assertEqual(xpkey, xpkey2)
        self.assertEqual(xkey, xkey2)


    def test_import(self):
          
        xkey1 = bytes.fromhex(
            '1001000001'
            '7E9AC3780FD65FEE94E9FCC572644F49D00E047D136570BF3BC85D57D7E05E99'
            '6F225C419237D42DC30B1D887F42E806CFFE8324D09332A6DAAC8D736B7438FC'
            '0000000000000000'
            '8523A051B3F19C114F2483FFA322B6271415D7F3AC21960425357E7AC92C3040'
            '71F8EDE182C95E56789DC19C68B1F79E394E4158C54A8C14620DA91488875541')

        self.assertTrue(is_xmss_short_key(xkey1))

        key1 = BPQKey(xkey1)

        self.assertTrue(is_xmss_key(key1.to_bytes()))
        self.assertEqual(key1.to_short_bytes(), xkey1);

        msg3 = b'message 3'

        index = key1.key_index

        sign13 = key1.sign(msg3)

        self.assertTrue(index < key1.key_index)

        pub1 = key1.public_key()
        xpub1 = pub1.to_bytes()

        self.assertTrue(is_xmss_pubkey(xpub1))

        self.assertTrue(pub1.verify(msg3, sign13))


    def test_subkey(self):

        key = BPQKey(BPQKey.XMSS_256_H10)

        msg = b'message 3'
        sig = key.sign(msg)
        sig_subkey = get_sig_info(sig)['subkey']
        self.assertEqual(sig_subkey+1, key.get_subkey())

        sig = key.sign(msg)
        sig_subkey = get_sig_info(sig)['subkey']
        self.assertEqual(sig_subkey+1, key.get_subkey())


    def test_hash256_sha2(self):

        msg1 = b""
        out1 = Hash256_SHA2(msg1)
        self.assertEqual(out1, bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

        msg1 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        out1 = Hash256_SHA2(msg1)
        self.assertEqual(out1, bytes.fromhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"))

    def test_hash_shake128(self):

        msg1 = b""
        out1 = Hash_SHAKE128(msg1, 512)
        self.assertEqual(len(out1), 512//8)
        self.assertEqual(out1, bytes.fromhex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"))

        msg1 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        out1 = Hash_SHAKE128(msg1, 512)
        self.assertEqual(len(out1), 512//8)
        self.assertEqual(out1, bytes.fromhex("1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f54ee5f19550825a6e070030519e944263ac1c6765287065621f9fcb3201723e32"))

    def test_hash256_shake128(self):

        msg1 = b""
        self.assertEqual(Hash256_SHAKE128(msg1), bytes.fromhex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"))

        msg1 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        self.assertEqual(Hash256_SHAKE128(msg1), bytes.fromhex("1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f5"))

    def test_get_key_info(self):

        key1 = BPQKey(BPQKey.XMSS_256_H10).to_short_bytes()
        self.assertTrue(is_xmss_short_key(key1))

        keyinfo = get_key_info(key1)

        self.assertTrue(keyinfo['is_xmss'])
        self.assertEqual(keyinfo['key_type'], KeyType.XMSS_256_H10)

    def test_aes(self):

        from . import aes

        key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
        iv = bytes(os.urandom(16))

        m = b"Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's."

        enc = aes.Encryptor.newCBC(key, iv)

        e = enc.encrypt(m)

        dec = aes.Decryptor.newCBC(key, iv)

        m2 = dec.decrypt(e)

        self.assertEqual(m, m2)

    def test_aes256(self):

        from . import aes

        key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C2B7E151628AED2A6ABF7158809CF4F3C")
        iv = bytes(os.urandom(16))

        m = b"Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's."

        enc = aes.Encryptor.newCBC(key, iv)

        e = enc.encrypt(m)

        dec = aes.Decryptor.newCBC(key, iv)

        m2 = dec.decrypt(e)

        self.assertEqual(m, m2)


if __name__ == "__main__":

    print("version: bpqcrypto", _version)

    unittest.main(failfast=True)
    #unittest.main(argv=["", "Test_1.test_main"], failfast=True)
    #unittest.main(argv=["", "Test_1.test_gen_from_seed"], failfast=True)
    #unittest.main(argv=["", "Test_1.test_import"], failfast=True)
    #unittest.main(argv=["", "Test_1.test_hash256_sha2"], failfast=True)
    #unittest.main(argv=["", "Test_1.test_hash256_shake128"], failfast=True)
    #unittest.main(argv=["", "Test_1.test_hash_shake128"], failfast=True)
    #unittest.main(argv=["", "Test_1.test_get_key_info"], failfast=True)
    #unittest.main(argv=["", "Test_1.test_subkey"], failfast=True)
    #unittest.main(argv=["", "Test_1.test_aes"], failfast=True)
