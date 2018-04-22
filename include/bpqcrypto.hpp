// Copyright (c) 2018 The Bitcoin Post-Quantum developers

#pragma once

#include <cstdint>
#include <vector>
#include <botan/secmem.h>

#include "bpqcrypto.h"

#include <array>

namespace bpqcrypto {

    using Botan::secure_vector;

    enum class KeyType
    {
        UNDEFINED = 0,

        ECDSA_COMPRESSED = 2,
        ECDSA_UNCOMPRESSED = 4,
        XMSS_256_H10 = 110,
        XMSS_256_H16 = 116,
        XMSS_256_H20 = 120,
    };

    inline bool is_xmss_key(secure_vector<uint8_t> const & key) noexcept
    {
        return is_xmss_key(key.data(), key.size());
    }

    inline bool is_xmss_short_key(secure_vector<uint8_t> const & key) noexcept
    {
        return is_xmss_short_key(key.data(), key.size());
    }

    inline bool is_xmss_pubkey(std::vector<uint8_t> const & key) noexcept
    {
        return is_xmss_pubkey(key.data(), key.size());
    }

    inline bool is_xmss_signature(std::vector<uint8_t> const & sig, bool bStrict) noexcept
    {
        return is_xmss_signature(sig.data(), sig.size(), bStrict);
    }

    BPQCRYPTO_PUBLIC secure_vector<uint8_t> xmss_generate(KeyType keytype = KeyType::XMSS_256_H10);
    BPQCRYPTO_PUBLIC secure_vector<uint8_t> xmss_generate(KeyType keytype,
                                                          secure_vector<uint8_t> const & sk_seed,
                                                          secure_vector<uint8_t> const & prf_seed,
                                                          secure_vector<uint8_t> const & pub_seed);

	BPQCRYPTO_PUBLIC size_t xmss_get_short_key_size(secure_vector<uint8_t> const & key);

    BPQCRYPTO_PUBLIC secure_vector<uint8_t> xmss_get_long_key(secure_vector<uint8_t> const & key);

    inline secure_vector<uint8_t> xmss_get_long_key(uint8_t const * key, size_t key_size)
    {
        return xmss_get_long_key(secure_vector<uint8_t>(key, key + key_size));
    }

    BPQCRYPTO_PUBLIC secure_vector<uint8_t> xmss_get_short_key(secure_vector<uint8_t> const & key);

    BPQCRYPTO_PUBLIC std::vector<uint8_t> xmss_get_pubkey(uint8_t const * key, size_t key_size);

    inline std::vector<uint8_t> xmss_get_pubkey(secure_vector<uint8_t> const & key)
    {
        return xmss_get_pubkey(key.data(), key.size());
    }

	BPQCRYPTO_PUBLIC std::vector<uint8_t> xmss_sign(
			uint8_t const * msg, size_t msg_size,
            secure_vector<uint8_t> const & key,
			size_t & leaf_index);

	inline std::vector<uint8_t> xmss_sign(
			uint8_t const * msg, size_t msg_size,
			uint8_t const * key, size_t key_size,
			size_t & leaf_index)
	{
		return xmss_sign(msg, msg_size, secure_vector<uint8_t>(key, key+key_size), leaf_index);
	}

    BPQCRYPTO_PUBLIC bool xmss_verify(
		uint8_t const * msg, size_t msg_size,
		std::vector<uint8_t> const & der_sig,
        std::vector<uint8_t> const & pubkey);


    //
    // ECDSA keys
    //

    inline bool is_ecdsa_key(secure_vector<uint8_t> const & key) noexcept
    {
        return is_ecdsa_key(key.data(), key.size());
    }

    //
    //
    //

	struct KeyInfo
    {
        KeyType keytype;
        bool is_xmss;
        size_t hash_size;
        size_t tree_height;
        size_t key_size;
        size_t pubkey_size;
        size_t sig_size;
        size_t key_index;
    };

    BPQCRYPTO_PUBLIC KeyInfo get_key_info(uint8_t const * key, size_t key_size) noexcept;
    extern "C" BPQCRYPTO_PUBLIC void get_key_info(uint8_t const * key, size_t key_size, KeyInfo * result) noexcept;

    struct SigInfo
    {
        bool is_xmss;
        size_t sig_size;
        size_t key_index;
    };

    BPQCRYPTO_PUBLIC SigInfo get_sig_info(uint8_t const * sig, size_t sig_size) noexcept;
    extern "C" BPQCRYPTO_PUBLIC void get_sig_info(uint8_t const * sig, size_t sig_size, SigInfo * result) noexcept;

    BPQCRYPTO_PUBLIC std::vector<uint8_t> xmss_create_dummy_signature(KeyType keytype);

    //
    // HASH 256
    //

    BPQCRYPTO_PUBLIC secure_vector<uint8_t> hash_sha256(uint8_t const * data, size_t size);

    inline secure_vector<uint8_t> hash_sha256(std::vector<uint8_t> const & msg)
    {
        return hash_sha256(msg.data(), msg.size());
    }

    BPQCRYPTO_PUBLIC secure_vector<uint8_t> hash_shake128(uint8_t const *msg, size_t msg_size, size_t output_bits);

    inline secure_vector<uint8_t> hash256_shake128(uint8_t const *msg, size_t msg_size)
    {
        return hash_shake128(msg, msg_size, 256);
    }

    inline secure_vector<uint8_t> hash_shake128(std::vector<uint8_t> const & msg, size_t output_bits)
    {
        return hash_shake128(msg.data(), msg.size(), output_bits);
    }

    inline secure_vector<uint8_t> hash256_shake128(std::vector<uint8_t> const & msg)
    {
        return hash_shake128(msg.data(), msg.size(), 256);
    }

} // namespace bpqcrypto
