// Copyright (c) 2018 The Bitcoin Post-Quantum developers

#include <botan/auto_rng.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include "xmss_privatekey.h"

#define BPQCRYPTO_EXPORT

#include "../include/bpqcrypto.hpp"
#include <vector>

namespace bpqcrypto {

    char const * get_version() noexcept
    {
        return BPQCRYPTO_VERSION;
    }


	static const size_t  XMSS_DER_SIGNATURE_OID = 0x0102;
	static const std::string XMSS_DEFAULT_ALGORITHM = "XMSS_SHAKE128_W16_H10";

	static const XMSS_Parameters::xmss_algorithm_t XMSS_256_H10_INT = XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE128_W16_H10;
    static const XMSS_Parameters::xmss_algorithm_t XMSS_256_H16_INT = XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE128_W16_H16;
    static const XMSS_Parameters::xmss_algorithm_t XMSS_256_H20_INT = XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE128_W16_H20;

    static KeyType convert_keytype(BPQ_KEYTYPE keytype)
    {
        switch (keytype)
        {
            case BPQ_KEYTYPE_XMSS_256_H10:
                return KeyType::XMSS_256_H10;

            case BPQ_KEYTYPE_XMSS_256_H16:
                return KeyType::XMSS_256_H16;

            case BPQ_KEYTYPE_XMSS_256_H20:
                return KeyType::XMSS_256_H20;

            default:
                throw std::invalid_argument(__func__);
        }
    }

    template <typename T>
	static T extract_uint(uint8_t const * data, size_t size)
	{
		if (size < sizeof(T))
			throw std::underflow_error(__func__);

		T value = 0;
		for (size_t i = 0; i < sizeof(T); i++)
		{
			value = ((value << 8) | data[i]);
		}

		return value;
	}

	static inline XMSS_Parameters xmss_params_from_keytype(KeyType keytype)
	{
		switch (keytype)
		{
			case KeyType::XMSS_256_H10:
				return XMSS_Parameters(XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE128_W16_H10);

			case KeyType::XMSS_256_H16:
				return XMSS_Parameters(XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE128_W16_H16);

            case KeyType::XMSS_256_H20:
                return XMSS_Parameters(XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE128_W16_H20);

            default:
                throw std::invalid_argument(__func__);
		}

	}

	static inline size_t get_pubkey_size(XMSS_Parameters const & params) noexcept
	{
		return 1 + sizeof(uint32_t) + 2 * params.element_size();
	}

	static inline size_t get_short_key_size(XMSS_Parameters const & params) noexcept
	{
		return get_pubkey_size(params) + sizeof(uint64_t) +	2 * params.element_size();
	}

	static inline size_t get_key_size(XMSS_Parameters const & params) noexcept
	{
		return get_short_key_size(params) + XMSS_HashTree::size(params);
	}

	static inline size_t get_signature_size(XMSS_Parameters const & params) noexcept
	{
		return 8 + params.element_size() * (1 + params.len() + params.tree_height());
	}

    static XMSS_Parameters xmss_get_key_params(uint8_t const *data, size_t size)
    {
        if (size < 5 || data[0] != BPQ_XMSS_PREFIX)
            throw Botan::Integrity_Failure("Invalid XMSS public key OID detected.");

        uint32_t raw_id = extract_uint<uint32_t>(data+1, size-1);
        return static_cast<XMSS_Parameters::xmss_algorithm_t>(raw_id);
    }

    static size_t get_index_from_key(uint8_t const *pKey, size_t nKeySize)
    {
        auto params = xmss_get_key_params(pKey, nKeySize);

        if (get_key_size(params) == nKeySize || get_short_key_size(params) == nKeySize)
        {
            size_t pub_size = get_pubkey_size(params);
            uint64_t index = extract_uint<uint64_t>(pKey + pub_size, nKeySize - pub_size);
            return index;
        }

        return 0;
    }


    static std::vector<uint8_t> xmss_der_encode_signature(
            size_t leaf_index, uint8_t const * sig, size_t sig_size)
    {
        auto der_sig = Botan::DER_Encoder()
                .start_cons(Botan::ASN1_Tag::SEQUENCE)
                .encode(XMSS_DER_SIGNATURE_OID)
                .encode((size_t)leaf_index)
                .raw_bytes(sig, sig_size)
                .end_cons()
                .get_contents_unlocked();

        return der_sig;
    }

    static bool xmss_decode_der_signature(
            uint8_t const * der_sig, size_t der_sig_size,
            size_t & leaf_index, std::vector<uint8_t> & sig, bool fVerifySize = true) noexcept
    {
        try
        {
            Botan::BER_Decoder decoder(der_sig, der_sig_size);

            decoder
                    .start_cons(Botan::ASN1_Tag::SEQUENCE)
                    .decode_and_check(XMSS_DER_SIGNATURE_OID, "not a XMSS signature")
                    .decode(leaf_index)
                    .raw_bytes(sig)
                    .end_cons();

            if (fVerifySize)
                decoder.verify_end();

            return true;
        }
        catch (std::exception&)
        {
            return false;
        }
    }

    static size_t get_der_signature_size(XMSS_Parameters const & params)
    {
        std::vector<uint8_t> sig(get_signature_size(params));
        auto der_sig = xmss_der_encode_signature(0, sig.data(), sig.size());
        return der_sig.size()+4;
    }

    BPQCRYPTO_PUBLIC size_t xmss_get_short_key_size(Botan::secure_vector<uint8_t> const & key)
    {
        auto params = xmss_get_key_params(key.data(), key.size());
        size_t pub_size = get_pubkey_size(params);
        return pub_size + sizeof(uint64_t) + 2 * params.element_size();
    }

	static Botan::secure_vector<uint8_t> xmss_generate(XMSS_Parameters const & params)
	{
		Botan::AutoSeeded_RNG rng;
		XMSS_PrivateKey sk(params.oid(), rng);

		if (sk.size() >= sk.size_long())
		{
			return sk.raw_private_key();
		}
		else
		{
			return sk.raw_private_key_long();
		}
	}

    static Botan::secure_vector<uint8_t> xmss_generate(XMSS_Parameters const & params,
                                                       secure_vector<uint8_t> const & sk_seed,
                                                       secure_vector<uint8_t> const & prf_seed,
                                                       secure_vector<uint8_t> const & pub_seed)
    {
        size_t idx_leaf = 0;
        XMSS_PrivateKey sk(params.oid(), idx_leaf, sk_seed, prf_seed, pub_seed);

        if (sk.size() >= sk.size_long())
        {
            return sk.raw_private_key();
        }
        else
        {
            return sk.raw_private_key_long();
        }
    }

	BPQCRYPTO_PUBLIC Botan::secure_vector<uint8_t> xmss_generate(KeyType keytype)
	{
		auto params = xmss_params_from_keytype(keytype);
		return xmss_generate(params);
	}

    BPQCRYPTO_PUBLIC secure_vector<uint8_t> xmss_generate(KeyType keytype,
                                    secure_vector<uint8_t> const & sk_seed,
                                    secure_vector<uint8_t> const & prf_seed,
                                    secure_vector<uint8_t> const & pub_seed)
    {
        auto params = xmss_params_from_keytype(keytype);
        return xmss_generate(params, sk_seed, prf_seed, pub_seed);
    }

    BPQCRYPTO_PUBLIC bool xmss_generate(BPQ_KEYTYPE keytype, uint8_t *pKey, size_t * pKeySize) noexcept
    {
        if (!pKeySize)
            return false;

        size_t key_buf_size = *pKeySize;

        try
        {
            auto params = bpqcrypto::xmss_params_from_keytype(convert_keytype(keytype));

            size_t key_size = bpqcrypto::get_key_size(params);

            *pKeySize = key_size;

            if ( key_buf_size < key_size )
                return false;

            if (!pKey)
                return false;

            auto key = bpqcrypto::xmss_generate(params);

            *pKeySize = key.size();

            if ( key_buf_size < key.size() )
                return false;

            memcpy(pKey, key.data(), key.size());

            return true;
        }
        catch (...)
        {
            if (pKeySize)
                *pKeySize = 0;
            return false;
        }
    }

    BPQCRYPTO_PUBLIC bool xmss_generate_from_seed(BPQ_KEYTYPE keytype,
                                                             uint8_t const * sk_seed,
                                                             uint8_t const * prf_seed,
                                                             uint8_t const * pub_seed,
                                                             uint8_t *pKey, size_t * pKeySize) noexcept
    {
        if (!pKeySize)
            return false;

        size_t key_buf_size = *pKeySize;

        try
        {
            auto params = bpqcrypto::xmss_params_from_keytype(convert_keytype(keytype));

            size_t key_size = bpqcrypto::get_key_size(params);

            *pKeySize = key_size;

            if ( key_buf_size < key_size )
                return false;

            if (!pKey || !sk_seed || !prf_seed || !pub_seed)
                return false;

            auto key = bpqcrypto::xmss_generate(params,
                secure_vector<uint8_t>(sk_seed, sk_seed + params.element_size()),
                secure_vector<uint8_t>(prf_seed, prf_seed + params.element_size()),
                secure_vector<uint8_t>(pub_seed, pub_seed + params.element_size())
            );

            *pKeySize = key.size();

            if ( key_buf_size < key.size() )
                return false;

            memcpy(pKey, key.data(), key.size());

            return true;
        }
        catch (...)
        {
            if (pKeySize)
                *pKeySize = 0;
            return false;
        }
    }

    BPQCRYPTO_PUBLIC bool is_xmss_key(uint8_t const *pKey, size_t nKeySize) noexcept
    {
        if (!pKey || nKeySize < 5)
            return false;

        try
        {
            auto params = bpqcrypto::xmss_get_key_params(pKey, nKeySize);

            return nKeySize == bpqcrypto::get_key_size(params); // || nKeySize == bpqcrypto::get_short_key_size(params);
        }
        catch (...)
        {
            return false;
        }
    }

    BPQCRYPTO_PUBLIC bool is_xmss_short_key(uint8_t const *pKey, size_t nKeySize) noexcept
    {
        if (!pKey || nKeySize < 5)
            return false;

        try
        {
            auto params = bpqcrypto::xmss_get_key_params(pKey, nKeySize);

            size_t key_size = bpqcrypto::get_short_key_size(params);

            return key_size == nKeySize;
        }
        catch (...)
        {
            return false;
        }
    }

    BPQCRYPTO_PUBLIC bool is_xmss_signature(uint8_t const *pSig, size_t nSigSize, bool bStrict) noexcept
    {
        if (!pSig || nSigSize < 2)
            return false;

        try
        {
            size_t leaf_index;
            std::vector<uint8_t> sig;
            return xmss_decode_der_signature(pSig, nSigSize, leaf_index, sig, bStrict);
        }
        catch (...)
        {
            return false;
        }
    }

    BPQCRYPTO_PUBLIC bool is_xmss_pubkey(uint8_t const *pKey, size_t nKeySize) noexcept
    {
        if (!pKey || nKeySize < 5)
            return false;

        try
        {
            auto params = bpqcrypto::xmss_get_key_params(pKey, nKeySize);

            size_t pub_size = bpqcrypto::get_pubkey_size(params);

            return pub_size == nKeySize;
        }
        catch (...)
        {
            return false;
        }
    }

    BPQCRYPTO_PUBLIC size_t xmss_get_key_size(uint8_t const *pKey, size_t nKeySize) noexcept
    {
        if (!pKey || nKeySize < 5)
            return 0;

        try
        {
            return get_key_size(xmss_get_key_params(pKey, nKeySize));
        }
        catch (...)
        {
            return 0;
        }
    }

    BPQCRYPTO_PUBLIC size_t xmss_get_short_key_size(uint8_t const *pKey, size_t nKeySize) noexcept
    {
        if (!pKey || nKeySize < 5)
            return 0;

        try
        {
            return get_short_key_size(xmss_get_key_params(pKey, nKeySize));
        }
        catch (...)
        {
            return 0;
        }
    }

    BPQCRYPTO_PUBLIC size_t xmss_get_pubkey_size(uint8_t const *pKey, size_t nKeySize) noexcept
    {
        if (!pKey || nKeySize < 5)
            return 0;

        try
        {
            return get_pubkey_size(xmss_get_key_params(pKey, nKeySize));
        }
        catch (...)
        {
            return 0;
        }
    }

    BPQCRYPTO_PUBLIC Botan::secure_vector<uint8_t> xmss_get_long_key(secure_vector<uint8_t> const & key)
    {
        XMSS_PrivateKey sk(key);
        return sk.raw_private_key_long();
    }

    BPQCRYPTO_PUBLIC bool xmss_get_long_key(uint8_t const *pKey, size_t nKeySize, uint8_t *pKey2, size_t nKeySize2) noexcept
    {
        if (!pKey || nKeySize < 5 || !pKey2)
            return false;

        try
        {
            auto key2 = xmss_get_long_key(secure_vector<uint8_t>(pKey, pKey + nKeySize));
            if (key2.size() != nKeySize2)
                return false;

            memcpy(pKey2, key2.data(), key2.size());
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    BPQCRYPTO_PUBLIC bool xmss_get_short_key(uint8_t const *pKey, size_t nKeySize, uint8_t *pKey2, size_t nKeySize2) noexcept
    {
        if (!pKey || nKeySize < 5 || !pKey2)
            return false;

        try
        {
            auto key2 = xmss_get_short_key(secure_vector<uint8_t>(pKey, pKey + nKeySize));
            if (key2.size() != nKeySize2)
                return false;

            memcpy(pKey2, key2.data(), key2.size());
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    BPQCRYPTO_PUBLIC secure_vector<uint8_t> xmss_get_short_key(secure_vector<uint8_t> const & key)
    {
        size_t size = get_short_key_size(xmss_get_key_params(key.data(), key.size()));
        return secure_vector<uint8_t>(key.data(), key.data() + size);
    }

    BPQCRYPTO_PUBLIC size_t xmss_get_signature_size(uint8_t const *pKey, size_t nKeySize) noexcept
    {
        if (!pKey || nKeySize < 5)
            return 0;

        try
        {
            auto params = xmss_get_key_params(pKey, nKeySize);

            return get_der_signature_size(params);
        }
        catch (...)
        {
            return 0;
        }
    }

    BPQCRYPTO_PUBLIC std::vector<uint8_t> xmss_get_pubkey(uint8_t const * key, size_t key_size)
    {
        auto params = xmss_get_key_params(key, key_size);
        size_t pub_size = get_pubkey_size(params);
        return std::vector<uint8_t>(key, key + pub_size);
    }

    BPQCRYPTO_PUBLIC bool xmss_get_pubkey(uint8_t const *pKey, size_t nKeySize, uint8_t *pPubKey, size_t nPubKeySize) noexcept
    {
        if (!pKey || nKeySize < 5 || !pPubKey)
            return false;

        try
        {
            auto params = xmss_get_key_params(pKey, nKeySize);
            size_t pub_size = get_pubkey_size(params);
            if (pub_size != nPubKeySize)
                return false;

            memcpy(pPubKey, pKey, pub_size);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

	BPQCRYPTO_PUBLIC bool xmss_sign(
		uint8_t const * msg, size_t msg_size,
		uint8_t const * key, size_t key_size,
        size_t * pLeafIndex,
        uint8_t * pSign, size_t * pSignSize) noexcept
	{
	    if (!pSign || !pLeafIndex || !pSignSize)
	        return false;

        size_t sig_buf_size = *pSignSize;

        try
        {
            XMSS_PrivateKey sk(secure_vector<uint8_t>(key, key+key_size));
            sk.set_unused_leaf_index(*pLeafIndex);

            Botan::AutoSeeded_RNG rng;

            size_t sig_subkey = sk.unused_leaf_index();

            auto sig = sk.sign(rng, msg, msg_size);

            *pLeafIndex = sk.unused_leaf_index();

            auto der_sig = xmss_der_encode_signature(sig_subkey, sig.data(), sig.size());

            *pSignSize = der_sig.size();

            if (sig_buf_size < der_sig.size())
                return false;

            memcpy(pSign, der_sig.data(), der_sig.size());
            return true;
        }
        catch(...)
        {
            *pSignSize = 0;
            return false;
        }
	}

    BPQCRYPTO_PUBLIC std::vector<uint8_t> xmss_sign(
            uint8_t const * msg, size_t msg_size,
            Botan::secure_vector<uint8_t> const & key,
            size_t & leaf_index)
    {
        XMSS_PrivateKey sk(key);

        sk.set_unused_leaf_index(leaf_index);

        Botan::AutoSeeded_RNG rng;

        size_t sig_subkey = sk.unused_leaf_index();

        auto && sig = sk.sign(rng, msg, msg_size);

        leaf_index = sk.unused_leaf_index();

        return xmss_der_encode_signature(sig_subkey, sig.data(), sig.size());
    }

    BPQCRYPTO_PUBLIC bool xmss_verify(
            uint8_t const * msg, size_t msg_size,
            uint8_t const * der_sig, size_t der_sig_size,
            uint8_t const * pubkey, size_t pubkey_size) noexcept
    {
        if (!msg || !der_sig || !pubkey)
            return false;

        try
        {
            XMSS_PublicKey pk(std::vector<uint8_t>(pubkey, pubkey + pubkey_size));

            size_t leaf_index;
            std::vector<uint8_t> sig;

            if (!xmss_decode_der_signature(der_sig, der_sig_size, leaf_index, sig, false /* verify size */))
                return false;

            return pk.verify(secure_vector<uint8_t>(msg, msg + msg_size), secure_vector<uint8_t>(sig.begin(), sig.end()));
        }
        catch (...)
        {
            return false;
        }
    }

	BPQCRYPTO_PUBLIC bool xmss_verify(
		uint8_t const * msg, size_t msg_size,
		std::vector<uint8_t> const & der_sig,
        std::vector<uint8_t> const & pubkey)
	{
		try
		{
			XMSS_PublicKey pk(pubkey);

			size_t leaf_index;
			std::vector<uint8_t> sig;

			if (!xmss_decode_der_signature(der_sig.data(), der_sig.size(), leaf_index, sig, false /* verify size */))
				return false;

			return pk.verify(secure_vector<uint8_t>(msg, msg + msg_size), secure_vector<uint8_t>(sig.begin(), sig.end()));
		}
		catch (std::exception&)
		{
			return false;
		}
	}

    BPQCRYPTO_PUBLIC KeyInfo get_key_info(uint8_t const * key, size_t key_size) noexcept
    {
        if (!key || key_size < 5)
            return {};

        try
        {
            KeyInfo info = {};

            auto params = xmss_get_key_params(key, key_size);

            if (params.oid() == XMSS_256_H10_INT)
                info.keytype = KeyType::XMSS_256_H10;
            else
            if (params.oid() == XMSS_256_H16_INT)
                info.keytype = KeyType::XMSS_256_H16;
            else
            if (params.oid() == XMSS_256_H20_INT)
                info.keytype = KeyType::XMSS_256_H20;
            else
                info.keytype = KeyType::UNDEFINED;

            info.is_xmss= true;
            info.hash_size = params.element_size();
            info.tree_height = params.tree_height();

            info.key_size = get_key_size(params);
            info.pubkey_size = get_pubkey_size(params);
            info.sig_size = get_signature_size(params);

            info.key_index = get_index_from_key(key, key_size);

            return info;
        }
        catch (std::exception&)
        {
            return {};
        }
    }

    BPQCRYPTO_PUBLIC void get_key_info(uint8_t const * key, size_t key_size, KeyInfo * result) noexcept
    {
        if (result)
            *result = get_key_info(key, key_size);
    }

    BPQCRYPTO_PUBLIC SigInfo get_sig_info(uint8_t const * der_sig, size_t der_sig_size) noexcept
    {
        if (!der_sig || der_sig_size < 5)
            return {};

        try
        {
            SigInfo info = {};

            size_t leaf_index;
            std::vector<uint8_t> sig;

            if (!xmss_decode_der_signature(der_sig, der_sig_size, leaf_index, sig, false /* verify size */))
            {
                info.is_xmss = false;
                return info;
            }

            info.is_xmss = true;
            info.sig_size = sig.size();
            info.key_index = leaf_index;

            return info;
        }
        catch (std::exception&)
        {
            return {};
        }
    }

    BPQCRYPTO_PUBLIC void get_sig_info(uint8_t const * sig, size_t sig_size, SigInfo * result) noexcept
    {
        if (result)
            *result = get_sig_info(sig, sig_size);
    }

    BPQCRYPTO_PUBLIC std::vector<uint8_t> xmss_create_dummy_signature(KeyType keytype)
    {
        auto params = xmss_params_from_keytype(keytype);

        size_t leaf_index = 0;

        std::vector<uint8_t> sig( get_signature_size(params), uint8_t(0) );

        return xmss_der_encode_signature(leaf_index, sig.data(), sig.size() );
    }

    BPQCRYPTO_PUBLIC bool is_ecdsa_key(uint8_t const * pKey, size_t nKeySize) noexcept
    {
        if (!pKey || nKeySize < 32)
            return false;

        if (nKeySize == 32)
            return true;

        if (nKeySize > 33)
            return false;

        return pKey[32] == 0 || pKey[32] == 1;
    }

} // namespace bpqcrypto


