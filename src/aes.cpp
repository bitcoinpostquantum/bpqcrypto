// Copyright (c) 2018 The Bitcoin Post-Quantum developers

#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/block_cipher.h>

#define BPQCRYPTO_EXPORT

#include "aes.h"

namespace bpqcrypto {


    void* aes_cipher_create(uint8_t const *pKey, uint8_t const * pIV, bool encrypt) noexcept
    {
        try
        {
            if (!pKey)
                return nullptr;

            std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7",
                encrypt ? Botan::ENCRYPTION : Botan::DECRYPTION);

            enc->set_key(pKey, 16);

            if (!pIV)
            {
                Botan::AutoSeeded_RNG rng;
                enc->start(rng.random_vec(enc->default_nonce_length()));            }
            else
            {
                enc->start(pIV, 16);
            }

            return enc.release();
        }
        catch (std::exception const &)
        {
            return nullptr;
        }
    }

    void* aes256_cipher_create(uint8_t const *pKey, uint8_t const * pIV, bool encrypt) noexcept
    {
        try
        {
            if (!pKey)
                return nullptr;

            std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7",
                                                                                 encrypt ? Botan::ENCRYPTION : Botan::DECRYPTION);

            enc->set_key(pKey, 32);

            if (!pIV)
            {
                Botan::AutoSeeded_RNG rng;
                enc->start(rng.random_vec(enc->default_nonce_length()));            }
            else
            {
                enc->start(pIV, 16);
            }

            return enc.release();
        }
        catch (std::exception const &)
        {
            return nullptr;
        }
    }

    void aes_cipher_free(void * cipher) noexcept
    {
        auto * _cipher = static_cast<Botan::Cipher_Mode*>(cipher);
        delete _cipher;
    }

    bool aes_encrypt(void * cipher,
        uint8_t const *pData, size_t nSize, uint8_t *pOutData, size_t * nOutSize) noexcept
    {
        if (!cipher || !pData || !nOutSize)
            return false;

        try
        {
            auto * _cipher = static_cast<Botan::Cipher_Mode*>(cipher);

            size_t out_size = _cipher->output_length(nSize);

            if (!pOutData)
            {
                *nOutSize = out_size;
                return true;
            }

            if (*nOutSize < out_size)
            {
                *nOutSize = out_size;
                return false;
            }

            Botan::secure_vector<uint8_t> pt;
            pt.reserve(out_size);
            pt.insert(pt.end(), pData, pData + nSize);

            _cipher->finish(pt);

            *nOutSize = pt.size();

            memcpy(pOutData, pt.data(), pt.size());
            return true;
        }
        catch (std::exception const &)
        {
            return false;
        }
    }

    bool aes_decrypt(void * cipher,
                     uint8_t const *pData, size_t nSize, uint8_t *pOutData, size_t * nOutSize) noexcept
    {
        if (!cipher || !pData || !nOutSize)
            return false;

        try
        {
            auto * _cipher = static_cast<Botan::Cipher_Mode*>(cipher);

            size_t out_size = _cipher->output_length(nSize);

            if (!pOutData)
            {
                *nOutSize = out_size;
                return true;
            }

            if (*nOutSize < out_size)
            {
                *nOutSize = out_size;
                return false;
            }

            Botan::secure_vector<uint8_t> pt;
            pt.reserve(out_size);
            pt.insert(pt.end(), pData, pData + nSize);

            _cipher->finish(pt);

            *nOutSize = pt.size();

            memcpy(pOutData, pt.data(), pt.size());
            return true;
        }
        catch (std::exception const &)
        {
            return false;
        }
    }
}
