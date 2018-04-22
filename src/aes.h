// Copyright (c) 2018 The Bitcoin Post-Quantum developers

#pragma once

#include "../include/bpqcrypto.hpp"

namespace bpqcrypto {

    extern "C" BPQCRYPTO_PUBLIC void* aes_cipher_create(uint8_t const *pKey, uint8_t const * pIV, bool encrypt) noexcept;
    extern "C" BPQCRYPTO_PUBLIC void* aes256_cipher_create(uint8_t const *pKey, uint8_t const * pIV, bool encrypt) noexcept;
    extern "C" BPQCRYPTO_PUBLIC void aes_cipher_free(void * cipher) noexcept;

    extern "C" BPQCRYPTO_PUBLIC bool aes_encrypt(void * cipher,
        uint8_t const *pData, size_t nSize, uint8_t *pOutData, size_t * nOutSize) noexcept;
    extern "C" BPQCRYPTO_PUBLIC bool aes_decrypt(void * cipher,
        uint8_t const *pData, size_t nSize, uint8_t *pOutData, size_t * nOutSize) noexcept;

}
