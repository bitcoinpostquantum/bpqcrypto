// Copyright (c) 2018 The Bitcoin Post-Quantum developers

#define BPQCRYPTO_EXPORT

#include "../include/bpqcrypto.hpp"

#include <botan/hash.h>
#include <botan/shake.h>

#include <vector>

namespace bpqcrypto {


    BPQCRYPTO_PUBLIC secure_vector<uint8_t> hash_sha256(uint8_t const *msg, size_t msg_size)
    {
        std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));

        hash->update(msg,msg_size);

        return hash->final();
    }

    BPQCRYPTO_PUBLIC secure_vector<uint8_t> hash_shake128(uint8_t const *msg, size_t msg_size, size_t output_bits)
    {
        Botan::SHAKE_128 hash(output_bits);

        hash.update(msg,msg_size);

        return hash.final();
    }

    BPQCRYPTO_PUBLIC bool hash_sha256(uint8_t const * msg, size_t msg_size, uint8_t result[32]) noexcept
    {
        try
        {
            auto hash = hash_sha256(msg, msg_size);
            std::copy(hash.begin(), hash.begin()+32, result);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    BPQCRYPTO_PUBLIC bool hash_shake128(uint8_t const * msg, size_t msg_size, size_t output_bits, uint8_t result[]) noexcept
    {
        try
        {
            auto hash = hash_shake128(msg, msg_size, output_bits);
            std::copy(hash.begin(), hash.begin() + output_bits/8, result);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    BPQCRYPTO_PUBLIC bool hash256_shake128(uint8_t const * msg, size_t msg_size, uint8_t result[32]) noexcept
    {
        try
        {
            auto hash = hash256_shake128(msg, msg_size);
            std::copy(hash.begin(), hash.begin()+32, result);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

} // namespace bpqcrypto
