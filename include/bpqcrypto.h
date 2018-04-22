// Copyright (c) 2018 The Bitcoin Post-Quantum developers

#ifndef BPQCRYPTO_BPQCRYPTO_H
#define BPQCRYPTO_BPQCRYPTO_H

#ifdef BPQCRYPTO_EXPORT

#if defined(_MSC_VER)
#define BPQCRYPTO_PUBLIC __declspec(dllexport)
#elif defined(__GNUC__)
#define BPQCRYPTO_PUBLIC __attribute__((visibility("default")))
#else
#define BPQCRYPTO_PUBLIC
#endif

#else // !BPQCRYPTO_EXPORT

#if defined(_MSC_VER)
#define BPQCRYPTO_PUBLIC __declspec(dllimport)
#elif defined(__GNUC__)
#define BPQCRYPTO_PUBLIC
#else
#define BPQCRYPTO_PUBLIC
#endif

#endif // BPQCRYPTO_EXPORT

#include <cstdint>

#define BPQCRYPTO_VERSION   "1.3.3"

enum BPQ_KEYTYPE
{
    BPQ_KEYTYPE_ECDSA_COMPRESSED = 2, // not implemented
    BPQ_KEYTYPE_ECDSA_UNCOMPRESSED = 4, // not implemented
    BPQ_KEYTYPE_XMSS_256_H10 = 110,
    BPQ_KEYTYPE_XMSS_256_H16 = 116,
    BPQ_KEYTYPE_XMSS_256_H20 = 120,
};

#ifdef __cplusplus
namespace bpqcrypto {
#endif

    extern "C" BPQCRYPTO_PUBLIC char const * get_version() noexcept;

    //
    // XMSS keys
    //

    // returns true if key was generated
    // *pKeySize  input: contains key buffer size
    //            output: contains key size or 0 on error
    extern "C" BPQCRYPTO_PUBLIC bool xmss_generate(BPQ_KEYTYPE keytype, uint8_t *pKey, size_t * pKeySize) noexcept;

    extern "C" BPQCRYPTO_PUBLIC bool xmss_generate_from_seed(BPQ_KEYTYPE keytype,
                                                             uint8_t const * sk_seed,
                                                             uint8_t const * prf_seed,
                                                             uint8_t const * pub_seed,
                                                             uint8_t *pKey, size_t * pKeySize) noexcept;

    extern "C" BPQCRYPTO_PUBLIC bool is_xmss_key(uint8_t const *pKey, size_t nKeySize) noexcept;
    extern "C" BPQCRYPTO_PUBLIC bool is_xmss_short_key(uint8_t const *pKey, size_t nKeySize) noexcept;
    extern "C" BPQCRYPTO_PUBLIC bool is_xmss_pubkey(uint8_t const *pKey, size_t nKeySize) noexcept;
    extern "C" BPQCRYPTO_PUBLIC bool is_xmss_signature(uint8_t const *pSig, size_t nSigSize, bool bStrict) noexcept;

    // returns long key size from any key ( long, short or public )
    extern "C" BPQCRYPTO_PUBLIC size_t xmss_get_key_size(uint8_t const *pKey, size_t nKeySize) noexcept;
    extern "C" BPQCRYPTO_PUBLIC size_t xmss_get_short_key_size(uint8_t const *pKey, size_t nKeySize) noexcept;
    extern "C" BPQCRYPTO_PUBLIC size_t xmss_get_pubkey_size(uint8_t const *pKey, size_t nKeySize) noexcept;

    extern "C" BPQCRYPTO_PUBLIC bool xmss_get_long_key(uint8_t const *pKey, size_t nKeySize, uint8_t *pKey2, size_t nKeySize2) noexcept;
    extern "C" BPQCRYPTO_PUBLIC bool xmss_get_short_key(uint8_t const *pKey, size_t nKeySize, uint8_t *pKey2, size_t nKeySize2) noexcept;
    extern "C" BPQCRYPTO_PUBLIC bool xmss_get_pubkey(uint8_t const *pKey, size_t nKeySize, uint8_t *pPubKey, size_t nPubKeySize) noexcept;

    // returns der signature size from any key ( long, short or public )
    extern "C" BPQCRYPTO_PUBLIC size_t xmss_get_signature_size(uint8_t const *pKey, size_t nKeySize) noexcept;

    extern "C" BPQCRYPTO_PUBLIC
    bool xmss_sign(
            uint8_t const * msg, size_t msg_size,
            uint8_t const * key, size_t key_size,
            size_t * pLeafIndex,
            uint8_t * pSign, size_t * pSignSize) noexcept;

    extern "C" BPQCRYPTO_PUBLIC
    bool xmss_verify(
            uint8_t const * msg, size_t msg_size,
            uint8_t const * sig, size_t sig_size,
            uint8_t const * pubkey, size_t pubkey_size) noexcept;


    //
    // ECDSA keys
    //

    extern "C" BPQCRYPTO_PUBLIC bool is_ecdsa_key(uint8_t const * pKey, size_t nKeySize) noexcept;

    //
    // HASH 256, shake
    //

    extern "C" BPQCRYPTO_PUBLIC bool hash_sha256(uint8_t const * msg, size_t msg_size, uint8_t result[32]) noexcept;
    extern "C" BPQCRYPTO_PUBLIC bool hash_shake128(uint8_t const * msg, size_t msg_size, size_t output_bits, uint8_t result[]) noexcept;
    extern "C" BPQCRYPTO_PUBLIC bool hash256_shake128(uint8_t const * msg, size_t msg_size, uint8_t result[32]) noexcept;



#ifdef __cplusplus
} // namespace bpqcrypto
#endif

#endif //BPQCRYPTO_BPQCRYPTO_H
