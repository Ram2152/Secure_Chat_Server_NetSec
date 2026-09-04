#ifndef CRYPTO_HH
#define CRYPTO_HH

#include <array>
#include <string>
#include <openssl/bn.h>
#include <openssl/evp.h>

constexpr int AES_KEY_LEN = 32;
constexpr int GCM_IV_LEN  = 12;
constexpr int GCM_TAG_LEN = 16;

using AesKey = std::array<unsigned char, AES_KEY_LEN>;

void my_mod_exp(BIGNUM *result, const BIGNUM *base, const BIGNUM *exp, const BIGNUM *m, BN_CTX *ctx);

int dh_generate_keypair(BIGNUM **priv, BIGNUM **pub);

std::string dh_compute_shared(const BIGNUM *peer_pub, const BIGNUM *priv);

std::string bn_to_bytes(const BIGNUM *bn);
BIGNUM *bn_from_bytes(const std::string &in);

std::string sha256(const std::string &data);

AesKey derive_key(const std::string &secret);

std::string fingerprint_hex(const std::string &data, int nbytes);

bool aes_gcm_seal(const AesKey &key, const std::string &pt, std::string &out);

bool aes_gcm_open(const AesKey &key, const std::string &in, std::string &pt);

#endif
