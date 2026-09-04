#ifndef CRYPTO_HH
#define CRYPTO_HH

#include <array>
#include <string>
#include <cstddef>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

constexpr int AES_KEY_LEN = 32;
constexpr int GCM_IV_LEN  = 12;
constexpr int GCM_TAG_LEN = 16;

using AesKey = std::array<unsigned char, AES_KEY_LEN>;

void my_mod_exp(BIGNUM *result, const BIGNUM *base, const BIGNUM *exp,
                const BIGNUM *m, BN_CTX *ctx);

int dh_generate_keypair(BIGNUM **priv, BIGNUM **pub);

std::string dh_compute_shared(const BIGNUM *peer_pub, const BIGNUM *priv);

std::string bn_to_bytes(const BIGNUM *bn);
BIGNUM *bn_from_bytes(const std::string &in);

std::string sha256(const std::string &data);   /* 32 raw bytes */

AesKey derive_key(const std::string &secret);

std::string fingerprint_hex(const std::string &data, int nbytes);

bool aes_gcm_seal(const AesKey &key, const std::string &pt, std::string &out);

bool aes_gcm_open(const AesKey &key, const std::string &in, std::string &pt);

bool random_bytes(unsigned char *buf, int n);   /* true on success */
std::string random_bytes(size_t n);             /* the challenge nonce uses this */

EVP_PKEY *load_privkey_file(const std::string &path);
X509     *load_cert_file(const std::string &path);
X509     *load_cert_mem(const std::string &pem);
bool      read_file(const std::string &path, std::string &out);

int validate_cert(X509 *cert, X509 *ca, const std::string &expected_cn, std::string &err);

bool rsa_sign(EVP_PKEY *priv, const std::string &msg, std::string &sig);
bool rsa_verify(EVP_PKEY *pub, const std::string &msg, const std::string &sig);

std::string bytes_to_hex(const std::string &in);
bool hex_to_bytes(const std::string &hex, std::string &out);

#endif /* CRYPTO_HH */
