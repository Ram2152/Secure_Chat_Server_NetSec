/* crypto.hh - cryptographic building blocks for Phase 3.
 *
 * What is implemented "from scratch" here:
 *   - Diffie-Hellman key agreement over the RFC 3526 2048-bit MODP group.
 *     The modular exponentiation is our own square-and-multiply loop
 *     (my_mod_exp). We use OpenSSL's BIGNUM ONLY as an arbitrary-precision
 *     integer type (multiply + mod), which the assignment explicitly permits;
 *     we do NOT call any DH_/DH* API and never include <openssl/dh.h>.
 *
 * What uses OpenSSL primitives (allowed as building blocks):
 *   - AES-256-GCM via <openssl/evp.h>
 *   - SHA-256 via <openssl/sha.h>
 *   - X.509 parsing / verification via <openssl/x509.h>
 *   - RSA signing/verification via EVP
 *
 * We never link the TLS/SSL layer (<openssl/ssl.h>): the handshake,
 * certificate checks and encryption framing are all our own logic.
 *
 * Every payload here (ciphertext blobs, DH public values, signatures, PEM
 * files) is binary data of a length known up front, so we carry it as
 * std::string throughout: std::string is length-tracked and NUL-transparent,
 * which is exactly what a length-prefixed byte blob needs, without the
 * caller having to pre-size a buffer or thread a length out-parameter.
 *
 * End-to-end hex-encoded wire tags arrive in Phase 4; not needed here.
 */
#ifndef CRYPTO_HH
#define CRYPTO_HH

#include <array>
#include <string>
#include <cstddef>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

constexpr int AES_KEY_LEN = 32;   /* AES-256                                */
constexpr int GCM_IV_LEN  = 12;   /* 96-bit nonce, the recommended GCM size */
constexpr int GCM_TAG_LEN = 16;   /* 128-bit authentication tag             */

using AesKey = std::array<unsigned char, AES_KEY_LEN>;

/* ----- Diffie-Hellman (our own modular exponentiation) ----- */

/* result = base^exp mod m, implemented with square-and-multiply. */
void my_mod_exp(BIGNUM *result, const BIGNUM *base, const BIGNUM *exp,
                const BIGNUM *m, BN_CTX *ctx);

/* Generate an ephemeral DH keypair in the RFC 3526 group.
 * Caller owns *priv and *pub (free with BN_free). Returns 0 on success. */
int dh_generate_keypair(BIGNUM **priv, BIGNUM **pub);

/* Compute the raw shared secret = peer_pub^priv mod p, as big-endian bytes. */
std::string dh_compute_shared(const BIGNUM *peer_pub, const BIGNUM *priv);

/* Serialise / parse a public value as raw big-endian bytes for the wire. */
std::string bn_to_bytes(const BIGNUM *bn);
BIGNUM *bn_from_bytes(const std::string &in);

/* ----- hashing / key derivation ----- */

std::string sha256(const std::string &data);   /* 32 raw bytes */

/* Derive a 32-byte AES key from the raw DH secret. This is the mandatory
 * hash step: the raw secret is a group element (non-uniform, wrong length),
 * so we run it through SHA-256 to get a uniform, fixed-length key. */
AesKey derive_key(const std::string &secret);

/* Human-comparable fingerprint = first nbytes of SHA-256(data), as hex.
 * Used to prove two sides agree WITHOUT ever revealing the secret/key. */
std::string fingerprint_hex(const std::string &data, int nbytes);

/* ----- AES-256-GCM (authenticated encryption) ----- */

/* Seal: out = [12B IV][ciphertext][16B tag]. A fresh random IV is generated
 * every call. Returns false on failure (out is left empty). */
bool aes_gcm_seal(const AesKey &key, const std::string &pt, std::string &out);

/* Open: parse [IV][ct][tag], decrypt and verify the tag.
 * Returns false if authentication fails (tampering) or input is malformed.
 * On failure no plaintext is produced (pt is left empty). */
bool aes_gcm_open(const AesKey &key, const std::string &in, std::string &pt);

/* ----- randomness ----- */
bool random_bytes(unsigned char *buf, int n);   /* true on success */
std::string random_bytes(size_t n);             /* the challenge nonce uses this */

/* ----- PKI / signatures ----- */

EVP_PKEY *load_privkey_file(const std::string &path);
X509     *load_cert_file(const std::string &path);
X509     *load_cert_mem(const std::string &pem);
bool      read_file(const std::string &path, std::string &out);

/* Validate a peer certificate against our trusted CA.
 * Checks (a) signature made by CA, (b) validity period, (c) CN == expected.
 * Returns 0 if valid; -1 otherwise with a human reason in err. */
int validate_cert(X509 *cert, X509 *ca, const std::string &expected_cn, std::string &err);

/* RSA-SHA256 signing / verification (proof of possession). */
bool rsa_sign(EVP_PKEY *priv, const std::string &msg, std::string &sig);
bool rsa_verify(EVP_PKEY *pub, const std::string &msg, const std::string &sig);

#endif /* CRYPTO_HH */
