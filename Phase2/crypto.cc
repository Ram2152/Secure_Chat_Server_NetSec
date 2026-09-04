#include "crypto.hh"

#include <algorithm>
#include <openssl/sha.h>
#include <openssl/rand.h>

const char *RFC3526_P_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

void load_group(BIGNUM **p, BIGNUM **g)
{
    *p = nullptr;
    BN_hex2bn(p, RFC3526_P_HEX);
    *g = BN_new();
    BN_set_word(*g, 2);
}

void my_mod_exp(BIGNUM *result, const BIGNUM *base, const BIGNUM *exp,
                const BIGNUM *m, BN_CTX *ctx)
{
    BIGNUM *b = BN_new();
    BN_one(result);                 
    BN_mod(b, base, m, ctx);        

    int bits = BN_num_bits(exp);
    for (int i = 0; i < bits; i++) {
        if (BN_is_bit_set(exp, i))
            BN_mod_mul(result, result, b, m, ctx);  
        BN_mod_mul(b, b, b, m, ctx);          
    }
    BN_free(b);
}

int dh_generate_keypair(BIGNUM **priv, BIGNUM **pub)
{
    BIGNUM *p, *g;
    load_group(&p, &g);
    BN_CTX *ctx = BN_CTX_new();

    *priv = BN_new();
    if (!BN_rand(*priv, 2047, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) goto err;

    *pub = BN_new();
    my_mod_exp(*pub, g, *priv, p, ctx);

    BN_free(p); BN_free(g); BN_CTX_free(ctx);
    return 0;
err:
    BN_free(p); BN_free(g); BN_CTX_free(ctx);
    return -1;
}

std::string dh_compute_shared(const BIGNUM *peer_pub, const BIGNUM *priv)
{
    BIGNUM *p, *g;
    load_group(&p, &g);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *s = BN_new();

    my_mod_exp(s, peer_pub, priv, p, ctx);

    std::string secret;
    secret.resize(BN_num_bytes(s));
    int len = BN_bn2bin(s, reinterpret_cast<unsigned char *>(&secret[0]));
    secret.resize(len);

    BN_free(s); BN_free(p); BN_free(g); BN_CTX_free(ctx);
    return secret;
}

std::string bn_to_bytes(const BIGNUM *bn)
{
    std::string out;
    out.resize(BN_num_bytes(bn));
    int len = BN_bn2bin(bn, reinterpret_cast<unsigned char *>(&out[0]));
    out.resize(len);
    return out;
}

BIGNUM *bn_from_bytes(const std::string &in)
{
    return BN_bin2bn(reinterpret_cast<const unsigned char *>(in.data()), (int)in.size(), nullptr);
}

std::string sha256(const std::string &data)
{
    std::string out;
    out.resize(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char *>(data.data()), data.size(),
           reinterpret_cast<unsigned char *>(&out[0]));
    return out;
}

AesKey derive_key(const std::string &secret)
{
    std::string h = sha256(secret);
    AesKey key{};
    std::copy(h.begin(), h.end(), key.begin());
    return key;
}

std::string bytes_to_hex(const std::string &in)
{
    const char *d = "0123456789abcdef";
    std::string out;
    out.resize(in.size() * 2);
    for (size_t i = 0; i < in.size(); i++) {
        unsigned char b = (unsigned char)in[i];
        out[2*i]   = d[(b >> 4) & 0xF];
        out[2*i+1] = d[b & 0xF];
    }
    return out;
}

std::string fingerprint_hex(const std::string &data, int nbytes)
{
    std::string h = sha256(data);
    if (nbytes > (int)h.size()) nbytes = (int)h.size();
    return bytes_to_hex(h.substr(0, nbytes));
}

bool random_bytes(unsigned char *buf, int n)
{
    return RAND_bytes(buf, n) == 1;
}

bool aes_gcm_seal(const AesKey &key, const std::string &pt, std::string &out)
{
    out.resize(pt.size() + GCM_IV_LEN + GCM_TAG_LEN);
    unsigned char *iv = reinterpret_cast<unsigned char *>(&out[0]);
    unsigned char *ct = iv + GCM_IV_LEN;
    if (!random_bytes(iv, GCM_IV_LEN)) { out.clear(); return false; }

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) { out.clear(); return false; }
    bool ok = false;
    int len = 0, ctlen = 0;
    do {
        if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(c, nullptr, nullptr, key.data(), iv) != 1) break;
        if (EVP_EncryptUpdate(c, ct, &len, reinterpret_cast<const unsigned char *>(pt.data()),
                              (int)pt.size()) != 1) break;
        ctlen = len;
        if (EVP_EncryptFinal_ex(c, ct + len, &len) != 1) break;
        ctlen += len;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, ct + ctlen) != 1) break;
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(c);
    if (!ok) out.clear();
    return ok;
}

bool aes_gcm_open(const AesKey &key, const std::string &in, std::string &pt)
{
    if (in.size() < (size_t)(GCM_IV_LEN + GCM_TAG_LEN)) { pt.clear(); return false; }
    const unsigned char *inp = reinterpret_cast<const unsigned char *>(in.data());
    const unsigned char *iv  = inp;
    const unsigned char *ct  = inp + GCM_IV_LEN;
    int ctlen = (int)in.size() - GCM_IV_LEN - GCM_TAG_LEN;
    const unsigned char *tag = inp + GCM_IV_LEN + ctlen;

    pt.resize(ctlen);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) { pt.clear(); return false; }
    bool ok = false;
    int len = 0, outl = 0;
    unsigned char finbuf[1];
    do {
        if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(c, nullptr, nullptr, key.data(), iv) != 1) break;
        if (ctlen > 0) {
            if (EVP_DecryptUpdate(c, reinterpret_cast<unsigned char *>(&pt[0]), &len, ct, ctlen) != 1) break;
        } 
        else {
            len = 0;
        }
        outl = len;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, const_cast<unsigned char *>(tag)) != 1) break;
        if (EVP_DecryptFinal_ex(c, finbuf, &len) <= 0) break;
        outl += len;
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(c);
    if (ok) pt.resize(outl); else pt.clear();
    return ok;
}
