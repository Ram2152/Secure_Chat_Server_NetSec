#include "common.hh"
#include "crypto.hh"
#include <string>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <arpa/inet.h>
#include <sys/socket.h>

const std::string SERVER_CN = "chatserver";
const int NONCE_LEN = 32;

const std::string T_INIT = "__E2E_INIT__";
const std::string T_ACK  = "__E2E_ACK__";
const std::string T_MSG  = "__E2E_MSG__";

int fd;
AesKey g_key;                    
std::string partner;
std::string user;
std::mutex plock;

bool starts_with(const std::string &s, const std::string &prefix)
{
    return s.compare(0, prefix.size(), prefix) == 0;
}

struct E2ESession {
    bool active  = false;               
    bool pending = false;               
    std::string peer;
    BIGNUM *my_priv = nullptr;          
    AesKey key{};
};
E2ESession g_e2e;
std::mutex g_elock;

int send_enc(const std::string &line)
{
    std::string blob;
    if (!aes_gcm_seal(g_key, line, blob)) return -1;
    return send_frame(fd, blob);
}

int send_msg_to(const std::string &target, const std::string &payload)
{
    return send_enc("MSG " + target + " " + payload);
}

void e2e_start(const std::string &peer)
{
    BIGNUM *priv, *pub;
    if (dh_generate_keypair(&priv, &pub) != 0) return;
    std::string hex = bytes_to_hex(bn_to_bytes(pub));

    {
        std::lock_guard<std::mutex> lk(g_elock);
        if (g_e2e.my_priv) BN_free(g_e2e.my_priv);
        g_e2e.active = false;
        g_e2e.pending = true;
        g_e2e.peer = peer;
        g_e2e.my_priv = priv;
    }
    BN_free(pub);

    send_msg_to(peer, T_INIT + hex);
    std::cout << "[e2e] sent handshake INIT to " << peer << " ...\n";
}

void e2e_on_init(const std::string &from, const std::string &hexpub)
{
    std::string pb;
    if (!hex_to_bytes(hexpub, pb) || pb.empty()) return;
    BIGNUM *peer_pub = bn_from_bytes(pb);

    BIGNUM *priv, *pub;
    if (dh_generate_keypair(&priv, &pub) != 0) { BN_free(peer_pub); return; }
    std::string secret = dh_compute_shared(peer_pub, priv);
    std::string hex = bytes_to_hex(bn_to_bytes(pub));

    AesKey newkey = derive_key(secret);
    {
        std::lock_guard<std::mutex> lk(g_elock);
        g_e2e.active = true;
        g_e2e.pending = false;
        g_e2e.peer = from;
        g_e2e.key = newkey;
    }

    std::string fp = fingerprint_hex(secret, 8);
    send_msg_to(from, T_ACK + hex);

    {
        std::lock_guard<std::mutex> lk(plock);
        partner = from;
    }
    std::cout << "\n[e2e] established with " << from << " (responder). shared fingerprint = " << fp << "\n> " << std::flush;
    BN_free(peer_pub); BN_free(priv); BN_free(pub);
}

void e2e_on_ack(const std::string &from, const std::string &hexpub)
{
    std::string pb;
    if (!hex_to_bytes(hexpub, pb) || pb.empty()) return;
    BIGNUM *peer_pub = bn_from_bytes(pb);

    bool accepted = false;
    std::string secret;
    {
        std::lock_guard<std::mutex> lk(g_elock);
        if (g_e2e.my_priv && g_e2e.peer == from) {
            secret = dh_compute_shared(peer_pub, g_e2e.my_priv);
            g_e2e.key = derive_key(secret);
            g_e2e.active = true;
            g_e2e.pending = false;
            BN_free(g_e2e.my_priv);
            g_e2e.my_priv = nullptr;
            accepted = true;
        }
    }
    BN_free(peer_pub);
    if (!accepted) return;

    std::string fp = fingerprint_hex(secret, 8);
    {
        std::lock_guard<std::mutex> lk(plock);
        partner = from;
    }
    std::cout << "\n[e2e] established with " << from << " (initiator). shared fingerprint = " << fp << "\n> " << std::flush;
}

void e2e_on_msg(const std::string &from, const std::string &hexblob)
{
    std::string blob;
    if (!hex_to_bytes(hexblob, blob) || blob.empty()) return;

    bool have;
    AesKey k;
    {
        std::lock_guard<std::mutex> lk(g_elock);
        have = g_e2e.active && g_e2e.peer == from;
        if (have) k = g_e2e.key;
    }
    if (!have) { std::cout << "\n[e2e] got encrypted msg from " << from << " but no session\n> " << std::flush; return; }

    std::string pt;
    if (!aes_gcm_open(k, blob, pt)) {
        std::cout << "\n[e2e] FAILED to decrypt message from " << from << "\n> " << std::flush;
        return;
    }
    std::cout << "\n[" << from << " (e2e)] " << pt << "\n> " << std::flush;
}

void handle_incoming_msg(const std::string &from, const std::string &payload)
{
    if (starts_with(payload, T_INIT))      e2e_on_init(from, payload.substr(T_INIT.size()));
    else if (starts_with(payload, T_ACK))  e2e_on_ack(from, payload.substr(T_ACK.size()));
    else if (starts_with(payload, T_MSG))  e2e_on_msg(from, payload.substr(T_MSG.size()));
    else { std::cout << "\n[" << from << "] " << payload << "\n> " << std::flush; }   /* plain chat */
}

void recv_thread()
{
    std::string blob, pt;
    while (recv_frame(fd, blob) == 0) {
        if (!aes_gcm_open(g_key, blob, pt)) {
            std::cout << "\n[!] link decryption FAILED - dropped\n> " << std::flush;
            continue;
        }
        if (starts_with(pt, "MSG ")) {
            std::string rest = pt.substr(4);
            size_t sp = rest.find(' ');
            if (sp != std::string::npos) handle_incoming_msg(rest.substr(0, sp), rest.substr(sp + 1));
        } 
        else if (starts_with(pt, "WHO ")) {
            std::cout << "\n[online] " << pt.substr(4) << "\n> " << std::flush;
        } 
        else if (starts_with(pt, "OK ")) {
            std::cout << "[server] " << pt.substr(3) << "\n> " << std::flush;
        } 
        else if (starts_with(pt, "ERR ")) {
            std::cout << "\n[error] " << pt.substr(4) << "\n> " << std::flush;
        } 
        else {
            std::cout << "\n[server] " << pt << "\n> " << std::flush;
        }
    }
    std::cout << "\n[disconnected from server]\n";
    exit(0);
}

void send_chat(const std::string &target, const std::string &text)
{
    bool e2e;
    AesKey k;
    {
        std::lock_guard<std::mutex> lk(g_elock);
        e2e = g_e2e.active && g_e2e.peer == target;
        if (e2e) k = g_e2e.key;
    }

    if (e2e) {
        std::string blob;
        if (!aes_gcm_seal(k, text, blob)) return;
        send_msg_to(target, T_MSG + bytes_to_hex(blob));
    } else {
        send_msg_to(target, text);   /* server can read this one */
    }
}

bool do_handshake(X509 *ca)
{
    std::string certbuf;
    if (recv_frame(fd, certbuf) != 0) return false;
    X509 *cert = load_cert_mem(certbuf);
    if (!cert) { std::cerr << "[ABORT] bad certificate\n"; return false; }

    std::string err;
    if (validate_cert(cert, ca, SERVER_CN, err) != 0) {
        std::cerr << "[ABORT] certificate REJECTED: " << err << "\n";
        X509_free(cert);
        return false;
    }
    std::cout << "[pki] certificate OK (CA-signed, valid, CN=" << SERVER_CN << ")\n";

    std::string nonce = random_bytes(NONCE_LEN);
    if (nonce.empty() || send_frame(fd, nonce) != 0) { X509_free(cert); return false; }

    std::string spub;
    if (recv_frame(fd, spub) != 0) { X509_free(cert); return false; }
    std::string sig;
    if (recv_frame(fd, sig) != 0) { X509_free(cert); return false; }

    EVP_PKEY *spk = X509_get_pubkey(cert);
    bool ok = rsa_verify(spk, nonce + spub, sig);
    EVP_PKEY_free(spk);
    if (!ok) { std::cerr << "[ABORT] proof-of-possession failed\n"; X509_free(cert); return false; }
    std::cout << "[pki] proof-of-possession OK\n";

    BIGNUM *priv, *pub;
    if (dh_generate_keypair(&priv, &pub) != 0) { X509_free(cert); return false; }
    if (send_frame(fd, bn_to_bytes(pub)) != 0) { X509_free(cert); BN_free(priv); BN_free(pub); return false; }
    BIGNUM *server_pub = bn_from_bytes(spub);
    std::string secret = dh_compute_shared(server_pub, priv);
    g_key = derive_key(secret);
    std::cout << "[dh] client<->server fingerprint = " << fingerprint_hex(secret, 8) << "\n";

    BN_free(priv); BN_free(pub); BN_free(server_pub); X509_free(cert);
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        std::cerr << "usage: " << argv[0] << " <server_ip> <port> <username> <ca_cert.pem>\n";
        return 1;
    }
    std::string ip = argv[1];
    int port = std::stoi(argv[2]);
    user = argv[3];
    X509 *ca = load_cert_file(argv[4]);
    if (!ca) { std::cerr << "cannot read CA cert\n"; return 1; }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        std::cerr << "connect: " << strerror(errno) << "\n";
        return 1;
    }
    if (!do_handshake(ca)) { std::cerr << "server authentication failed.\n"; close(fd); return 2; }

    send_enc("LOGIN " + user);
    std::thread t(recv_thread);
    t.detach();
    std::cout << "Connected as '" << user << "'. Commands: @user msg | /chat user | /e2e user | /who | /quit\n> " << std::flush;

    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) { std::cout << "> " << std::flush; continue; }

        if (line == "/quit") {
            send_enc("QUIT");
            break;
        } 
        else if (line == "/who") {
            send_enc("WHO");
        } 
        else if (starts_with(line, "/e2e ")) {
            e2e_start(line.substr(5));
            std::cout << "> " << std::flush;
        } 
        else if (starts_with(line, "/chat ")) {
            std::string who = line.substr(6);
            {
                std::lock_guard<std::mutex> lk(plock);
                partner = who;
            }
            std::cout << "[now chatting with " << who << "]\n> " << std::flush;
        } 
        else if (line[0] == '@') {
            size_t sp = line.find(' ');
            std::string target = (sp == std::string::npos) ? line.substr(1) : line.substr(1, sp - 1);
            std::string text   = (sp == std::string::npos) ? "" : line.substr(sp + 1);
            {
                std::lock_guard<std::mutex> lk(plock);
                partner = target;
            }
            if (!text.empty()) send_chat(target, text);
            else std::cout << "[now chatting with " << target << "]\n";
            std::cout << "> " << std::flush;
        } else {
            std::string target;
            {
                std::lock_guard<std::mutex> lk(plock);
                target = partner;
            }
            if (target.empty()) {
                std::cout << "[no partner selected]\n> " << std::flush;
            } 
            else {
                send_chat(target, line);
                std::cout << "> " << std::flush;
            }
        }
    }
    close(fd);
    return 0;
}
