#include "common.hh"
#include "crypto.hh"
#include <string>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <chrono>
#include <ctime>
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

using Clock = std::chrono::steady_clock;

int fd;
AesKey g_key;                 
std::string partner;
std::string g_user;
std::mutex g_plock;

bool starts_with(const std::string &s, const std::string &prefix)
{
    return s.compare(0, prefix.size(), prefix) == 0;
}

struct E2ESession {
    bool active = false;
    std::string peer;
    int cur_epoch = 0;                  
    AesKey cur_key{};
    int prev_epoch = -1;                
    AesKey prev_key{};
    int pending_epoch = 0;              
    BIGNUM *pending_priv = nullptr;     
    Clock::time_point last_rotate;
};
E2ESession g_e2e;
std::mutex g_elock;

bool am_initiator(const std::string &peer) { return g_user < peer; }

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

std::string key_fingerprint(const AesKey &key, int nbytes)
{
    return fingerprint_hex(std::string(key.begin(), key.end()), nbytes);
}

void log_key(const std::string &what, int epoch, const AesKey &key)
{
    std::string fp = key_fingerprint(key, 8);
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char ts[32];
    std::strftime(ts, sizeof ts, "%H:%M:%S", std::localtime(&t));
    std::cout << "\n[rekey] " << what << "  epoch=" << epoch << "  key-fingerprint=" << fp << "  at " << ts << "\n> " << std::flush;
}

void install_key(int epoch, const AesKey &newkey)
{
    if (g_e2e.active) {
        g_e2e.prev_key = g_e2e.cur_key;
        g_e2e.prev_epoch = g_e2e.cur_epoch;
    } 
    else {
        g_e2e.prev_epoch = -1;
    }
    g_e2e.cur_key = newkey;
    g_e2e.cur_epoch = epoch;
    g_e2e.active = true;
    g_e2e.last_rotate = Clock::now();
}

void e2e_send_init(const std::string &peer, int epoch)
{
    BIGNUM *priv, *pub;
    if (dh_generate_keypair(&priv, &pub) != 0) return;
    std::string hex = bytes_to_hex(bn_to_bytes(pub));
    BN_free(pub);

    {
        std::lock_guard<std::mutex> lk(g_elock);
        if (g_e2e.pending_priv) BN_free(g_e2e.pending_priv);
        g_e2e.pending_priv = priv;
        g_e2e.pending_epoch = epoch;
        g_e2e.peer = peer;
    }

    send_msg_to(peer, T_INIT + std::to_string(epoch) + ":" + hex);
}

void e2e_start(const std::string &peer)
{
    e2e_send_init(peer, 1);
    std::cout << "[e2e] initiating with " << peer << " ...\n";
}

void e2e_rekey()
{
    bool active;
    std::string peer;
    int next;
    {
        std::lock_guard<std::mutex> lk(g_elock);
        active = g_e2e.active;
        peer = g_e2e.peer;
        next = g_e2e.cur_epoch + 1;
    }
    if (!active || !am_initiator(peer)) return;
    e2e_send_init(peer, next);
}

void e2e_on_init(const std::string &from, int epoch, const std::string &hexpub)
{
    std::string pb;
    if (!hex_to_bytes(hexpub, pb) || pb.empty()) return;
    BIGNUM *peer_pub = bn_from_bytes(pb);
    BIGNUM *priv, *pub;
    if (dh_generate_keypair(&priv, &pub) != 0) { BN_free(peer_pub); return; }
    std::string secret = dh_compute_shared(peer_pub, priv);
    AesKey newkey = derive_key(secret);
    std::string hex = bytes_to_hex(bn_to_bytes(pub));
    BN_free(peer_pub); BN_free(priv); BN_free(pub);

    bool accepted = false, initial = false;
    {
        std::lock_guard<std::mutex> lk(g_elock);
        if (!g_e2e.active || epoch > g_e2e.cur_epoch) {
            initial = !g_e2e.active;
            g_e2e.peer = from;
            install_key(epoch, newkey);
            accepted = true;
        }
    }

    if (accepted) {
        send_msg_to(from, T_ACK + std::to_string(epoch) + ":" + hex);
        if (initial) {
            {
                std::lock_guard<std::mutex> lk(g_plock);
                partner = from;
            }
            log_key("established (responder)", epoch, newkey);
        } 
        else {
            log_key("rotated (responder)", epoch, newkey);
        }
    }
}

void e2e_on_ack(const std::string &from, int epoch, const std::string &hexpub)
{
    std::string pb;
    if (!hex_to_bytes(hexpub, pb) || pb.empty()) return;
    BIGNUM *peer_pub = bn_from_bytes(pb);

    bool accepted = false, initial = false;
    AesKey newkey{};
    {
        std::lock_guard<std::mutex> lk(g_elock);
        if (g_e2e.pending_priv && g_e2e.pending_epoch == epoch && g_e2e.peer == from) {
            std::string secret = dh_compute_shared(peer_pub, g_e2e.pending_priv);
            newkey = derive_key(secret);
            initial = !g_e2e.active;
            install_key(epoch, newkey);
            BN_free(g_e2e.pending_priv);
            g_e2e.pending_priv = nullptr;
            g_e2e.pending_epoch = 0;
            accepted = true;
        }
    }
    BN_free(peer_pub);

    if (accepted) {
        if (initial) {
            {
                std::lock_guard<std::mutex> lk(g_plock);
                partner = from;
            }
            log_key("established (initiator)", epoch, newkey);
        } 
        else {
            log_key("rotated (initiator)", epoch, newkey);
        }
    }
}

void e2e_on_msg(const std::string &from, int epoch, const std::string &hexblob)
{
    std::string blob;
    if (!hex_to_bytes(hexblob, blob) || blob.empty()) return;

    bool have = false;
    AesKey k{};
    {
        std::lock_guard<std::mutex> lk(g_elock);
        if (g_e2e.active && g_e2e.peer == from) {
            if (epoch == g_e2e.cur_epoch)       { k = g_e2e.cur_key;  have = true; }
            else if (epoch == g_e2e.prev_epoch) { k = g_e2e.prev_key; have = true; }
        }
    }
    if (!have) {
        std::cout << "\n[e2e] msg from " << from << " under unknown epoch " << epoch << " - dropped\n> " << std::flush;
        return;
    }
    std::string pt;
    if (!aes_gcm_open(k, blob, pt)) {
        std::cout << "\n[e2e] decrypt failed from " << from << "\n> " << std::flush;
        return;
    }
    std::cout << "\n[" << from << " (e2e/e" << epoch << ")] " << pt << "\n> " << std::flush;
}

bool split_epoch(const std::string &s, int &epoch, std::string &hex)
{
    size_t c = s.find(':');
    if (c == std::string::npos) return false;
    epoch = std::atoi(s.substr(0, c).c_str());
    hex = s.substr(c + 1);
    return true;
}

void handle_incoming_msg(const std::string &from, const std::string &payload)
{
    int e;
    std::string h;
    if (starts_with(payload, T_INIT)) {
        if (split_epoch(payload.substr(T_INIT.size()), e, h)) e2e_on_init(from, e, h);
    } 
    else if (starts_with(payload, T_ACK)) {
        if (split_epoch(payload.substr(T_ACK.size()), e, h)) e2e_on_ack(from, e, h);
    } 
    else if (starts_with(payload, T_MSG)) {
        if (split_epoch(payload.substr(T_MSG.size()), e, h)) e2e_on_msg(from, e, h);
    } 
    else {
        std::cout << "\n[" << from << "] " << payload << "\n> " << std::flush;
    }
}

void recv_thread()
{
    std::string blob, pt;
    while (recv_frame(fd, blob) == 0) {
        if (!aes_gcm_open(g_key, blob, pt)) {
            std::cout << "\n[!] link decrypt failed\n> " << std::flush;
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

void rekey_timer()
{
    const char *env = std::getenv("E2E_REKEY_SECONDS");
    int secs = env ? std::atoi(env) : 60;
    if (secs <= 0) secs = 60;
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(secs));
        bool active;
        std::string peer;
        {
            std::lock_guard<std::mutex> lk(g_elock);
            active = g_e2e.active;
            peer = g_e2e.peer;
        }
        if (active && am_initiator(peer)) e2e_rekey();
    }
}

void send_chat(const std::string &target, const std::string &text)
{
    bool e2e = false;
    AesKey k{};
    int epoch = 0;
    {
        std::lock_guard<std::mutex> lk(g_elock);
        if (g_e2e.active && g_e2e.peer == target) {
            k = g_e2e.cur_key;
            epoch = g_e2e.cur_epoch;
            e2e = true;
        }
    }
    if (e2e) {
        std::string blob;
        if (!aes_gcm_seal(k, text, blob)) return;
        send_msg_to(target, T_MSG + std::to_string(epoch) + ":" + bytes_to_hex(blob));
    } 
    else {
        send_msg_to(target, text);
    }
}

void cmd_keyage()
{
    bool active;
    std::string fp, peer;
    int age = 0, epoch = 0;
    {
        std::lock_guard<std::mutex> lk(g_elock);
        active = g_e2e.active;
        if (active) {
            fp = key_fingerprint(g_e2e.cur_key, 8);
            age = (int)std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - g_e2e.last_rotate).count();
            epoch = g_e2e.cur_epoch;
            peer = g_e2e.peer;
        }
    }
    if (!active) { std::cout << "[keyage] no active E2E session\n> " << std::flush; return; }
    std::cout << "[keyage] peer=" << peer << " epoch=" << epoch << " fingerprint=" << fp << " age=" << age << "s role=" << (am_initiator(peer) ? "initiator" : "responder") << "\n> " << std::flush;
}

bool do_handshake(X509 *ca)
{
    std::string certbuf;
    if (recv_frame(fd, certbuf) != 0) return false;
    X509 *cert = load_cert_mem(certbuf);
    if (!cert) { std::cerr << "[ABORT] bad certificate\n"; return false; }

    std::string err;
    if (validate_cert(cert, ca, SERVER_CN, err) != 0) {
        std::cerr << "[ABORT] cert REJECTED: " << err << "\n";
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
    g_user = argv[3];
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

    send_enc("LOGIN " + g_user);
    std::thread t(recv_thread);
    t.detach();
    std::thread tk(rekey_timer);
    tk.detach();
    std::cout << "Connected as '" << g_user << "'. Commands: @user msg | /chat user | /e2e user | /rekey | /keyage | /who | /quit\n> " << std::flush;

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
        else if (line == "/keyage") {
            cmd_keyage();
        } 
        else if (line == "/rekey") {
            bool active;
            std::string peer;
            {
                std::lock_guard<std::mutex> lk(g_elock);
                active = g_e2e.active;
                peer = g_e2e.peer;
            }
            if (!active) {
                std::cout << "[rekey] no active E2E session\n> " << std::flush;
            } 
            else if (!am_initiator(peer)) {
                std::cout << "[rekey] you are the responder; rotations are driven by '" << peer << "'\n> " << std::flush;
            } 
            else {
                e2e_rekey();
                std::cout << "[rekey] forcing rotation ...\n> " << std::flush;
            }
        } 
        else if (starts_with(line, "/e2e ")) {
            e2e_start(line.substr(5));
            std::cout << "> " << std::flush;
        } 
        else if (starts_with(line, "/chat ")) {
            std::string who = line.substr(6);
            {
                std::lock_guard<std::mutex> lk(g_plock);
                partner = who;
            }
            std::cout << "[now chatting with " << who << "]\n> " << std::flush;
        } 
        else if (line[0] == '@') {
            size_t sp = line.find(' ');
            std::string target = (sp == std::string::npos) ? line.substr(1) : line.substr(1, sp - 1);
            std::string text   = (sp == std::string::npos) ? "" : line.substr(sp + 1);
            {
                std::lock_guard<std::mutex> lk(g_plock);
                partner = target;
            }
            if (!text.empty()) send_chat(target, text);
            else std::cout << "[now chatting with " << target << "]\n";
            std::cout << "> " << std::flush;
        } 
        else {
            std::string target;
            {
                std::lock_guard<std::mutex> lk(g_plock);
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
