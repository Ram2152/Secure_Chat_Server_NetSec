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

int fd;
AesKey g_key;
std::string partner;
std::mutex g_plock;

bool starts_with(const std::string &s, const std::string &prefix)
{
    return s.compare(0, prefix.size(), prefix) == 0;
}

int send_enc(const std::string &line)
{
    std::string blob;
    if (!aes_gcm_seal(g_key, line, blob)) return -1;
    return send_frame(fd, blob);
}

void recv_thread()
{
    std::string blob, pt;
    while (recv_frame(fd, blob) == 0) {
        if (!aes_gcm_open(g_key, blob, pt)) {
            std::cout << "\n[!] decryption/authentication FAILED - message dropped\n> " << std::flush;
            continue;
        }
        if (starts_with(pt, "MSG ")) {
            std::string rest = pt.substr(4);
            size_t sp = rest.find(' ');
            if (sp != std::string::npos)
                std::cout << "\n[" << rest.substr(0, sp) << "] " << rest.substr(sp + 1) << "\n> ";
        } 
        else if (starts_with(pt, "WHO ")) {
            std::cout << "\n[online] " << pt.substr(4) << "\n> ";
        } 
        else if (starts_with(pt, "OK ")) {
            std::cout << "[server] " << pt.substr(3) << "\n> ";
        } 
        else if (starts_with(pt, "ERR ")) {
            std::cout << "\n[error] " << pt.substr(4) << "\n> ";
        } 
        else {
            std::cout << "\n[server] " << pt << "\n> ";
        }
        std::cout << std::flush;
    }
    std::cout << "\n[disconnected from server]\n";
    exit(0);
}

bool do_dh()
{
    BIGNUM *priv, *pub;
    if (dh_generate_keypair(&priv, &pub) != 0) return false;
    if (send_frame(fd, bn_to_bytes(pub)) != 0) { BN_free(priv); BN_free(pub); return false; }

    std::string spub;
    if (recv_frame(fd, spub) != 0) { BN_free(priv); BN_free(pub); return false; }
    BIGNUM *server_pub = bn_from_bytes(spub);

    std::string secret = dh_compute_shared(server_pub, priv);
    g_key = derive_key(secret);

    std::cout << "[dh] shared-secret fingerprint = " << fingerprint_hex(secret, 8) << "\n";
    std::cout << "     (must match the server's printed fingerprint for this link)\n";

    BN_free(priv); BN_free(pub); BN_free(server_pub);
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " <server_ip> <port> <username>\n";
        return 1;
    }
    std::string ip = argv[1];
    int port = std::stoi(argv[2]);
    std::string user = argv[3];

    fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        std::cerr << "connect: " << strerror(errno) << "\n";
        return 1;
    }

    if (!do_dh()) {
        std::cerr << "DH handshake failed\n";
        return 1;
    }

    send_enc("LOGIN " + user);

    std::thread t(recv_thread);
    t.detach();

    std::cout << "Connected as '" << user << "'. Commands: @user msg | /chat user | /who | /quit\n> " << std::flush;

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
            if (!text.empty()) {
                send_enc("MSG " + target + " " + text);
            } 
            else {
                std::cout << "[now chatting with " << target << "]\n";
            }
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
                send_enc("MSG " + target + " " + line);
                std::cout << "> " << std::flush;
            }
        }
    }
    close(fd);
    return 0;
}
