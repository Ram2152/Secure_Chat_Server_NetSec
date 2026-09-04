#include "common.hh"
#include "crypto.hh"
#include <string>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char **argv)
{
    if (argc != 5) {
        std::cerr << "usage: " << argv[0] << " <listen_port> <fake|stolen> <cert.pem> <signing_key.pem>\n";
        return 1;
    }
    
    int lport = std::stoi(argv[1]);
    std::string mode = argv[2];
    std::string cert_pem;
    
    if (!read_file(argv[3], cert_pem) || cert_pem.empty()) {
        std::cerr << "cannot load cert/key\n";
        return 1;
    }
    
    EVP_PKEY *sign_key = load_privkey_file(argv[4]);
    
    if (!sign_key) {
        std::cerr << "cannot load cert/key\n";
        return 1;
    }

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
    std::cout << "Mallory listening on " << lport << ", mode=" << mode << "\n";
    std::cout << "Mallory presenting cert '" << argv[3] << "', signing with '" << argv[4] << "'\n" << std::flush;

    for (;;) {
        struct sockaddr_in ca;
        socklen_t cl = sizeof ca;
        int vfd = accept(ls, (struct sockaddr *)&ca, &cl);
        if (vfd < 0) continue;
        std::cout << "\nMallory's victim connected from " << inet_ntoa(ca.sin_addr) << ":" << ntohs(ca.sin_port) << "\n" << std::flush;

        // send the certificate we are trying to pass off
        if (send_frame(vfd, cert_pem) != 0) {
		close(vfd);
		continue;
	}

        // try to receive the victim's challenge nonce
        std::string nonce;
        if (recv_frame(vfd, nonce) != 0) {
            std::cout << "RESULT: victim rejected the certificate and hung up.\n";
            std::cout << "              -> our cert was not signed by the trusted CA. Attack failed.\n" << std::flush;
            close(vfd);
            continue;
        }

        BIGNUM *priv, *pub;
        dh_generate_keypair(&priv, &pub);
        std::string pb = bn_to_bytes(pub);
        send_frame(vfd, pb);
        std::string sig;
        rsa_sign(sign_key, nonce + pb, sig);   // wrong key!
        send_frame(vfd, sig);
        BN_free(priv); BN_free(pub);

        // the victim will verify our signature
        std::string cbuf;
        if (recv_frame(vfd, cbuf) != 0) {
            std::cout << "              RESULT: victim accepted the (stolen) certificate but\n";
            std::cout << "              rejected proof-of-possession and hung up.\n";
            std::cout << "              -> we hold the cert file but NOT the private key. Attack failed.\n";
        } else {
            std::cout << "victim continued -- check your setup.\n";
        }
        std::cout << std::flush;
        close(vfd);
    }
}
