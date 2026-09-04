#include "common.hh"
#include "crypto.hh"
#include <string>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_CLIENTS 16
const int NONCE_LEN = 32;

struct client_t {
    int fd = -1;
    std::string name;
    AesKey key{};
    bool active = false;
};

client_t g_clients[MAX_CLIENTS];
std::mutex g_lock;

std::string g_cert_pem;
EVP_PKEY    *g_srv_key;

bool starts_with(const std::string &s, const std::string &prefix) {
    return s.compare(0, prefix.size(), prefix) == 0;
}

int send_enc(int fd, const AesKey &key, const std::string &line) {
    std::string blob;
    if (!aes_gcm_seal(key, line, blob))
	    return -1;
    return send_frame(fd, blob);
}

int recv_enc(int fd, const AesKey &key, std::string &out) {
    std::string blob;
    if (recv_frame(fd, blob) != 0)
	    return -1;
    if (!aes_gcm_open(key, blob, out))
	    return -2;
    return 0;
}

int register_client(int fd, const std::string &name, const AesKey &key) {
    std::lock_guard<std::mutex> lk(g_lock);
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (g_clients[i].active && g_clients[i].name == name)
		return -1;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (!g_clients[i].active) {
            g_clients[i].fd = fd;
            g_clients[i].active = true;
            g_clients[i].key = key;
            g_clients[i].name = name;
            return i;
        }
    return -1;
}

void unregister_client(int idx) {
    std::lock_guard<std::mutex> lk(g_lock);
    g_clients[idx].active = false;
    g_clients[idx].name.clear();
}

int relay_to(const std::string &target, const std::string &from, const std::string &text) {
    std::string out = "MSG " + from + " " + text;
    std::lock_guard<std::mutex> lk(g_lock);
    int rc = -1;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (g_clients[i].active && g_clients[i].name == target) {
            rc = send_enc(g_clients[i].fd, g_clients[i].key, out);
            break;
        }
    return rc;
}

void send_who(int fd, const AesKey &key) {
    std::string csv = "WHO ";
    {
        std::lock_guard<std::mutex> lk(g_lock);
        bool first = true;
        for (int i = 0; i < MAX_CLIENTS; i++)
            if (g_clients[i].active) {
                if (!first) csv += ",";
                csv += g_clients[i].name;
                first = false;
            }
    }
    send_enc(fd, key, csv);
}

bool do_handshake(int fd, AesKey &key)
{
    // send certificate
    if (send_frame(fd, g_cert_pem) != 0)
	    return false;

    // receive challenge nonce
    std::string nonce;
    if (recv_frame(fd, nonce) != 0 || nonce.size() != (size_t)NONCE_LEN)
	    return false;

    // our DH public value
    BIGNUM *priv, *pub;
    if (dh_generate_keypair(&priv, &pub) != 0)
	    return false;
    
    std::string pubbuf = bn_to_bytes(pub);
    
    if (send_frame(fd, pubbuf) != 0) {
	    BN_free(priv);
	    BN_free(pub);
	    return false;
    }

    // sign (nonce || server_pub) with our private key
    std::string sig;
    if (!rsa_sign(g_srv_key, nonce + pubbuf, sig)) {
	    BN_free(priv);
	    BN_free(pub);
	    return false;
    }

    if (send_frame(fd, sig) != 0) {
	    BN_free(priv);
	    BN_free(pub);
	    return false;
    }

    // client DH public value
    std::string cbuf;
    if (recv_frame(fd, cbuf) != 0) {
	    BN_free(priv);
	    BN_free(pub);
	    return false; 
    }
    
    BIGNUM *client_pub = bn_from_bytes(cbuf);

    // shared secret -> key
    std::string secret = dh_compute_shared(client_pub, priv);
    key = derive_key(secret);
    std::cout << "[dh] shared-secret fingerprint = " << fingerprint_hex(secret, 8) << "\n" << std::flush;

    BN_free(priv);
    BN_free(pub);
    BN_free(client_pub);
    return true;
}

void client_thread(int fd)
{
    AesKey key{};
    if (!do_handshake(fd, key)) {
        std::cout << "[!] handshake with a client failed/aborted\n" << std::flush;
        close(fd);
        return;
    }

    std::string frame;
    int idx = -1;
    std::string myname = "?";
    int r = recv_enc(fd, key, frame);
    
    if (r != 0) {
	    close(fd);
	    return;
    }
    
    if (starts_with(frame, "LOGIN ")) {
        std::string name = frame.substr(6);
        
	if (name.size() >= MAX_NAME)
		name.resize(MAX_NAME - 1);
        
	idx = register_client(fd, name, key);
        
	if (idx < 0) {
		send_enc(fd, key, "ERR name in use or server full");
		close(fd);
		return;
	}
        
	myname = name;
        send_enc(fd, key, "OK logged in");
        std::cout << "[+] " << myname << " connected\n" << std::flush;
    } else {
        send_enc(fd, key, "ERR expected LOGIN");
        close(fd);
        return;
    }

    for (;;) {
        r = recv_enc(fd, key, frame);
        if (r == -1)
		break;
        if (r == -2) {
		std::cout << "[!] " << myname << ": dropped tampered frame\n" << std::flush;
		continue;
	}
        if (starts_with(frame, "MSG ")) {
            std::string rest = frame.substr(4);
            size_t sp = rest.find(' ');

            if (sp == std::string::npos) {
		    send_enc(fd, key, "ERR malformed MSG");	
		    continue;
	    }
            
	    std::string target = rest.substr(0, sp);
            std::string text   = rest.substr(sp + 1);
            std::cout << "[relay] " << myname << " -> " << target << " : " << text << "\n" << std::flush;
            
	    if (relay_to(target, myname, text) != 0)
		    send_enc(fd, key, "ERR user not online");
        } else if (frame == "WHO") {
            send_who(fd, key);
        } else if (frame == "QUIT") {
            break;
        } else {
            send_enc(fd, key, "ERR unknown command");
        }
    }
    if (idx >= 0) {
        unregister_client(idx);
        std::cout << "[-] " << myname << " disconnected\n" << std::flush;
    }
    close(fd);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
	    std::cerr << "usage: " << argv[0] << " <port> <server_cert.pem> <server_key.pem>\n";
	    return 1;
    }
    
    int port = std::stoi(argv[1]);
    
    if (!read_file(argv[2], g_cert_pem) || g_cert_pem.empty()) {
        std::cerr << "cannot read cert " << argv[2] << "\n";
        return 1;
    }
    
    g_srv_key = load_privkey_file(argv[3]);
    
    if (!g_srv_key) {
	    std::cerr << "cannot read key " << argv[3] << "\n";
	    return 1;
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    struct sockaddr_in addr = {0};
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) < 0) {
        std::cerr << "bind: " << strerror(errno) << "\n";
        return 1;
    }
    
    if (listen(s, 8) < 0) {
        std::cerr << "listen: " << strerror(errno) << "\n";
        return 1;
    }
    
    std::cout << "server on port " << port << "\n" << std::flush;

    for (;;) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof cli;
        int fd = accept(s, (struct sockaddr *)&cli, &cl);
        if (fd < 0)
		continue;
        std::cout << "[*] connection from " << inet_ntoa(cli.sin_addr) << ":" << ntohs(cli.sin_port) << "\n" << std::flush;
        std::thread t(client_thread, fd);
        t.detach();
    }
}
