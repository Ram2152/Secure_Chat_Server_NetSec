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

struct client_t {
    int fd = -1;
    std::string name;
    AesKey key{};
    bool active = false;
};

client_t clients[MAX_CLIENTS];
std::mutex lock;

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
    std::lock_guard<std::mutex> lk(lock);
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].active && clients[i].name == name)
            return -1;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (!clients[i].active) {
            clients[i].fd = fd;
            clients[i].active = true;
            clients[i].key = key;
            clients[i].name = name;
            return i;
        }
    return -1;
}

void unregister_client(int idx) {
    std::lock_guard<std::mutex> lk(lock);
    clients[idx].active = false;
    clients[idx].name.clear();
}

int relay_to(const std::string &target, const std::string &from, const std::string &text) {
    std::string out = "MSG " + from + " " + text;
    std::lock_guard<std::mutex> lk(lock);
    int rc = -1;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].active && clients[i].name == target) {
            rc = send_enc(clients[i].fd, clients[i].key, out);
            break;
        }
    return rc;
}

void send_who(int fd, const AesKey &key) {
    std::string csv = "WHO ";
    {
        std::lock_guard<std::mutex> lk(lock);
        bool first = true;
        for (int i = 0; i < MAX_CLIENTS; i++)
            if (clients[i].active) {
                if (!first) csv += ",";
                csv += clients[i].name;
                first = false;
            }
    }
    send_enc(fd, key, csv);
}

bool do_dh(int fd, AesKey &key, const std::string &who) {
    std::string cbuf;
    if (recv_frame(fd, cbuf) != 0)
	    return false;
    BIGNUM *client_pub = bn_from_bytes(cbuf);

    BIGNUM *priv, *pub;
    if (dh_generate_keypair(&priv, &pub) != 0) {
	    BN_free(client_pub);
	    return false;
    }
    
    if (send_frame(fd, bn_to_bytes(pub)) != 0) {
        BN_free(client_pub);
	BN_free(priv);
	BN_free(pub);
	return false;
    }

    std::string secret = dh_compute_shared(client_pub, priv);
    key = derive_key(secret);

    std::cout << "[dh] " << who << ": shared-secret fingerprint = " << fingerprint_hex(secret, 8) << "\n" << std::flush;

    BN_free(client_pub);
    BN_free(priv);
    BN_free(pub);
    return true;
}

void client_thread(int fd)
{
    AesKey key{};
    if (!do_dh(fd, key, "new client")) {
	    close(fd); return;
    }

    std::string frame;
    int idx = -1;
    std::string myname = "?";

    int r = recv_enc(fd, key, frame);
    if (r != 0) {
	    close(fd); return;
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
        std::cout << "[+] " << myname << " connected (encrypted)\n" << std::flush;
    } else {
        send_enc(fd, key, "ERR expected LOGIN");
        close(fd);
        return;
    }

    for (;;) {
        r = recv_enc(fd, key, frame);
        if (r == -1) break;                     
        if (r == -2) {                          
            std::cout << "[!] " << myname << ": dropped a tampered/forged frame (auth failed)\n" << std::flush;
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
            std::cout << "[relay] " << myname << " -> " << target << " : " << text << "\n" << std::flush;   /* server reads plaintext */
            
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
    if (argc != 2) {
	    std::cerr << "usage: " << argv[0] << " <port>\n";
	    return 1;
    }
    
    int port = std::stoi(argv[1]);
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
    
    std::cout << "server listening on port " << port << "\n" << std::flush;

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
