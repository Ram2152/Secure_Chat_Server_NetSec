#include "common.hh"
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
    bool active = false;
};

client_t clients[MAX_CLIENTS];
std::mutex lock;

bool starts_with(const std::string &s, const std::string &prefix) {
    return s.compare(0, prefix.size(), prefix) == 0;
}

int register_client(int fd, const std::string &name) {
    std::lock_guard<std::mutex> lk(lock);

    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].active && clients[i].name == name)
            return -1;                        // name already taken
    
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (!clients[i].active) {
            clients[i].fd = fd;
            clients[i].active = true;
            clients[i].name = name;
            return i;
        }
    
    return -1;                                // table full
}

void unregister_client(int idx) {
    std::lock_guard<std::mutex> lk(lock);
    clients[idx].active = false;
    clients[idx].name.clear();
}

int send_line(int fd, const std::string &line) {
    return send_frame(fd, line);
}

int relay_to(const std::string &target, const std::string &from, const std::string &text) {
    std::string out = "MSG " + from + " " + text;
    std::lock_guard<std::mutex> lk(lock);
    int rc = -1;

    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].active && clients[i].name == target) {
            rc = send_line(clients[i].fd, out);                   // send only if target is online
            break;
        }
    return rc;
}

void send_who(int fd) {
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
    send_line(fd, csv);
}

void client_thread(int fd)
{
    std::string frame;
    int idx = -1;
    std::string myname = "?";

    if (recv_frame(fd, frame) != 0) {
	    close(fd); return;
    }
    if (starts_with(frame, "LOGIN ")) {
        std::string name = frame.substr(6);
        
	if (name.size() >= MAX_NAME)
		name.resize(MAX_NAME - 1);
        
	idx = register_client(fd, name);
        
	if (idx < 0) {
		send_line(fd, "ERR name in use or server full");
		close(fd);
		return;
	}
        
	myname = name;
        send_line(fd, "OK logged in");
        std::cout << "[+] " << myname << " connected (fd=" << fd << ")\n" << std::flush;
    } else {
        send_line(fd, "ERR expected LOGIN first");
        close(fd);
        return;
    }

    while (recv_frame(fd, frame) == 0) {
        if (starts_with(frame, "MSG ")) {
            std::string rest = frame.substr(4);
            size_t sp = rest.find(' ');
            
	    if (sp == std::string::npos) {
		    send_line(fd, "ERR malformed MSG");
		    continue;
	    }
            
	    std::string target = rest.substr(0, sp);
            std::string text   = rest.substr(sp + 1);
            std::cout << "[relay] " << myname << " -> " << target << " : " << text << "\n" << std::flush;
            
	    if (relay_to(target, myname, text) != 0)
                send_line(fd, "ERR user not online");
        } else if (frame == "WHO") {
            send_who(fd);
        } else if (frame == "QUIT") {
            break;
        } else {
            send_line(fd, "ERR unknown command");
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
        
	if (fd < 0) continue;
        
	std::cout << "[*] connection from " << inet_ntoa(cli.sin_addr) << ":" << ntohs(cli.sin_port) << "\n" << std::flush;
        std::thread t(client_thread, fd);
        t.detach();
    }
}
