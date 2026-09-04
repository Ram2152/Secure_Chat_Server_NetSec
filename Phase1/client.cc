#include "common.hh"
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
std::string partner;
std::mutex plock;

bool starts_with(const std::string &s, const std::string &prefix) {
    return s.compare(0, prefix.size(), prefix) == 0;
}

int send_line(const std::string &line) {
    return send_frame(fd, line);
}

void recv_thread() {
    std::string line;
    while (recv_frame(fd, line) == 0) {
        if (starts_with(line, "MSG ")) {
            std::string rest = line.substr(4);
            size_t sp = rest.find(' ');
            if (sp != std::string::npos)
                std::cout << "\n[" << rest.substr(0, sp) << "] " << rest.substr(sp + 1) << "\n> ";
        } 
        else if (starts_with(line, "WHO ")) {
            std::cout << "\n[online] " << line.substr(4) << "\n> ";
        } 
        else if (starts_with(line, "OK ")) {
            std::cout << "[server] " << line.substr(3) << "\n> ";
        } 
        else if (starts_with(line, "ERR ")) {
            std::cout << "\n[error] " << line.substr(4) << "\n> ";
        } 
        else {
            std::cout << "\n[server] " << line << "\n> ";
        }
        std::cout << std::flush;
    }
    std::cout << "\n[disconnected from server]\n";
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " <server_ip> <server_port> <username>\n";
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

    send_line("LOGIN " + user);

    std::thread t(recv_thread);
    t.detach();

    std::cout << "Connected as '" << user << "'. Commands: @user msg | /chat user | /who | /quit\n> " << std::flush;

    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) { std::cout << "> " << std::flush; continue; }

        if (line == "/quit") {
            send_line("QUIT");
            break;
        } 
        else if (line == "/who") {
            send_line("WHO");
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
            if (!text.empty()) {
                send_line("MSG " + target + " " + text);
            } 
            else {
                std::cout << "[now chatting with " << target << "]\n";
            }
            std::cout << "> " << std::flush;
        } 
        else {
            std::string target;
            {
                std::lock_guard<std::mutex> lk(plock);
                target = partner;
            }
            if (target.empty()) {
                std::cout << "[no partner selected - use @user or /chat user]\n> " << std::flush;
            } 
            else {
                send_line("MSG " + target + " " + line);
                std::cout << "> " << std::flush;
            }
        }
    }
    close(fd);
    return 0;
}
