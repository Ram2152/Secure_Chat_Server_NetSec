#ifndef COMMON_HH
#define COMMON_HH

#include <cstddef>
#include <string>

#define MAX_FRAME 65536       
#define MAX_NAME 64          

int send_all(int fd, const void *buf, size_t n);

int recv_all(int fd, void *buf, size_t n);

int send_frame(int fd, const std::string &data);

int recv_frame(int fd, std::string &out);

#endif
