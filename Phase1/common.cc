#include "common.hh"

#include <unistd.h>
#include <cerrno>
#include <arpa/inet.h>

int send_all(int fd, const void *buf, size_t n)
{
    const char *p = static_cast<const char *>(buf);
    size_t sent = 0;
    while (sent < n) {
        ssize_t k = write(fd, p + sent, n - sent);
        if (k < 0) {
            if (errno == EINTR) continue;   // retry on signal
            return -1;
        }
        if (k == 0) return -1;              // connection closed
        sent += k;
    }
    return 0;
}

int recv_all(int fd, void *buf, size_t n)
{
    char *p = static_cast<char *>(buf);
    size_t got = 0;
    while (got < n) {
        ssize_t k = read(fd, p + got, n - got);
        if (k < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (k == 0) return -1;              // peer closed (EOF)
        got += k;
    }
    return 0;
}

int send_frame(int fd, const std::string &data)
{
    int netlen = htonl(data.size());
    if (send_all(fd, &netlen, 4) != 0) return -1;
    if (!data.empty() && send_all(fd, data.data(), data.size()) != 0) return -1;
    return 0;
}

int recv_frame(int fd, std::string &out)
{
    int netlen;
    if (recv_all(fd, &netlen, 4) != 0) return -1;
    int len = ntohl(netlen);
    if (len < 0 || len > MAX_FRAME) return -1;   // refuse oversized/bad frames
    out.resize(len);
    if (len > 0 && recv_all(fd, &out[0], len) != 0) return -1;
    return 0;
}
