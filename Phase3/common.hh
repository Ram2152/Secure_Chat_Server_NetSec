/* common.hh - length-prefixed TCP framing and small helpers.
 *
 * TCP is a byte stream, not a message stream: a single read() may return
 * half a message or several messages glued together. To recover message
 * boundaries we prefix every payload with a 4-byte big-endian length. The
 * receiver first reads exactly 4 bytes (the length N), then reads exactly N
 * bytes of payload. A message is "complete" when those N bytes have arrived.
 *
 * This same framing is reused unchanged in every phase. In Phase 1 the payload
 * is plaintext; from Phase 2 on the payload is an AES-GCM ciphertext blob.
 */
#ifndef COMMON_HH
#define COMMON_HH

#include <cstddef>
#include <string>

#define MAX_FRAME   65536       /* max payload we will accept in one frame   */
#define MAX_NAME    64          /* max username length                       */

/* Write exactly n bytes; returns 0 on success, -1 on error/EOF. */
int send_all(int fd, const void *buf, size_t n);

/* Read exactly n bytes; returns 0 on success, -1 on error/EOF. */
int recv_all(int fd, void *buf, size_t n);

/* Send one framed message: [4-byte BE length][payload]. */
int send_frame(int fd, const std::string &data);

/* Receive one framed message. On success stores the payload in `out` and
 * returns 0. Returns -1 on error/EOF or if the advertised length exceeds
 * MAX_FRAME. */
int recv_frame(int fd, std::string &out);

#endif /* COMMON_HH */
