#include <unistd.h>
#include <sys/socket.h>

#include "dv_ssl.h"
#include "dv_tls.h"
#include "dv_crypto.h"
#include "dv_errno.h"

static int
dv_ssl_do_handshake(dv_ssl_t *s)
{
    void        *buf = NULL;
    dv_u32      len = 0;
    ssize_t     wlen = 0;

    buf = s->ssl_method->md_ssl_handshake(s, &len);
    if (buf == NULL) {
        return DV_ERROR;
    }
    wlen = write(s->ssl_fd, buf, len);
    dv_free(buf);
    if (wlen < len) {
        return DV_ERROR;
    }

    return DV_OK;
}

int
dv_ssl_accept_sock(dv_ssl_t *s)
{
    void            *buf = NULL;
    ssize_t         rlen = 0;

    buf = dv_malloc(DV_TLS_MSG_MAX_LEN);
    if (buf == NULL) {
        return DV_ERROR;
    }

    rlen = read(s->ssl_fd, buf, DV_TLS_MSG_MAX_LEN);
    if (rlen < 0) {
        dv_free(buf);
        return DV_ERROR;
    }
    dv_free(buf);

    return dv_ssl_do_handshake(s);
}

int
dv_ssl_connect_sock(dv_ssl_t *s)
{
    return dv_ssl_do_handshake(s);
}

int
dv_ssl_read_sock(dv_ssl_t *s, void *buf, dv_u32 len)
{
    return read(s->ssl_fd, buf, len);
}

int
dv_ssl_write_sock(dv_ssl_t *s, const void *buf, dv_u32 len)
{
    return write(s->ssl_fd, buf, len);
}

int
dv_ssl_shutdown_sock(dv_ssl_t *s)
{
    return shutdown(s->ssl_fd, SHUT_RDWR);
}
