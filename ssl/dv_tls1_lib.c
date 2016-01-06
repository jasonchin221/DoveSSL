
#include "dv_ssl.h"
#include "dv_crypto.h"
#include "dv_errno.h"

int
dv_tls1_new(dv_ssl_t *s)
{
    s->ssl_msg = dv_malloc(s->ssl_method->md_msg_max_len);
    if (s->ssl_msg == NULL) {
        return DV_ERROR;
    }

    return DV_OK;
}

void
dv_tls1_free(dv_ssl_t *s)
{
    if (s->ssl_msg) {
        dv_free(s->ssl_msg);
    }
}
