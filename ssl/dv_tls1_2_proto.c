

#include "dv_crypto.h"
#include "dv_ssl.h"
#include "dv_tls.h"

void *
dv_tls1_2_client_handshake(dv_ssl_t *s, dv_u32 *len)
{
    dv_tls_record_proto_header_t    *h = NULL;
    void                            *buf = NULL;

    buf = dv_malloc(DV_TLS_MSG_MAX_LEN);
    if (buf == NULL) {
        return NULL;
    }

    h = buf;
    h->rh_content_type = DV_TLS_CONTENT_TYPE_HANDSHAKE;
    h->rh_version.pv_version = DV_TLS1_2_VERSION;
    h->rh_length = 0;
    
    *len = sizeof(*h);

    return buf;
}

void *
dv_tls1_2_server_handshake(dv_ssl_t *s, dv_u32 *len)
{
    dv_tls_record_proto_header_t    *h = NULL;
    void                            *buf = NULL;

    buf = dv_malloc(DV_TLS_MSG_MAX_LEN);
    if (buf == NULL) {
        return NULL;
    }

    h = buf;
    h->rh_content_type = DV_TLS_CONTENT_TYPE_HANDSHAKE;
    h->rh_version.pv_version = DV_TLS1_2_VERSION;
    h->rh_length = 0;
    
    *len = sizeof(*h);

    return buf;
}
