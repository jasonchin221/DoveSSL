

#include "dv_crypto.h"
#include "dv_ssl.h"
#include "dv_tls.h"

int
dv_tls1_2_client_handshake(dv_ssl_t *s, void *buf, dv_u32 len)
{
    dv_tls_record_proto_header_t    *h = NULL;
    h = buf;
    h->rh_content_type = DV_TLS_CONTENT_TYPE_HANDSHAKE;
    h->rh_version.pv_version = DV_TLS1_2_VERSION;
    h->rh_length = 0;
    
    return sizeof(*h);
}

int
dv_tls1_2_server_handshake(dv_ssl_t *s, void *buf, dv_u32 len)
{
    dv_tls_record_proto_header_t    *h = NULL;

    h = buf;
    h->rh_content_type = DV_TLS_CONTENT_TYPE_HANDSHAKE;
    h->rh_version.pv_version = DV_TLS1_2_VERSION;
    h->rh_length = 0;
    
    return sizeof(*h);
}
