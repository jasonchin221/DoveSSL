
#include "dv_ssl_loc.h"
#include "dv_tls.h"
#include "dv_bio.h"

ds_implement_tls_meth_func(DV_TLS1_2_VERSION, DV_TLS_MSG_MAX_LEN, 
        dv_tls_v1_2_client_method, dv_undefined_function, dv_tls_bio_connect,
        dv_tls1_2_client_handshake, dv_bio_read_sock, dv_bio_write_sock)
ds_implement_tls_meth_func(DV_TLS1_2_VERSION, DV_TLS_MSG_MAX_LEN,
        dv_tls_v1_2_server_method, dv_tls_bio_accept, dv_undefined_function,
        dv_tls1_2_server_handshake, dv_bio_read_sock, dv_bio_write_sock)
