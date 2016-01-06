
#include "dv_ssl_loc.h"
#include "dv_tls.h"

ds_implement_tls_meth_func(DV_TLS1_2_VERSION, dv_tls_v1_2_client_method,
        dv_undefined_function, dv_ssl_connect_sock,
        dv_tls1_2_client_handshake)
ds_implement_tls_meth_func(DV_TLS1_2_VERSION, dv_tls_v1_2_server_method,
        dv_ssl_accept_sock, dv_undefined_function,
        dv_tls1_2_server_handshake)
