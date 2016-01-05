
#include "dv_ssl.h"
#include "dv_tls.h"

ds_implement_tls_meth_func(DV_TLS1_2_VERSION, dv_tls_v1_2_client_method,
        dv_undefined_function, dv_ssl_connect);
ds_implement_tls_meth_func(DV_TLS1_2_VERSION, dv_tls_v1_2_server_method,
        dv_ssl_accept, dv_undefined_function);
