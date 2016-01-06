#ifndef __DV_SSL_LOC_H__
#define __DV_SSL_LOC_H__

#include "dv_ssl.h"
#include "dv_tls.h"

#define ds_implement_tls_meth_func(version, func_name, accept, connect, \
        handshake) \
const dv_method_t *\
func_name(void) \
{ \
    static const dv_method_t func_name##_data = { \
        version, \
        dv_tls1_new, /* md_ssl_new */\
        dv_tls1_free, /* md_ssl_free */\
        accept, \
        connect, \
        dv_ssl_read_sock, /* md_ssl_read */\
        dv_ssl_write_sock, /* md_ssl_write */\
        dv_ssl_shutdown_sock, /* md_ssl_shutdown */\
        handshake, \
    }; \
    \
    return &func_name##_data;\
}


#endif
