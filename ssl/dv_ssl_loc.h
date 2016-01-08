#ifndef __DV_SSL_LOC_H__
#define __DV_SSL_LOC_H__

#include "dv_ssl.h"
#include "dv_tls.h"

#define dv_implement_tls_meth_func(version, msg_max_len, func_name, \
        accept, connect, hello, parse, get_time, read_f, write_f) \
const dv_method_t *\
func_name(void) \
{ \
    static const dv_method_t func_name##_data = { \
        version, \
        msg_max_len, \
        dv_tls_new, /* md_ssl_new */\
        dv_tls_free, /* md_ssl_free */\
        accept, \
        connect, \
        dv_tls_bio_read, /* md_ssl_read */\
        dv_tls_bio_write, /* md_ssl_write */\
        dv_tls_bio_shutdown, /* md_ssl_shutdown */\
        hello, \
        dv_tls_bio_get_message, \
        parse, \
        get_time, \
        read_f, \
        write_f, \
    }; \
    \
    return &func_name##_data;\
}

extern void dv_tls_get_cipher_suites(dv_u16 *dest, 
            const dv_u16 *suites, dv_u32 num);

#endif
