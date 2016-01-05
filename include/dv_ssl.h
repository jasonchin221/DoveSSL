#ifndef __DV_SSL_H__
#define __DV_SSL_H__

#include "dv_types.h"

typedef struct _dv_ssl_t {
    dv_u32      ssl_state;
} dv_ssl_t;

typedef struct _dv_method_t {
    dv_u32      md_version;
    int         (*md_ssl_new)(dv_ssl_t *s);
    void        (*md_ssl_free)(dv_ssl_t *s);
    int         (*md_ssl_accept)(dv_ssl_t *s);
    int         (*md_ssl_connect)(dv_ssl_t *s);
    int         (*md_ssl_read)(dv_ssl_t *s, void *buf, dv_u32 len);
//    int         (*md_ssl_peek)(dv_ssl_t *s, void *buf, dv_u32 len);
    int         (*md_ssl_write)(dv_ssl_t *s, const void *buf, dv_u32 len);
    int         (*md_ssl_shutdown)(dv_ssl_t *s);
} dv_method_t;

typedef struct _dv_ssl_ctx_t {
    const dv_method_t   *sc_method;
} dv_ssl_ctx_t; 

extern dv_ssl_ctx_t *dv_ssl_ctx_new(const dv_method_t *meth);
extern void dv_ssl_ctx_free(dv_ssl_ctx_t *ctx);

extern dv_ssl_t *dv_ssl_new(dv_ssl_ctx_t *ctx);
extern void dv_ssl_free(dv_ssl_t *s);

extern int dv_library_init(void);
extern void dv_add_all_algorighms(void);
extern void dv_load_error_strings(void);

extern int dv_ssl_accept(dv_ssl_t *s);
extern int dv_ssl_connect(dv_ssl_t *s);
extern int dv_undefined_function(dv_ssl_t *s);

#define ds_implement_tls_meth_func(version, func_name, s_accept, s_connect) \
const dv_method_t *\
func_name(void) \
{ \
    static const dv_method_t func_name##_data = { \
        version, \
        NULL, /* md_ssl_new */\
        NULL, /* md_ssl_free */\
        s_accept, \
        s_connect, \
        NULL, /* md_ssl_read */\
        NULL, /* md_ssl_write */\
        NULL, /* md_ssl_shutdown */\
    }; \
    \
    return &func_name##_data;\
}

#endif
