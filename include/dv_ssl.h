#ifndef __DV_SSL_H__
#define __DV_SSL_H__

#include "dv_types.h"

struct _dv_method_t;

typedef struct _dv_ssl_t {
    dv_u32                          ssl_state;
    const struct _dv_method_t       *ssl_method;
    int                             ssl_fd;
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
    void        *(*md_ssl_handshake)(dv_ssl_t *s, dv_u32 *len);
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

extern int dv_ssl_accept_sock(dv_ssl_t *s);
extern int dv_ssl_connect_sock(dv_ssl_t *s);
extern int dv_ssl_read_sock(dv_ssl_t *s, void *buf, dv_u32 len);
extern int dv_ssl_write_sock(dv_ssl_t *s, const void *buf, dv_u32 len);
extern int dv_ssl_shutdown_sock(dv_ssl_t *s);


extern int dv_ssl_accept(dv_ssl_t *s);
extern int dv_ssl_connect(dv_ssl_t *s);
extern int dv_ssl_set_fd(dv_ssl_t *s, int fd);
extern int dv_ssl_read(dv_ssl_t *s, void *buf, dv_u32 len);
extern int dv_ssl_write(dv_ssl_t *s, const void *buf, dv_u32 len);
extern int dv_ssl_shutdown(dv_ssl_t *s);

extern int dv_undefined_function(dv_ssl_t *s);

extern int dv_ssl_ctx_use_certificate_file(dv_ssl_ctx_t *ctx,
            const char *file, dv_u32 type);
extern int dv_ssl_ctx_use_private_key_file(dv_ssl_ctx_t *ctx,
            const char *file, dv_u32 type);
extern int dv_ssl_ctx_check_private_key(const dv_ssl_ctx_t *ctx);

#endif
