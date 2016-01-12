#ifndef __DV_SSL_H__
#define __DV_SSL_H__

#include "dv_types.h"

enum {
    DV_SSL_STATE_INIT,
    DV_SSL_STATE_HELLO,
    DV_SSL_STATE_KEY_EXCHANGE,
};

struct _dv_method_t;

typedef struct _dv_ssl_t {
    dv_u32                          ssl_state;
    const struct _dv_method_t       *ssl_method;
    bool                            ssl_server;
    int                             ssl_fd;
    void                            *ssl_ca;
    /* 
     * pointer to handshake message body, set by
     * md_ssl_get_message 
     */
    void                            *ssl_msg;
    int                             ssl_mlen;
    dv_u16                          ssl_cipher_suite;
} dv_ssl_t;

typedef struct _dv_method_t {
    dv_u16      md_version;
    dv_u16      md_msg_max_len;
    int         (*md_ssl_new)(dv_ssl_t *s);
    void        (*md_ssl_free)(dv_ssl_t *s);
    int         (*md_ssl_accept)(dv_ssl_t *s);
    int         (*md_ssl_connect)(dv_ssl_t *s);
    int         (*md_ssl_read)(dv_ssl_t *s, void *buf, dv_u32 len);
//    int         (*md_ssl_peek)(dv_ssl_t *s, void *buf, dv_u32 len);
    int         (*md_ssl_write)(dv_ssl_t *s, const void *buf, dv_u32 len);
    int         (*md_ssl_shutdown)(dv_ssl_t *s);
    int         (*md_ssl_hello)(dv_ssl_t *s);
    int         (*md_ssl_get_message)(dv_ssl_t *s);
    int         (*md_ssl_parse_message)(dv_ssl_t *s);
    int         (*md_bio_get_time)(dv_u32 *t);
    int         (*md_bio_read)(int fd, void *buf, dv_u32 len);
    int         (*md_bio_read_file)(const char *file, void **data);
    int         (*md_bio_write)(int fd, const void *buf, dv_u32 len);
} dv_method_t;

typedef struct _dv_ssl_ctx_t {
    const dv_method_t   *sc_method;
    void                *sc_ca;
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
extern int dv_ssl_set_fd(dv_ssl_t *s, int fd);
extern int dv_ssl_read(dv_ssl_t *s, void *buf, dv_u32 len);
extern int dv_ssl_write(dv_ssl_t *s, const void *buf, dv_u32 len);
extern int dv_ssl_shutdown(dv_ssl_t *s);
extern int dv_ssl_get_message(dv_ssl_t *s);

extern int dv_undefined_function(dv_ssl_t *s);

extern int dv_ssl_ctx_use_certificate_file(dv_ssl_ctx_t *ctx,
            const char *file, dv_u32 type);
extern int dv_ssl_ctx_use_private_key_file(dv_ssl_ctx_t *ctx,
            const char *file, dv_u32 type);
extern int dv_ssl_ctx_check_private_key(const dv_ssl_ctx_t *ctx);

#endif
