
#include "dv_ssl.h"
#include "dv_crypto.h"
#include "dv_errno.h"

dv_ssl_ctx_t *
dv_ssl_ctx_new(const dv_method_t *meth)
{
    dv_ssl_ctx_t    *ctx = NULL;

    ctx = dv_malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->sc_method = meth;

    return ctx;
}

void
dv_ssl_ctx_free(dv_ssl_ctx_t *ctx)
{
    dv_free(ctx);
}

dv_ssl_t *
dv_ssl_new(dv_ssl_ctx_t *ctx)
{
    dv_ssl_t    *ssl = NULL;

    ssl = dv_malloc(sizeof(*ssl));
    if (ssl == NULL) {
        return NULL;
    }

    ssl->ssl_method = ctx->sc_method;
    if (ssl->ssl_method->md_ssl_new(ssl) != DV_OK) {
        goto err;
    }

    ssl->ssl_state = DV_SSL_STATE_INIT;

    return ssl;
err:
    dv_ssl_free(ssl);
    return NULL;
}

void
dv_ssl_free(dv_ssl_t *s)
{
    if (s->ssl_method != NULL) {
        s->ssl_method->md_ssl_free(s);
    }

    dv_free(s);
}

int 
dv_ssl_accept(dv_ssl_t *s)
{
    return s->ssl_method->md_ssl_accept(s);
}

int
dv_ssl_connect(dv_ssl_t *s)
{
    return s->ssl_method->md_ssl_connect(s);
}

int
dv_ssl_set_fd(dv_ssl_t *s, int fd)
{
    s->ssl_fd = fd;

    return DV_OK;
}

int
dv_ssl_read(dv_ssl_t *s, void *buf, dv_u32 len)
{
    return s->ssl_method->md_ssl_read(s, buf, len);
}

int
dv_ssl_write(dv_ssl_t *s, const void *buf, dv_u32 len)
{
    return s->ssl_method->md_ssl_write(s, buf, len);
}

int
dv_ssl_shutdown(dv_ssl_t *s)
{
    return s->ssl_method->md_ssl_shutdown(s);
}

int
dv_ssl_get_message(dv_ssl_t *s, int type)
{
    return s->ssl_method->md_ssl_get_message(s, type);
}

int
dv_library_init(void)
{
    return DV_OK;
}

void
dv_add_all_algorighms(void)
{
    //OpenSSL_add_all_algorithms();
}

void
dv_load_error_strings(void)
{
    //SSL_load_error_strings();
}

int
dv_undefined_function(dv_ssl_t *s)
{
    return DV_OK;
}

