
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

    return ssl;
}

int
dv_ssl_accept(dv_ssl_t *s)
{
    return DV_OK;
}

int
dv_ssl_connect(dv_ssl_t *s)
{
    return DV_OK;
}

void
dv_ssl_free(dv_ssl_t *s)
{
    dv_free(s);
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

