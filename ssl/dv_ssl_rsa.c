
#include "dv_ssl.h"
#include "dv_types.h"
#include "dv_errno.h"
#include "dv_crypto.h"

int 
dv_ssl_ctx_use_certificate_file(dv_ssl_ctx_t *ctx,
        const char *file, dv_u32 type)
{
    void    *pem = NULL;
    int     len = 0;

    len = ctx->sc_method->md_bio_read_file(file, &pem);
    if (len <= 0) {
        return DV_ERROR;
    }

    dv_free(pem);

    return DV_OK;
}

int
dv_ssl_ctx_use_private_key_file(dv_ssl_ctx_t *ctx,
        const char *file, dv_u32 type)
{
    return DV_OK;
}

int
dv_ssl_ctx_check_private_key(const dv_ssl_ctx_t *ctx)
{
    return DV_OK;
}
