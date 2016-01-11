
#include "dv_crypto.h"
#include "dv_errno.h"
#include "dv_print.h"

#include <openssl/evp.h>

static void
dv_pem_decode_init(dv_pem_decode_ctx_t *ctx)
{
    ctx->pd_length = 30;
    ctx->pd_num = 0;
    ctx->pd_line_num = 0;
    ctx->pd_expect_nl = 0;
}

int
dv_pem_decode(dv_pem_decode_ctx_t *ctx, void *out, int *outl, void *in, int inl)
{
    int     len = 0;
    int     ret = DV_ERROR;

    dv_pem_decode_init(ctx);

    ret = EVP_DecodeUpdate((EVP_ENCODE_CTX *)ctx, out, outl, in, inl);
    if (ret < 0) {
        DV_PRINT("EVP_DecodeUpdate err!\n");
        return DV_ERROR;
    }

    len = *outl;
    ret = EVP_DecodeFinal((EVP_ENCODE_CTX *)ctx, out, outl);
    if (ret < 0) {
        DV_PRINT("EVP_DecodeUpdate err!\n");
        return DV_ERROR;
    }

    return len;
}


