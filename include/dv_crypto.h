#ifndef __DV_CRYPTO_H__
#define __DV_CRYPTO_H__

#include <sys/types.h>

extern void *dv_crypto_malloc(size_t num, const char *file, int line);
extern void dv_crypto_free(void *ptr);

#define dv_malloc(size)     dv_crypto_malloc(size, __FUNCTION__, __LINE__)
#define dv_free(ptr)        dv_crypto_free(ptr)

#endif
