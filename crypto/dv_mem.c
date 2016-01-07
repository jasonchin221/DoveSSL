#include <stdlib.h>

#include "dv_print.h"

void *
dv_crypto_malloc(size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    ptr = malloc(num);
    if (ptr == NULL) {
        DV_PRINT("Malloc %d failed!(%s %d)\n", (int)num, file, line);
    }

    return ptr;
}

void *
dv_crypto_calloc(size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    ptr = calloc(1, num);
    if (ptr == NULL) {
        DV_PRINT("Malloc %d failed!(%s %d)\n", (int)num, file, line);
    }

    return ptr;
}

void
dv_crypto_free(void *ptr)
{
    free(ptr);
}
