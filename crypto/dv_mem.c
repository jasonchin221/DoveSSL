#include <stdlib.h>

void *
dv_crypto_malloc(size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    ptr = malloc(num);

    return ptr;
}

void
dv_crypto_free(void *ptr)
{
}
