
#include <openssl/ssl.h>
#include "ds_ssl.h"

int
ds_library_init(void)
{
    return SSL_library_init();
}

void
ds_add_all_algorighms(void)
{
    OpenSSL_add_all_algorithms();
}

void
ds_load_error_strings(void)
{
    SSL_load_error_strings();
}
