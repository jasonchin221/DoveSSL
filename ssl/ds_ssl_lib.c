
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "ds_ssl.h"
#include "ds_errno.h"

extern void ssl_load_ciphers(void);
extern const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha256(void);
extern const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha256(void);

int
ds_library_init(void)
{
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_cipher(EVP_aes_192_cbc());
    EVP_add_cipher(EVP_aes_256_cbc());
    EVP_add_cipher(EVP_aes_128_gcm());
    EVP_add_cipher(EVP_aes_256_gcm());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
    EVP_add_digest(EVP_ecdsa());

    //ssl_load_ciphers();

    return DS_OK;
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
