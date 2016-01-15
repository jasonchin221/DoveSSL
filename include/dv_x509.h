#ifndef __DV_X509_H__
#define __DV_X509_H__

#include "dv_types.h"

typedef struct _dv_x509_t {
    dv_u32      x509_version;
    void        *x509_store;
} dv_x509_t;

extern int dv_d2i_x509(dv_x509_t *x509, const dv_u8 *data, dv_u32 len);

#endif
