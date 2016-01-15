#ifndef __DV_BN_H__
#define __DV_BN_H__

#include "dv_types.h"

typedef struct _dv_bn_t {
    dv_u8       *bn_num;
    dv_u32      bn_len;
} dv_bn_t;

#endif
