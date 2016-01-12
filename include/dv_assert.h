#ifndef __DV_ASSERT_H__
#define __DV_ASSERT_H__

#include <assert.h>
#include "dv_print.h"

#ifndef RTOS_BIOS6
#define dv_assert(expr) assert(expr)
#else
#define dv_assert(expr) \
    do {\
        if (!expr) { \
            DV_PRINT("%s %d error\n", __FUNCTION__, __LINE__); \
        } \
    } while(0)

#endif

#endif
