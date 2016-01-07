#include <time.h>

#include "dv_ssl.h"
#include "dv_types.h"
#include "dv_lib.h"

int
dv_bio_get_time_linux(dv_u32 *t)
{
    *t = time(NULL);
    *t = DV_HTONL(*t);

    return 0;
}
