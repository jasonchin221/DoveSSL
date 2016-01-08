#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

#include "dv_errno.h"
#include "dv_types.h"
#include "dv_ssl.h"
#include "dv_lib.h"

int
dv_bio_read_sock(int fd, void *buf, dv_u32 len)
{
    return read(fd, buf, len);
}

int
dv_bio_write_sock(int fd, const void *buf, dv_u32 len)
{
    return write(fd, buf, len);
}

int
dv_bio_get_time_linux(dv_u32 *t)
{
    *t = time(NULL);
    *t = DV_HTONL(*t);

    return 0;
}
