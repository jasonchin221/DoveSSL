#include <unistd.h>
#include <sys/socket.h>

#include "dv_errno.h"
#include "dv_types.h"

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

