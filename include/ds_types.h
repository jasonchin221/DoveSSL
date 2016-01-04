#ifndef __DS_TYPES_H__
#define __DS_TYPES_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define DS_TRUE        1
#define DS_FALSE       0

#define ds_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/*
 * ds_container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define ds_container_of(ptr, type, member) ({          \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

typedef unsigned long           ds_ulong;
typedef unsigned long long      ds_u64;
typedef unsigned int            ds_u32;
typedef unsigned short          ds_u16;
typedef unsigned char           ds_u8;

typedef long                    ds_long;
typedef long long               ds_s64;
typedef int                     ds_s32;
typedef short                   ds_s16;
typedef char                    ds_s8;

typedef bool                    ds_bool;


#endif
