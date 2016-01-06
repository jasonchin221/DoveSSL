#ifndef __DV_TLS_H__
#define __DV_TLS_H__

#include "dv_ssl.h"

#define DV_TLS1_0_VERSION                   0x0301
#define DV_TLS1_2_VERSION                   0x0303
#define DV_TLS1_3_VERSION                   0x0304
#define DV_TLS_MAX_VERSION                  DV_TLS1_3_VERSION

#define DV_TLS_MSG_MAX_LEN                  1024

typedef enum _DV_TLS_CONTENT_TYPE_E {
    DV_TLS_CONTENT_TYPE_ALERT = 21,
    DV_TLS_CONTENT_TYPE_HANDSHAKE = 22,
    DV_TLS_CONTENT_TYPE_APPLICATION_DATA = 23,
} DV_TLS_CONTENT_TYPE_E;

#pragma pack (1)

typedef struct _dv_proto_version_t {
    union {
        dv_u16  pv_version;
        struct {
            dv_u8   pv_major;
            dv_u8   pv_minor;
        };
    };
} dv_proto_version_t;

typedef struct _dv_tls_record_proto_header_t {
    dv_u8                   rh_content_type;
    dv_proto_version_t      rh_version;
    dv_u16                  rh_length;
} dv_tls_record_proto_header_t;


extern const dv_method_t *dv_tls_v1_2_client_method(void);  /* TLSv1.2 */
extern const dv_method_t *dv_tls_v1_2_server_method(void);  /* TLSv1.2 */
extern int dv_tls1_new(dv_ssl_t *s);
extern void dv_tls1_free(dv_ssl_t *s);
extern void *dv_tls1_2_client_handshake(dv_ssl_t *s, dv_u32 *len);
extern void *dv_tls1_2_server_handshake(dv_ssl_t *s, dv_u32 *len);

#endif
