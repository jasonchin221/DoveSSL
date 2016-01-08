#ifndef __DV_TLS_H__
#define __DV_TLS_H__

#include "dv_ssl.h"

#define DV_TLS1_0_VERSION                   0x0301
#define DV_TLS1_2_VERSION                   0x0303
#define DV_TLS1_3_VERSION                   0x0304
#define DV_TLS_MAX_VERSION                  DV_TLS1_3_VERSION

#define DV_TLS_MSG_MAX_LEN                  1024

#define DV_TLS_RANDOM_BYTES_LEN             28

#define DV_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384        (0xc030)
#define DV_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        (0xc02f)
#define DV_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      (0xc02c)
#define DV_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      (0xc02b)

#define DV_TLS_RSA_WITH_AES_256_GCM_SHA384              (0x009d)
#define DV_TLS_RSA_WITH_AES_256_CBC_SHA256              (0x003d)
#define DV_TLS_RSA_WITH_AES_128_GCM_SHA256              (0x009c)
#define DV_TLS_RSA_WITH_AES_128_CBC_SHA256              (0x003c)

typedef enum _DV_TLS_CONTENT_TYPE_E {
    DV_TLS_CONTENT_TYPE_ALERT = 21,
    DV_TLS_CONTENT_TYPE_HANDSHAKE = 22,
    DV_TLS_CONTENT_TYPE_APPLICATION_DATA = 23,
    DV_TLS_CONTENT_TYPE_MAX = 255,
} DV_TLS_CONTENT_TYPE_E;

typedef enum _DV_TLS_HANDSHAKE_TYPE_E {
    DV_TLS_HANDSHAKE_TYPE_HELLO_REQUEST = 0,
    DV_TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 1,
    DV_TLS_HANDSHAKE_TYPE_SERVER_HELLO = 2,
    DV_TLS_HANDSHAKE_TYPE_SESSION_TICKET = 4,
    DV_TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST = 6,
    DV_TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8,
    DV_TLS_HANDSHAKE_TYPE_CERTIFICATE = 11,
    DV_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12,
    DV_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13,
    DV_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14,
    DV_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15,
    DV_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16,
    DV_TLS_HANDSHAKE_TYPE_SERVER_CONFIGURATION = 17,
    DV_TLS_HANDSHAKE_TYPE_FINISHED = 20,
    DV_TLS_HANDSHAKE_TYPE_KEY_UPDATE = 20,
    DV_TLS_HANDSHAKE_TYPE_MAX = 255,
} DV_TLS_HANDSHAKE_TYPE_E; 

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

typedef struct _dv_tls_record_header_t {
    dv_u8                   rh_content_type;
    dv_proto_version_t      rh_version;
    dv_u16                  rh_length;
} dv_tls_record_header_t;


typedef struct _dv_tls_handshake_header_t {
    dv_u8                   hh_msg_type;
    dv_u8                   hh_length[3];
} dv_tls_handshake_header_t;

typedef struct _dv_tlsv1_2_random_t {
    dv_u32      rd_gmt_unix_time;
    dv_u8       rd_random_bytes[DV_TLS_RANDOM_BYTES_LEN];
} dv_tlsv1_2_random_t;

typedef struct _dv_tlsv1_2_client_hello_t {
    dv_proto_version_t          ch_version;
    dv_tlsv1_2_random_t         ch_random;
    dv_u8                       ch_session_id;
} dv_tlsv1_2_client_hello_t;

extern int dv_tls_bio_accept(dv_ssl_t *s);
extern int dv_tls_bio_connect(dv_ssl_t *s);
extern int dv_tls_bio_read(dv_ssl_t *s, void *buf, dv_u32 len);
extern int dv_tls_bio_write(dv_ssl_t *s, const void *buf, dv_u32 len);
extern int dv_tls_bio_shutdown(dv_ssl_t *s);
extern int dv_tls_bio_get_message(dv_ssl_t *s);
extern const dv_method_t *dv_tls_v1_2_client_method(void);  /* TLSv1.2 */
extern const dv_method_t *dv_tls_v1_2_server_method(void);  /* TLSv1.2 */
extern int dv_tls_new(dv_ssl_t *s);
extern void dv_tls_free(dv_ssl_t *s);
extern int dv_tls1_2_client_hello(dv_ssl_t *s);
extern int dv_tls1_2_server_hello(dv_ssl_t *s);
extern int dv_tls1_2_client_parse_msg(dv_ssl_t *s);
extern int dv_tls1_2_server_parse_msg(dv_ssl_t *s);

#endif
