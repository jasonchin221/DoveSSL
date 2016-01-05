#ifndef __DV_TLS_H__
#define __DV_TLS_H__

#include "dv_ssl.h"

#define DV_TLS1_2_VERSION                   0x0303
#define DV_TLS_MAX_VERSION                  DV_TLS1_2_VERSION

const dv_method_t *dv_tls_v1_2_client_method(void);  /* TLSv1.2 */
const dv_method_t *dv_tls_v1_2_server_method(void);  /* TLSv1.2 */

#endif
