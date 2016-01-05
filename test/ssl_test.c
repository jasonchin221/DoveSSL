#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>

#include "ds_types.h"
#include "ds_lib.h"
#include "ds_errno.h"
#include "ds_ssl.h"
#include "ssl_test.h"

#define DS_DEF_IP_ADDRESS       "127.0.0.1"
#define DS_DEF_PORT             "7838"
#define DS_SERVER_LISTEN_NUM    5
#define DS_TEST_REQ             "Hello TLS!"
#define DS_TEST_RESP            "TLS OK!"
#define DS_TEST_EVENT_MAX_NUM   10
#define DS_TEST_CMD_START       "start"
#define DS_TEST_CMD_OK          "OK"
#define DS_TEST_CMD_END         "end"
#define DS_BUF_MAX_LEN          1000

static void ds_openssl_add_all_algorighms(void);
static void *ds_openssl_ctx_client_new(void);
static void *ds_openssl_ctx_server_new(void);
static int ds_openssl_ctx_use_certificate_file(void *ctx, const char *file);
static int ds_openssl_ctx_use_privateKey_file(void *ctx, const char *file);
static int ds_openssl_ctx_check_private_key(const void *ctx);
static void *ds_openssl_new(void *ctx);
static int ds_openssl_set_fd(void *s, int fd);
static int ds_openssl_accept(void *s);
static int ds_openssl_connect(void *s);
static int ds_openssl_read(void *s, void *buf, int num);
static int ds_openssl_write(void *s, const void *buf, int num);
static int ds_openssl_shutdown(void *s);
static void ds_openssl_free(void *s);
static void ds_openssl_ctx_free(void *ctx);

static void *ds_dovessl_ctx_client_new(void);
static void *ds_dovessl_ctx_server_new(void);
static int ds_dovessl_ctx_use_certificate_file(void *ctx, const char *file);
static int ds_dovessl_ctx_use_privateKey_file(void *ctx, const char *file);
static int ds_dovessl_ctx_check_private_key(const void *ctx);
static void *ds_dovessl_new(void *ctx);
static int ds_dovessl_set_fd(void *s, int fd);
static int ds_dovessl_accept(void *s);
static int ds_dovessl_connect(void *s);
static int ds_dovessl_read(void *s, void *buf, int num);
static int ds_dovessl_write(void *s, const void *buf, int num);
static int ds_dovessl_shutdown(void *s);
static void ds_dovessl_free(void *s);
static void ds_dovessl_ctx_free(void *ctx);

static const char *
ds_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
ds_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"client", 0, 0, 'C'},
	{"server", 0, 0, 'S'},
	{"address", 0, 0, 'a'},
	{"port", 0, 0, 'p'},
	{"certificate", 0, 0, 'c'},
	{"key", 0, 0, 'k'},
	{0, 0, 0, 0}
};

static const char *
ds_options[] = {
	"--address      -a	IP address for SSL communication\n",	
	"--port         -p	Port for SSL communication\n",	
	"--certificate  -c	certificate file\n",	
	"--key          -k	private key file\n",	
	"--client       -C	Client use openssl lib\n",	
	"--server       -S	Server use openssl lib\n",	
	"--help         -H	Print help information\n",	
};

static const ds_proto_suite_t ds_openssl_suite = {
    .ps_library_init = SSL_library_init,
    .ps_add_all_algorithms = ds_openssl_add_all_algorighms,
    .ps_load_error_strings = SSL_load_error_strings,
    .ps_ctx_client_new = ds_openssl_ctx_client_new,
    .ps_ctx_server_new = ds_openssl_ctx_server_new,
    .ps_ctx_use_certificate_file = ds_openssl_ctx_use_certificate_file,
    .ps_ctx_use_privateKey_file = ds_openssl_ctx_use_privateKey_file,
    .ps_ctx_check_private_key = ds_openssl_ctx_check_private_key,
    .ps_ssl_new = ds_openssl_new,
    .ps_set_fd = ds_openssl_set_fd,
    .ps_accept = ds_openssl_accept,
    .ps_connect = ds_openssl_connect,
    .ps_read = ds_openssl_read,
    .ps_write = ds_openssl_write,
    .ps_shutdown = ds_openssl_shutdown,
    .ps_ssl_free = ds_openssl_free,
    .ps_ctx_free = ds_openssl_ctx_free,
};

static const ds_proto_suite_t ds_dovessl_suite = {
    .ps_library_init = ds_library_init,
    .ps_add_all_algorithms = ds_add_all_algorighms,
    .ps_load_error_strings = ds_load_error_strings,
    .ps_ctx_client_new = ds_dovessl_ctx_client_new,
    .ps_ctx_server_new = ds_dovessl_ctx_server_new,
    .ps_ctx_use_certificate_file = ds_dovessl_ctx_use_certificate_file,
    .ps_ctx_use_privateKey_file = ds_dovessl_ctx_use_privateKey_file,
    .ps_ctx_check_private_key = ds_dovessl_ctx_check_private_key,
    .ps_ssl_new = ds_dovessl_new,
    .ps_set_fd = ds_dovessl_set_fd,
    .ps_accept = ds_dovessl_accept,
    .ps_connect = ds_dovessl_connect,
    .ps_read = ds_dovessl_read,
    .ps_write = ds_dovessl_write,
    .ps_shutdown = ds_dovessl_shutdown,
    .ps_ssl_free = ds_dovessl_free,
    .ps_ctx_free = ds_dovessl_ctx_free,
};

/* OpenSSL */
static void
ds_openssl_add_all_algorighms(void)
{
    OpenSSL_add_all_algorithms();
}

static void *
ds_openssl_ctx_client_new(void)
{
    return SSL_CTX_new(TLSv1_2_client_method());
}

static void *
ds_openssl_ctx_server_new(void)
{
    return SSL_CTX_new(TLSv1_2_server_method());
}

static int 
ds_openssl_ctx_use_certificate_file(void *ctx, const char *file)
{
    return SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
}

static int
ds_openssl_ctx_use_privateKey_file(void *ctx, const char *file)
{
    return SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM);
}

static int
ds_openssl_ctx_check_private_key(const void *ctx)
{
    return SSL_CTX_check_private_key(ctx);
}

static void *ds_openssl_new(void *ctx)
{
    return SSL_new(ctx);
}

static int
ds_openssl_set_fd(void *s, int fd)
{
    return SSL_set_fd(s, fd);
}

static int
ds_openssl_accept(void *s)
{
    return SSL_accept(s);
}

static int
ds_openssl_connect(void *s)
{
    return SSL_connect(s);
}

static int
ds_openssl_read(void *s, void *buf, int num)
{
    return SSL_read(s, buf, num);
}

static int
ds_openssl_write(void *s, const void *buf, int num)
{
    return SSL_write(s, buf, num);
}

static int
ds_openssl_shutdown(void *s)
{
    return SSL_shutdown(s);
}

static void
ds_openssl_free(void *s)
{
    SSL_free(s);
}

static void
ds_openssl_ctx_free(void *ctx)
{
    SSL_CTX_free(ctx);
}

/* DoveSSL */
static void *
ds_dovessl_ctx_client_new(void)
{
    return SSL_CTX_new(TLSv1_2_client_method());
}

static void *
ds_dovessl_ctx_server_new(void)
{
    return SSL_CTX_new(TLSv1_2_server_method());
}

static int 
ds_dovessl_ctx_use_certificate_file(void *ctx, const char *file)
{
    return SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
}

static int
ds_dovessl_ctx_use_privateKey_file(void *ctx, const char *file)
{
    return SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM);
}

static int
ds_dovessl_ctx_check_private_key(const void *ctx)
{
    return SSL_CTX_check_private_key(ctx);
}

static void *ds_dovessl_new(void *ctx)
{
    return SSL_new(ctx);
}

static int
ds_dovessl_set_fd(void *s, int fd)
{
    return SSL_set_fd(s, fd);
}

static int
ds_dovessl_accept(void *s)
{
    return SSL_accept(s);
}

static int
ds_dovessl_connect(void *s)
{
    return SSL_connect(s);
}

static int
ds_dovessl_read(void *s, void *buf, int num)
{
    return SSL_read(s, buf, num);
}

static int
ds_dovessl_write(void *s, const void *buf, int num)
{
    return SSL_write(s, buf, num);
}

static int
ds_dovessl_shutdown(void *s)
{
    return SSL_shutdown(s);
}

static void
ds_dovessl_free(void *s)
{
    SSL_free(s);
}

static void
ds_dovessl_ctx_free(void *ctx)
{
    SSL_CTX_free(ctx);
}

static void
ds_add_epoll_event(int epfd, struct epoll_event *ev, int fd)
{
    ev->data.fd = fd;
    ev->events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
}

static int
ds_server_main(int pipefd, struct sockaddr_in *my_addr, char *cf,
        char *key, const ds_proto_suite_t *suite)
{
    struct epoll_event  ev = {};
    struct epoll_event  events[DS_TEST_EVENT_MAX_NUM] = {};
    int                 sockfd = 0;
    int                 efd = 0;
    int                 new_fd = 0;
    int                 epfd = 0;
    int                 nfds = 0;
    int                 i = 0;
    socklen_t           len = 0;
    ssize_t             rlen = 0;
    ssize_t             wlen = 0;
    struct sockaddr_in  their_addr = {};
    char                buf[DS_BUF_MAX_LEN] = {};
    void                *ctx = NULL;
    void                *ssl = NULL;
        
    /* SSL 库初始化 */
    suite->ps_library_init();
    /* 载入所有 SSL 算法 */
    suite->ps_add_all_algorithms();
    /* 载入所有 SSL 错误消息 */
    suite->ps_load_error_strings();
    /* 以 TLS1.2 标准兼容方式产生一个 SSL_CTX ,即 SSL Content Text */
    ctx = suite->ps_ctx_server_new();
    if (ctx == NULL) {
        fprintf(stderr, "CTX new failed!\n");
        exit(1);
    }
    /* 载入用户的数字证书, 此证书用来发送给客户端。 证书里包含有公钥 */
    if (suite->ps_ctx_use_certificate_file(ctx, cf) <= 0) {
        fprintf(stderr, "Load certificate failed!\n");
        exit(1);
    }
    /* 载入用户私钥 */
    if (suite->ps_ctx_use_privateKey_file(ctx, key) <= 0) {
        fprintf(stderr, "Load private key failed!\n");
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (!suite->ps_ctx_check_private_key(ctx)) {
        fprintf(stderr, "Check private key failed!\n");
        exit(1);
    }
    /* 开启一个 socket 监听 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    if (bind(sockfd, (struct sockaddr *)my_addr, sizeof(*my_addr)) == -1) {
        perror("bind");
        exit(1);
    }
    
    if (listen(sockfd, DS_SERVER_LISTEN_NUM) == -1) {
        perror("listen");
        exit(1);
    }

    epfd = epoll_create(1);
    if (epfd < 0) {
        exit(1);
    }
    ds_add_epoll_event(epfd, &ev, pipefd);
    ds_add_epoll_event(epfd, &ev, sockfd);

    while (1) {
        nfds = epoll_wait(epfd, events, DS_TEST_EVENT_MAX_NUM, -1);
        for (i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLIN) {
                if ((efd = events[i].data.fd) < 0) {
                    continue;
                }

                /* Client有请求到达 */
                if (efd == sockfd) {
                    /* 等待客户端连上来 */
                    if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr,
                                    &len)) == -1) {
                        perror("accept");
                        exit(errno);
                    } 
                    /* 基于 ctx 产生一个新的 SSL */
                    ssl = suite->ps_ssl_new(ctx);
                    /* 将连接用户的 socket 加入到 SSL */
                    suite->ps_set_fd(ssl, new_fd);
                    /* 建立 SSL 连接 */
                    if (suite->ps_accept(ssl) == -1) {
                        perror("accept");
                        close(new_fd);
                        goto out;
                    }
                    /* 开始处理每个新连接上的数据收发 */
                    bzero(buf, sizeof(buf));
                    /* 接收客户端的消息 */
                    len = suite->ps_read(ssl, buf, sizeof(buf));
                    if (len > 0 && strcmp(buf, DS_TEST_REQ) == 0) {
                        printf("Server接收消息成功:'%s',共%d 个字节的数据\n",
                                buf, len);
                    } else {
                        printf("Server消息接收失败!错误代码是%d,错误信息是'%s'\n",
                             errno, strerror(errno));
                        goto finish;
                    }
                    /* 发消息给客户端 */
                    len = suite->ps_write(ssl, DS_TEST_RESP, sizeof(DS_TEST_RESP));
                    if (len <= 0) {
                        printf("Server消息'%s'发送失败!错误信息是'%s'\n",
                             buf, strerror(errno));
                        goto finish;
                    } 
                    printf("Server消息'%s'发送成功,共发送了%d 个字节!\n",
                            DS_TEST_RESP, len);

                    /* 处理每个新连接上的数据收发结束 */
finish:
                    /* 关闭 SSL 连接 */
                    suite->ps_shutdown(ssl);
                    /* 释放 SSL */
                    suite->ps_ssl_free(ssl);
                    /* 关闭 socket */
                    close(new_fd);
                    ds_add_epoll_event(epfd, &ev, sockfd);
                    continue;
                }
                if (efd == pipefd) {
                    rlen = read(pipefd, buf, sizeof(buf));
                    if (rlen < 0) {
                        fprintf(stderr, "Read form pipe failed!\n");
                        goto out;
                    }
                    wlen = write(pipefd, DS_TEST_CMD_OK, sizeof(DS_TEST_CMD_OK));
                    if (wlen < sizeof(DS_TEST_CMD_OK)) {
                        fprintf(stderr, "Write to pipe failed!\n");
                        goto out;
                    }
                    if (strcmp(buf, DS_TEST_CMD_START) == 0) {
                        fprintf(stdout, "Test start!\n");
                        ds_add_epoll_event(epfd, &ev, sockfd);
                    } else {
                        goto out;
                    }
                }
            }
        }
    }
out:
    close(epfd);
    /* 关闭监听的 socket */
    close(sockfd);
    /* 释放 CTX */
    suite->ps_ctx_free(ctx);
    return 0;
}

static int
ds_server(int pipefd, struct sockaddr_in *addr, char *cf,
        char *key, const ds_proto_suite_t *suite)
{
    return ds_server_main(pipefd, addr, cf, key, suite);
}

#if 0
void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    } else
        printf("无证书信息!\n");
}
#endif

static int 
ds_client_main(struct sockaddr_in *dest, char *cf, char *key,
        const ds_proto_suite_t *suite)
{
    int         sockfd = 0;
    int         len = 0;
    char        buffer[DS_BUF_MAX_LEN] = {};
    SSL_CTX     *ctx = NULL;
    SSL         *ssl = NULL;

    suite->ps_library_init();
    suite->ps_add_all_algorithms();
    suite->ps_load_error_strings();
    ctx = suite->ps_ctx_client_new();
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        return DS_ERROR;
    }
    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");
    printf("address created\n");
    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)dest, sizeof(*dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");
    /* 基于 ctx 产生一个新的 SSL */
    ssl = suite->ps_ssl_new(ctx);
    suite->ps_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    if (suite->ps_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
    } else {
        //printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        //ShowCerts(ssl);
    }
    /* 发消息给服务器 */
    len = suite->ps_write(ssl, DS_TEST_REQ, sizeof(DS_TEST_REQ));
    if (len < 0) {
        printf("Client消息'%s'发送失败!错误代码是%d,错误信息是'%s'\n",
             buffer, errno, strerror(errno));
    } else {
        printf("Client消息'%s'发送成功,共发送了%d 个字节!\n",
                DS_TEST_REQ, len);
    }

    /* 接收服务器来的消息 */
    len = suite->ps_read(ssl, buffer, sizeof(buffer));
    if (len > 0 && strcmp(buffer, DS_TEST_RESP) == 0) {
        printf("Client接收消息成功:'%s',共%d 个字节的数据\n",
                buffer, len);
    } else {
        printf("Client消息接收失败!错误代码是%d,错误信息是'%s', len = %d\n",
             errno, strerror(errno), len);
    }

    /* 关闭连接 */
    suite->ps_shutdown(ssl);
    suite->ps_ssl_free(ssl);
    close(sockfd);
    suite->ps_ctx_free(ctx);
    return 0;
}

static int
ds_client(int pipefd, struct sockaddr_in *addr, char *cf, 
        char *key, const ds_proto_suite_t *suite)
{
    char                buf[DS_BUF_MAX_LEN] = {};
    ssize_t             rlen = 0;
    ssize_t             wlen = 0;
    int                 ret = 0;

    wlen = write(pipefd, DS_TEST_CMD_START, strlen(DS_TEST_CMD_START));
    if (wlen < strlen(DS_TEST_CMD_START)) {
        fprintf(stderr, "Write to pipefd failed(errno=%s)\n", strerror(errno));
        return DS_ERROR;
    }
    rlen = read(pipefd, buf, sizeof(buf));
    if (rlen < 0 || strcmp(DS_TEST_CMD_OK, buf) != 0) {
        fprintf(stderr, "Read from pipefd failed(errno=%s)\n", strerror(errno));
        return DS_ERROR;
    }
    ret = ds_client_main(addr, cf, key, suite);
    if (ret != DS_OK) {
        close(pipefd);
        return DS_ERROR;
    }

    wlen = write(pipefd, DS_TEST_CMD_START, strlen(DS_TEST_CMD_END));
    if (wlen < strlen(DS_TEST_CMD_END)) {
        fprintf(stderr, "Write to pipefd failed(errno=%s), wlen = %d\n",
                strerror(errno), (int)wlen);
        close(pipefd);
        return DS_ERROR;
    }

    rlen = read(pipefd, buf, sizeof(buf));
    close(pipefd);
    if (rlen < 0 || strcmp(DS_TEST_CMD_OK, buf) != 0) {
        fprintf(stderr, "Read from pipefd failed(errno=%s)\n", strerror(errno));
        return DS_ERROR;
    }
    return DS_OK;
}

static void 
ds_help(void)
{
	int     index;

	fprintf(stdout, "Version: %s\n", ds_program_version);

	fprintf(stdout, "\nOptions:\n");
	for(index = 0; index < DS_ARRAY_SIZE(ds_options); index++) {
		fprintf(stdout, "  %s", ds_options[index]);
	}
}

static const char *
ds_optstring = "HCSa:p:c:k:";

int
main(int argc, char **argv)  
{
    int                     c = 0;
    int                     fd[2] = {};
    struct sockaddr_in      addr = {
        .sin_family = AF_INET,
    };
    pid_t                   pid = 0;
    ds_u16                  pport = 0;
    const ds_proto_suite_t  *client_suite = &ds_dovessl_suite;
    const ds_proto_suite_t  *server_suite = &ds_dovessl_suite;
    char                    *ip = DS_DEF_IP_ADDRESS;
    char                    *port = DS_DEF_IP_ADDRESS;
    char                    *cf = NULL;
    char                    *key = NULL;

    while((c = getopt_long(argc, argv, 
                    ds_optstring,  ds_long_opts, NULL)) != -1) {
        switch(c) {
            case 'H':
                ds_help();
                return DS_OK;

            case 'C':
                client_suite = &ds_openssl_suite;
                break;

            case 'S':
                server_suite = &ds_openssl_suite;
                break;

            case 'a':
                ip = optarg;
                break;

            case 'p':
                port = optarg;
                break;

            case 'c':
                cf = optarg;
                break;

            case 'k':
                key = optarg;
                break;

            default:
                ds_help();
                return -DS_ERROR;
        }
    }

    if (cf == NULL) {
        fprintf(stderr, "Please input cf by -c!\n");
        return -DS_ERROR;
    }

    if (key == NULL) {
        fprintf(stderr, "Please input key by -k!\n");
        return -DS_ERROR;
    }

    pport = atoi(port);
    addr.sin_port = htons(pport);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
        fprintf(stderr, "Create socketpair failed(errn=%s)!\n",
                strerror(errno));
        return -DS_ERROR;
    }

    if ((pid = fork()) < 0) {
        fprintf(stderr, "Fork failed!\n");
        return -DS_ERROR;
    }

    if (pid > 0) {  /* Parent */
        close(fd[0]);
        return -ds_client(fd[1], &addr, cf, key, client_suite);
    }

    /* Child */
    close(fd[1]);
    return -ds_server(fd[0], &addr, cf, key, server_suite);
}
