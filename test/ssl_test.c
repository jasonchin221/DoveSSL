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

static const char *
ds_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
ds_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"openssl", 0, 0, 'O'},
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
	"--openssl      -O	Use openssl lib\n",	
	"--help         -H	Print help information\n",	
};

static void
ds_add_epoll_event(int epfd, struct epoll_event *ev, int fd)
{
    ev->data.fd = fd;
    ev->events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
}

int server_main(int pipefd, struct sockaddr_in *my_addr, char *cf, char *key)
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
    SSL_CTX             *ctx = NULL;
    SSL                 *ssl = NULL;
        
    /* SSL 库初始化 */
    SSL_library_init();
    /* 载入所有 SSL 算法 */
    OpenSSL_add_all_algorithms();
    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();
    /* 以 TLS1.2 标准兼容方式产生一个 SSL_CTX ,即 SSL Content Text */
    ctx = SSL_CTX_new(TLSv1_2_server_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3
       标准 */
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户的数字证书, 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, cf, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 开启一个 socket 监听 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else
        printf("socket created\n");

    if (bind(sockfd, (struct sockaddr *)my_addr, sizeof(*my_addr)) == -1) {
        perror("bind");
        exit(1);
    } else
        printf("binded\n");
    if (listen(sockfd, DS_SERVER_LISTEN_NUM) == -1) {
        perror("listen");
        exit(1);
    } else
        printf("begin listen\n");

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
                    ssl = SSL_new(ctx);
                    /* 将连接用户的 socket 加入到 SSL */
                    SSL_set_fd(ssl, new_fd);
                    /* 建立 SSL 连接 */
                    if (SSL_accept(ssl) == -1) {
                        perror("accept");
                        close(new_fd);
                        goto out;
                    }
                    /* 开始处理每个新连接上的数据收发 */
                    bzero(buf, sizeof(buf));
                    /* 接收客户端的消息 */
                    len = SSL_read(ssl, buf, sizeof(buf));
                    if (len > 0 && strcmp(buf, DS_TEST_REQ) == 0) {
                        printf("Server接收消息成功:'%s',共%d 个字节的数据\n",
                                buf, len);
                    } else {
                        printf("Server消息接收失败!错误代码是%d,错误信息是'%s'\n",
                             errno, strerror(errno));
                        goto finish;
                    }
                    /* 发消息给客户端 */
                    len = SSL_write(ssl, DS_TEST_RESP, sizeof(DS_TEST_RESP));
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
                    SSL_shutdown(ssl);
                    /* 释放 SSL */
                    SSL_free(ssl);
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
    SSL_CTX_free(ctx);
    return 0;
}

static int
ds_server(int pipefd, struct sockaddr_in *addr, char *cf, char *key)
{
    return server_main(pipefd, addr, cf, key);
}


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

int client_main(struct sockaddr_in *dest)
{
    int         sockfd = 0;
    int         len = 0;
    char        buffer[DS_BUF_MAX_LEN] = {};
    SSL_CTX     *ctx = NULL;
    SSL         *ssl = NULL;

    /* SSL 库初始化,参看 ssl-server.c 代码 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLSv1_2_client_method());
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
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    /* 发消息给服务器 */
    len = SSL_write(ssl, DS_TEST_REQ, sizeof(DS_TEST_REQ));
    if (len < 0) {
        printf("Client消息'%s'发送失败!错误代码是%d,错误信息是'%s'\n",
             buffer, errno, strerror(errno));
    } else {
        printf("Client消息'%s'发送成功,共发送了%d 个字节!\n",
                DS_TEST_REQ, len);
    }

    /* 接收服务器来的消息 */
    len = SSL_read(ssl, buffer, sizeof(buffer));
    if (len > 0 && strcmp(buffer, DS_TEST_RESP) == 0) {
        printf("Client接收消息成功:'%s',共%d 个字节的数据\n",
                buffer, len);
    } else {
        printf("Client消息接收失败!错误代码是%d,错误信息是'%s', len = %d\n",
             errno, strerror(errno), len);
    }

    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}

static int
ds_client(int pipefd, struct sockaddr_in *addr, char *cf)
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
    ret = client_main(addr);
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
ds_optstring = "HOa:p:c:k:";

int
main(int argc, char **argv)  
{
    int                 c = 0;
    int                 fd[2] = {};
    struct sockaddr_in  addr = {
        .sin_family = AF_INET,
    };
    pid_t               pid = 0;
    ds_u16              pport = 0;
    char                *ip = DS_DEF_IP_ADDRESS;
    char                *port = DS_DEF_IP_ADDRESS;
    char                *cf = NULL;
    char                *key = NULL;

    while((c = getopt_long(argc, argv, 
                    ds_optstring,  ds_long_opts, NULL)) != -1) {
        switch(c) {
            case 'H':
                ds_help();
                return DS_OK;

            case 'O':
                return DS_OK;

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
        return -ds_client(fd[1], &addr, cf);
    }

    /* Child */
    close(fd[1]);
    return -ds_server(fd[0], &addr, cf, key);
}
