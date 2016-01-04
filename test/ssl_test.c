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

#include "ds_types.h"
#include "ds_lib.h"
#include "ds_errno.h"

#define DS_DEF_IP_ADDRESS       "127.0.0.1"
#define DS_DEF_PORT             "7838"
#define DS_SERVER_LISTEN_NUM    5

static const char *
ds_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
ds_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"server", 0, 0, 'S'},
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
	"--server       -S	Server mode\n",	
	"--openssl      -O	Use openssl lib\n",	
	"--help         -H	Print help information\n",	
};

#define MAXBUF 1024

int server_main(struct sockaddr_in *my_addr, char *cf, char *key)
{
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in their_addr;
    char buf[MAXBUF + 1];
    SSL_CTX *ctx;
        
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
    while (1) {
        SSL *ssl;
        len = sizeof(struct sockaddr);
        /* 等待客户端连上来 */
        if ((new_fd =
                    accept(sockfd, (struct sockaddr *) &their_addr,
                        &len)) == -1) {
            perror("accept");
            exit(errno);
        } else
            printf("server: got connection from %s, port %d, socket %d\n",
                    inet_ntoa(their_addr.sin_addr),
                    ntohs(their_addr.sin_port), new_fd);
        /* 基于 ctx 产生一个新的 SSL */
        ssl = SSL_new(ctx);
        /* 将连接用户的 socket 加入到 SSL */
        SSL_set_fd(ssl, new_fd);
        /* 建立 SSL 连接 */
        if (SSL_accept(ssl) == -1) {
            perror("accept");
            close(new_fd);

            break;
        }
        /* 开始处理每个新连接上的数据收发 */
        bzero(buf, MAXBUF + 1);
        strcpy(buf, "server->client");
        /* 发消息给客户端 */
        len = SSL_write(ssl, buf, strlen(buf));
        if (len <= 0) {
            printf
                ("消息'%s'发送失败!错误代码是%d,错误信息是'%s'\n",
                 buf, errno, strerror(errno));
            goto finish;
        } else
            printf("消息'%s'发送成功,共发送了%d 个字节!\n",
                    buf, len);
        bzero(buf, MAXBUF + 1);
        /* 接收客户端的消息 */
        len = SSL_read(ssl, buf, MAXBUF);
        if (len > 0)
            printf("接收消息成功:'%s',共%d 个字节的数据\n",
                    buf, len);
        else
            printf
                ("消息接收失败!错误代码是%d,错误信息是'%s'\n",
                 errno, strerror(errno));
        /* 处理每个新连接上的数据收发结束 */
finish:
        /* 关闭 SSL 连接 */
        SSL_shutdown(ssl);
        /* 释放 SSL */
        SSL_free(ssl);
        /* 关闭 socket */
        close(new_fd);
    }
    /* 关闭监听的 socket */
    close(sockfd);
    /* 释放 CTX */
    SSL_CTX_free(ctx);
    return 0;
}

static int
ds_server(struct sockaddr_in *addr, char *cf, char *key)
{
    return server_main(addr, cf, key);
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
    int sockfd, len;
    char buffer[MAXBUF + 1];
    SSL_CTX *ctx;
    SSL *ssl;

    /* SSL 库初始化,参看 ssl-server.c 代码 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
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
    /* 接收对方发过来的消息,最多接收 MAXBUF 个字节 */
    bzero(buffer, MAXBUF + 1);
    /* 接收服务器来的消息 */
    len = SSL_read(ssl, buffer, MAXBUF);
    if (len > 0)
        printf("接收消息成功:'%s',共%d 个字节的数据\n",
                buffer, len);
    else {
        printf
            ("消息接收失败!错误代码是%d,错误信息是'%s'\n",
             errno, strerror(errno));
        goto finish;
    }
    bzero(buffer, MAXBUF + 1);
    strcpy(buffer, "from client->server");
    /* 发消息给服务器 */
    len = SSL_write(ssl, buffer, strlen(buffer));
    if (len < 0)
        printf
            ("消息'%s'发送失败!错误代码是%d,错误信息是'%s'\n",
             buffer, errno, strerror(errno));
    else
        printf("消息'%s'发送成功,共发送了%d 个字节!\n",
                buffer, len);
finish:
    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}

static int
ds_client(struct sockaddr_in *addr, char *cf)
{
    return client_main(addr);
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
ds_optstring = "HSOa:p:c:k:";

int
main(int argc, char **argv)  
{
    int                 c = 0;
    bool                client = DS_TRUE;
    struct sockaddr_in  addr = {
        .sin_family = AF_INET,
    };
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

            case 'S':
                client = DS_FALSE;
                break;

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
        printf("Please input cf by -c!\n");
        return -DS_ERROR;
    }
    addr.sin_port = htons(atoi(port));
    addr.sin_addr.s_addr = inet_addr(ip);
    if (client == DS_TRUE) {
        return ds_client(&addr, cf);
    }

    if (key == NULL) {
        printf("Please input key by -k!\n");
        return -DS_ERROR;
    }

    return ds_server(&addr, cf, key);
}
