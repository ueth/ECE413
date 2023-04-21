#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL    -1
// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
    SSL_CTX *ctx;

	/* load & register all cryptos, etc. */
    OpenSSL_add_all_algorithms();

	/* load all error messages */
    SSL_load_error_strings();

	/* create new server-method instance && create new context from method */
    ctx = SSL_CTX_new(TLSv1_2_server_method());
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    printf("Server is running.\n");
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) != 1){
        fprintf(stderr, "ERROR 1\n");
        exit(1);
    }
    
    /* set the private key from KeyFile (may be the same as CertFile) */
    if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) != 1){
        fprintf(stderr, "ERROR 2\n");
        exit(1);
    }

    /* verify private key */
    if (SSL_CTX_check_private_key(ctx) != 1){
        fprintf(stderr, "ERROR private key couldn't be verified\n");
        exit(1);
    }
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;

	/* Get certificates (if available) */
    cert = SSL_get_peer_certificate(ssl);

    if ( cert != NULL )
    {
        X509_NAME *subj_name = X509_get_subject_name(cert);
        X509_NAME *issuer_name = X509_get_issuer_name(cert);

        printf("Server certificates:\n");
        line = X509_NAME_oneline(subj_name, 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(issuer_name, 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
    }
    else
        printf("No certificates.\n");
}
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int sd, bytes;
    const char* ServerResponse="<\Body>\
                               <Name>sousi.com</Name>\
                               <year>1.5</year>\
                               <BlogType>Embedede and c\c++<\BlogType>\
                               <Author>John Johny<Author>\
                               <\Body>";
    const char *cpValidMessage = "<Body>\
                               <UserName>sousi<UserName>\
                 <Password>123<Password>\
                 <\Body>";
	/* do SSL-protocol accept */
    if (SSL_accept(ssl) != FAIL){
        bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = '\0';

        if(bytes <= 0){
            fprintf(stderr, "The read operation was not successful\n");
            exit(1);
        }
        if(strcmp(cpValidMessage,buf) == 0)
            SSL_write(ssl, ServerResponse, strlen(ServerResponse));
        else
            SSL_write(ssl, "Wrong UserName-Password", strlen("Wrong UserName-Password"));
    }
    else{
        fprintf(stderr, "ERROR\n");
    }
  
	/* get socket connection */
    sd = SSL_get_fd(ssl);
    if(sd == FAIL){
        fprintf(stderr, "The operation failed, because the underlying BIO is not of the correct type\n");
        exit(1);
    }

	/* release SSL state */
    SSL_free(ssl);

    /* close connection */
    close(sd);
}
int main(int count, char *Argc[])
{
    SSL_CTX *ctx;
    int sockfd;
    
//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    // Initialize the SSL library
    SSL_library_init();

    /* initialize SSL */
    ctx = InitServerCTX();

    /* load certs */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem");

    /* create server socket */
    sockfd = OpenListener(atoi(Argc[1]));

    while (1)
    {
        struct sockaddr_in addr;
        SSL *ssl;

		/* accept connection as usual */
        int client_socket = accept(sockfd, NULL, NULL);
        printf("New Connection\n");

		/* get new SSL state with context */
        ssl = SSL_new(ctx);

		/* set connection socket to SSL state */
        SSL_set_fd(ssl, client_socket);

		/* service connection */
        Servlet(ssl);
    }
    /* close server socket */
    close(sockfd);

	/* release context */
    SSL_CTX_free(ctx);
}
