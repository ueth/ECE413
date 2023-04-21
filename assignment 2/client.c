#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL    -1
int OpenConnection(const char *hostname, int port)
{
    int sockfd = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;

    bzero(&server_address, sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr.s_addr = INADDR_ANY;

    int connection_status = connect(sockfd, (struct sockaddr *) &server_address, sizeof(server_address));
    if(connection_status == -1){
        fprintf(stderr, "ERROR: making the connection to the remote server\n");
        exit(1);
    }
    return sockfd;
}
SSL_CTX* InitCTX(void)
{
    SSL_CTX *ctx;

	/* Load cryptos, et.al. */
    OpenSSL_add_all_algorithms();

	/* Bring in and register error messages */
    SSL_load_error_strings();

	/* Create new client-method instance && Create new context */
    ctx = SSL_CTX_new(TLSv1_2_client_method());
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;

	/* get the server's certificate */
    cert = SSL_get_peer_certificate(ssl);

    if ( cert != NULL ) // If peer did not present any certificate
    {
        X509_NAME *subj_name = X509_get_subject_name(cert);
        X509_NAME *issuer_name = X509_get_issuer_name(cert);

        printf("Server certificates:\n");

        /*NULL buf dynamicaly alocates and returns string to `line`*/
        line = X509_NAME_oneline(subj_name, NULL, 0);
        printf("Subject: %s\n", line);
        free(line);
       	line = X509_NAME_oneline(issuer_name, NULL, 0);
        printf("Issuer: %s\n", line);
        free(line);
    }
    else
        printf("Info: No client certificates configured.\n");
}
int main(int count, char *strings[])
{
    SSL_CTX *ctx;
    int server_socket, reply_length;
    SSL *ssl;
    char reply_buffer[1024], client_request[1024] = {0};
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(1);
    }
    /*register the available SSL/TLS ciphers and digests*/
    SSL_library_init();

    ctx = InitCTX();
    server_socket = OpenConnection(strings[1], atoi(strings[2]));

    /* create new SSL connection state */
    ssl = SSL_new(ctx);

	/* attach the socket descriptor */
    SSL_set_fd(ssl, server_socket);

		/* perform the connection */
    if ( SSL_connect(ssl) == FAIL )   /* connection fail */
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body>\
                               <UserName>%s<UserName>\
                 <Password>%s<Password>\
                 <\Body>";
        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);

		/* construct reply */
        sprintf(client_request, cpRequestMessage, acUsername, acPassword);
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));

   		/* get any certs */
        ShowCerts(ssl);

        /* encrypt & send message */
        if((SSL_write(ssl, client_request, strlen(client_request)) <= 0)){
            fprintf(stderr, "The write operation was not successful\n");
            exit(1);
        }

        /* get reply & decrypt */
        reply_length = SSL_read(ssl, reply_buffer, sizeof(reply_buffer));
        if(reply_length <= 0){
            fprintf(stderr, "The read operation was not successful\n");
            exit(1);
        }
        reply_buffer[reply_length] = '\0';
        printf("Reply read: %s\n", reply_buffer);

	    /* release connection state */
        SSL_free(ssl);
    }
	/* close socket */
    close(server_socket);

	/* release context */
    SSL_CTX_free(ctx);
    return 0;
}
