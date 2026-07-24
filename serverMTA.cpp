#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ranges>
#include <string_view>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>
#include <ctime>


#include "include/packet.h"
#include "include/lib.h"

extern "C" {
    #include <spf2/spf.h>
}

int main(void)
{
    int sockfd;
    struct sockaddr_in serv;

    load_env();

    const char* env_domain = getenv("SMTP_DOMAIN");
    const char* env_sender = getenv("SMTP_SENDER");
    const char* env_port = getenv("SMTP_PORT");
    const char* env_mail_domain = getenv("MAIL_DOMAIN");

    string smtp_domain = string(env_domain);
    string smtp_sender = string(env_sender);
    string PORT = string(env_port);
    string mail_domain = string(env_mail_domain);

    memset(&serv, 0, sizeof(serv));

    serv.sin_family = AF_INET;
    serv.sin_port = htons(stoi(PORT));
    serv.sin_addr.s_addr = INADDR_ANY;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
    {
        perror("[SERVER] Error trying to create the server socket!\n");
        return -1;
    }

    int op = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &op, sizeof(op));


    if (bind(sockfd, (struct sockaddr*)&serv, sizeof(serv)) < 0)
    {
        perror("[SERVER] Error trying to bind the server socket!\n");
        return -1;
    }

    if (listen(sockfd, SOMAXCONN) < 0)
    {
        perror("[SERVER] Listen failed!\n");
        return -1;
    }

    SSL_CTX* ctx = init_server_ssl_context();
    while(true)
    {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);

        int client_fd = accept(sockfd, (struct sockaddr*)&client, &client_len);

        if (client_fd < 0)
        {
            perror("[SERVER] Error on connect!\n");
            continue;
        }

        email mail = receive_email(client_fd, ctx, smtp_domain, mail_domain);

        //TEST
        if (mail.anvelopa.sender.empty())
        {
            cout<<"nu a mers\n";
            continue;
        }

        cout<<mail.anvelopa.sender<<'\n';
        cout<<mail.anvelopa.recipients[0]<<'\n';

        for (auto& [key, value] : mail.corp.headers)
        {
            cout<<key<<": "<<value<<'\n'; 
        }

        cout<<mail.corp.body<<'\n'<<'\n';

    }

    close(sockfd);
    return 0;
}