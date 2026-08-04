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

void handle_conn(int client_fd, SSL_CTX* ctx, string smtp_domain, string mail_domain, string ip_str)
{
    sprint("[SERVER ", this_thread::get_id(), "] Connection received from ", ip_str, '\n');

    email mail = receive_email(client_fd, ctx, smtp_domain, mail_domain);

        if (mail.anvelopa.sender.empty())
        {
            sprint("[SERVER ", this_thread::get_id(), "] Error trying to receive the email!", '\n');
            return;
        }

        sprint(mail.anvelopa.sender, '\n');
        sprint(mail.anvelopa.recipients[0], '\n');

        for (auto& [key, value] : mail.corp.headers)
        {
            sprint(key, ": ", value, '\n');
        }

        sprint(mail.corp.body, '\n', '\n');

        if (!deliver_to_dovecot_lmtp(mail))
            sprint("Error trying to deliver the mail to Dovecot", '\n');
        else
            sprint("[SERVER ", this_thread::get_id(), "] Mail stored in database", '\n');
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

        char ip_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &client.sin_addr.s_addr, ip_str, INET_ADDRSTRLEN);
        string client_ip(ip_str);

        if (client_fd < 0)
        {
            perror("[SERVER] Error on connect!\n");
            continue;
        }

        thread t(handle_conn, client_fd, ctx, smtp_domain, mail_domain, client_ip);

        t.detach();
    }

    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}