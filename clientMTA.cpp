#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ranges>
#include <string_view>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctime>

#include "include/packet.h"
#include "include/lib.h"

extern "C" {
    #include <spf2/spf.h>
}

int next_step(email mail, string smtp_domain, string PORT)
{
    int sockfd;
    map<string, vector<string>> domenii = domains(mail.anvelopa.recipients);

    for (auto& [domain, usernames] : domenii)
    {
        vector<string> mx_servers = get_mx_servers(domain);

        if (mx_servers.size() == 0)
        {
            perror("Could not find a MX server!\n");
            return -1;
        }

        struct addrinfo hints, *result;
        for (auto& server : mx_servers)
        {
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            int code = getaddrinfo(server.c_str(), PORT.c_str(), &hints, &result);
            if (code != 0)
            {
                result = NULL;
                continue;
            }

            sockfd = socket(AF_INET, SOCK_STREAM, result->ai_protocol);

            if (connect(sockfd, result->ai_addr, result->ai_addrlen) < 0)
            {
                perror("Cannot connect to the given SMTP destination!");
                freeaddrinfo(result);
                return -1;
            }
            cout << "[CLIENT] Socket connection established\n";

            freeaddrinfo(result);
            break;
        }

        email temp = mail;

        temp.anvelopa.recipients.clear();

        for (auto& rec : usernames)
            temp.anvelopa.recipients.push_back(rec + "@" + domain);

        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        cout << "[CLIENT] SSL library loaded. Sending mail...\n";
        send_mail(sockfd, temp, smtp_domain);
    }

        return 0;
}

int main(void)
{
    int uafd;
    struct sockaddr_in serveraddr;

    email mail;

    load_env();

    const char* env_domain = getenv("SMTP_DOMAIN");
    const char* env_sender = getenv("SMTP_SENDER");
    const char* env_port = getenv("SMTP_PORT");
    const char* env_mail_domain = getenv("MAIL_DOMAIN");

    string smtp_domain = string(env_domain);
    string smtp_sender = string(env_sender);
    string PORT = string(env_port);
    string mail_domain = string(env_mail_domain);

    //TEST MAIL
    mail.anvelopa.sender = smtp_sender;
    mail.anvelopa.recipients.push_back("hoza.ciprian2005@gmail.com");
    mail.anvelopa.recipients.push_back("1149j.test@inbox.testmail.app");
    mail.corp.headers["Subject"] = "test email";
    mail.corp.headers["From"] = "Ciprian Hoza <" + smtp_sender + ">";
    mail.corp.headers["Message-ID"] = "<" + to_string(time(nullptr)) + "@test-projects.dev>";
    mail.corp.headers["Date"] = get_date();
    mail.corp.body = "Acesta este inca un email de test mai lung de data aceasta!";
    //TEST MAIL

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(587);
    serveraddr.sin_addr.s_addr = INADDR_ANY;

    uafd = socket(AF_INET, SOCK_STREAM, 0);
    if (uafd == -1)
    {
        perror("[CLIENT]Error trying to create the user agent connection socket\n");
        return -1;
    }

    int op = 1;
    setsockopt(uafd, SOL_SOCKET, SO_REUSEADDR, &op, sizeof(op));

    if (bind(uafd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
    {
        perror("[CLIENT] Error trying to bind the uafd socket!\n");
        return -1;
    }

    if (listen(uafd, SOMAXCONN) < 0)
    {
        perror("[CLIENT] Listen failed!\n");
        return -1;
    }

    SSL_CTX* ctx = init_server_ssl_context();
    char ip_str[INET_ADDRSTRLEN];
    while(true)
    {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);

        int client_fd = accept(uafd, (struct sockaddr*)&client, &client_len);

        if (client_fd < 0)
        {
            perror("[CLIENT] Error on connect!\n");
            continue;
        }

        memset(ip_str, 0, sizeof(ip_str));

        inet_ntop(AF_INET, &(client.sin_addr), ip_str, INET_ADDRSTRLEN);

        cout<<"[CLIENT] Connection received from " << string(ip_str) << '\n';

        if (client_fd < 0)
        {
            perror("[CLIENT] Error on connect!\n");
            continue;
        }

        email true_mail = receive_from_ua(client_fd, ctx, smtp_domain, mail_domain);

        if (true_mail.anvelopa.sender.empty())
        {
            perror("[CLIENT] Error on receiving the mail from user agent\n");
            continue;
        }

        true_mail.corp.headers["Message-ID"] = "<" + to_string(time(nullptr)) + "@" + mail_domain + ">";
        true_mail.corp.headers["Date"] = get_date();

        if (next_step(true_mail, smtp_domain, PORT) == -1)
        {
            perror("[CLIENT]Error trying sending the email...\n");
            continue;
        }

        cout << "[CLIENT] Email sent!" << '\n';
    }
    
    return 0;
}