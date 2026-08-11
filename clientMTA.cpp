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


int next_step(email mail, string smtp_domain, string PORT, string mail_domain)
{
    int sockfd;
    map<string, vector<string>> domenii = domains(mail.anvelopa.recipients);

    string key_path = "/etc/opendkim/keys/" + mail_domain + "/mail.private";
    string dkim_header = sign_dkim(mail, mail_domain, "mail", key_path);

    if (!dkim_header.empty())
    {
        sprint("[CLIENT ", this_thread::get_id(), "] DKIM signature created successfully!", '\n');

        size_t pos = dkim_header.find(':');
        if (pos != string::npos)
        {
            string value = dkim_header.substr(pos + 1);

            while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' '))
                value.pop_back();
            while (!value.empty() && value.front() == ' ')
                value.erase(0, 1);

            mail.corp.headers["DKIM-Signature"] = value;
        }
    }
    else
        sprint("[CLIENT ", this_thread::get_id(), "] Failed to generate DKIM signature!", '\n');

    for (auto& [domain, usernames] : domenii)
    {
        vector<string> mx_servers = get_mx_servers(domain);

        if (mx_servers.size() == 0)
        {
            sprint("[CLIENT ", this_thread::get_id(), "] Could not find a MX server!", '\n');
            continue;
        }

        sockfd = -1;
        bool connected = false;

        for (auto& server : mx_servers)
        {
            struct addrinfo hints, *result = nullptr;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            int code = getaddrinfo(server.c_str(), PORT.c_str(), &hints, &result);
            if (code != 0 || !result)
            {
                sprint("[CLIENT ", this_thread::get_id(), "] DNS lookup failed for MX: ", server, '\n');
                continue;
            }

            sockfd = socket(AF_INET, SOCK_STREAM, result->ai_protocol);

            if (sockfd < 0)
            {
                freeaddrinfo(result);
                continue;
            }

            if (connect(sockfd, result->ai_addr, result->ai_addrlen) < 0)
            {
                sprint("[CLIENT ", this_thread::get_id(), "] Cannot connect to MX: ", server, ", trying another one...", '\n');
                close(sockfd);
                freeaddrinfo(result);
                continue;
            }
            sprint("[CLIENT ", this_thread::get_id(), "] Socket connection established with MX: ", server, '\n');
            connected = true;
            freeaddrinfo(result);
            break;
        }

        if (!connected)
        {
            sprint("[CLIENT ", this_thread::get_id(), "] Failed to connect to any MX server for domain: ", domain, '\n');
            continue;;
        }

        email temp = mail;

        temp.anvelopa.recipients.clear();

        for (auto& rec : usernames)
            temp.anvelopa.recipients.push_back(rec + "@" + domain);

        sprint("[CLIENT ", this_thread::get_id(), "] SSL library loaded. Sending mail...", '\n');
        send_mail(sockfd, temp, smtp_domain);
    }

        return 0;
}

void handle_conn(int client_fd, SSL_CTX* ctx, string smtp_domain, string mail_domain, string PORT, string client_ip)
{
    sprint("[CLIENT ", this_thread::get_id(), "] Connection received from ", client_ip, '\n');

        email true_mail = receive_from_ua(client_fd, ctx, smtp_domain, mail_domain);

        if (true_mail.anvelopa.sender.empty())
        {
            sprint("[CLIENT ", this_thread::get_id(), "] Error on receiving the mail from user agent", '\n');
            return;
        }

        if (true_mail.corp.headers["Message-ID"].empty())
            true_mail.corp.headers["Message-ID"] = "<" + to_string(time(nullptr)) + "@" + mail_domain + ">";

        if (true_mail.corp.headers["Date"].empty())
            true_mail.corp.headers["Date"] = get_date();

        next_step(true_mail, smtp_domain, PORT, mail_domain);
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

        char ip_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &(client.sin_addr), ip_str, INET_ADDRSTRLEN);

        string client_ip(ip_str);

        thread t(handle_conn, client_fd, ctx, smtp_domain, mail_domain, PORT, client_ip);

        t.detach();
    }
    
    close(uafd);
    SSL_CTX_free(ctx);
    return 0;
}