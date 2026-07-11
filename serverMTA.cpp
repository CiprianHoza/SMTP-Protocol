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

int main(void)
{
    int sockfd;
    struct sockaddr_in serveraddr;

    email mail;

    load_env();

    const char* env_domain = getenv("SMTP_DOMAIN");
    const char* env_sender = getenv("SMTP_SENDER");
    const char* env_port = getenv("SMTP_PORT");

    string smtp_domain = string(env_domain);
    string smtp_sender = string(env_sender);
    string PORT = string(env_port);

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

    map<string, vector<string>> domenii = domains(mail.anvelopa.recipients);

    for (auto& [domain, usernames] : domenii)
    {
        vector<string> mx_servers = get_mx_servers(domain);

        if (mx_servers.size() == 0)
        {
            perror("Could not find a MX server!\n");
            return 1;
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
                return 1;
            }
            cout << "[SERVER] Socket connection established\n";

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
        cout << "[SERVER] SSL library loaded. Sending mail...\n";
        send_mail(sockfd, temp, smtp_domain);
    }
    

    return 0;
}