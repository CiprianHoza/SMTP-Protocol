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

#include "include/packet.h"
#include "include/lib.h"

#define PORT "25"

int main(void)
{
    int sockfd;
    struct sockaddr_in serveraddr;

    email mail;

    mail.anvelopa.sender = "hoza.ciprian2016@gmail.com";
    mail.anvelopa.recipients.push_back("ceva@example.com");
    mail.anvelopa.recipients.push_back("altceva@gmail.com");
    mail.anvelopa.recipients.push_back("hoza.ciprian2005@gmail.com");
    mail.corp.headers["Subject"] = "test email";
    mail.corp.headers["From"] = "hoza.ciprian2016@gmail.com";
    mail.corp.body = "acesta este un mail de test";


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

            int code = getaddrinfo(server.c_str(), PORT, &hints, &result);
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

            freeaddrinfo(result);
            break;
        }

        email temp = mail;

        temp.anvelopa.recipients.clear();

        for (auto& rec : usernames)
            temp.anvelopa.recipients.push_back(rec + "@" + domain);

        send_mail(sockfd, mail);
    }
    

    return 0;
}