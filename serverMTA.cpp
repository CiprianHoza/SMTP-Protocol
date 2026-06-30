#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ranges>
#include <string_view>
#include <resolv.h>

#include "include/packet.h"
#include "include/lib.h"

#define PORT 25

int main(void)
{
    int sockfd;
    struct sockaddr_in serveraddr;

    email mail;

    mail.anvelopa.sender = "hoza.ciprian2016@gmail.com";
    mail.anvelopa.recipients.push_back("ceva@example.com");
    mail.anvelopa.recipients.push_back("altceva@gmail.com");
    mail.anvelopa.recipients.push_back("hoza.ciprian2005@gmail.com");
    mail.corp.headers["Subject:"] = "test email";
    mail.corp.headers["From:"] = "hoza.ciprian2016@gmail.com";
    mail.corp.body = "acesta este un mail de test";


    map<string, vector<string>> domenii = domains(mail.anvelopa.recipients);

    for (auto& [domain, usernames] : domenii)
    {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);

        //to do: resolve connections
    }
    

    return 0;
}