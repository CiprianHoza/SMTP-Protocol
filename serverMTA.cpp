#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "include/packet.h"
#include "include/lib.h"

#define PORT 2525
#define localhost "127.0.0.1"

int main(void)
{
    int sockfd;
    struct sockaddr_in serveraddr;

    email mail;

    mail.anvelopa.sender = "hoza.ciprian2016@gmail.com";
    mail.anvelopa.recipients.push_back("ceva@example.com");
    mail.corp.headers["Subject"] = "test email";
    mail.corp.body = "acesta este un mail de test";

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(PORT);
    int code = inet_pton(AF_INET, localhost, &serveraddr.sin_addr);

    if (code != 1)
        perror("Error trying to set the IPV4 address!\n");

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (connect(sockfd, (const struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
        perror("Connection to server failed!\n");
        return 1;
    }

    send_mail(sockfd, mail);

    return 0;
}