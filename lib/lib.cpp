#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "include/packet.h"


void error(int code)
{
    if (code == -1)
        perror("Error send/receive fail!\n");
}

void check_error(char* response)
{
    char *p = strtok(response, " ");
    char error[20];

    if (strncmp(p, "250", 3) != 0 && strncmp(p, "354", 3) != 0 && strncmp(p, "220", 3) != 0)
    {
        sprintf(error, "%s bad response!\n", p);
        perror(error);
    }
}

void send_mail(int sockfd, email mail)
{
    int code;
    char response[1024];

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), NULL);
    error(code);

    check_error(response);

    //Init connection
    code = send(sockfd, "EHLO localhost\r\n", 16, NULL);
    error(code);

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), NULL);
    error(code);

    check_error(response);

    //Sending sender
    char cmd[256];
    sprintf(cmd, "MAIL FROM:<%s>\r\n", mail.anvelopa.sender.c_str());
    code = send(sockfd, cmd, strlen(cmd), NULL);
    error(code);
    
    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), NULL);
    error(code);

    check_error(response);

    //Sendind recipient(s)
    for (const auto& rec : mail.anvelopa.recipients)
    {
        char from[512];

        sprintf(from, "RCPT TO:<%s>\r\n", rec.c_str());

        code = send(sockfd, from, strlen(from), NULL);
        error(code);

        memset(response, 0, sizeof(response));
        code = recv(sockfd, response, sizeof(response), NULL);
        error(code);

        check_error(response);
    }

    //Sending DATA command
    code = send(sockfd, "DATA\r\n", 6, NULL);
    error(code);

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), NULL);
    error(code);

    check_error(response);
    
    //Sending headers
    for (const auto& pair : mail.corp.headers)
    {
        char mess[1024];

        sprintf(mess, "%s: %s\r\n", pair.first.c_str(), pair.second.c_str());

        code = send(sockfd, mess, strlen(mess), NULL);
        error(code);
    }

    //Sending body
    code = send(sockfd, "\r\n", 2, NULL);
    error(code);

    char message[1024];
    sprintf(message, "%s\r\n", mail.corp.body.c_str());

    code = send(sockfd, message, strlen(message), NULL);
    error(code);

    code = send(sockfd, ".\r\n", 3, NULL);
    error(code);

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), NULL);
    error(code);

    check_error(response);

    //Closing connection
    code = send(sockfd, "QUIT\r\n", 6, NULL);
    close(sockfd);
}