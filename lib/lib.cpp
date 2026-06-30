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

map<string, vector<string>> domains(vector<string> recipients)
{
    map<string, vector<string>> domenii;

    for (auto& rec : recipients)
    {
        auto parts = std::views::split(rec, '@')
                    | std::ranges::to<std::vector<std::string>>();

        if (parts.size() == 2)
        {
            string username = parts[0];
            string domain = parts[1];

            domenii[domain].push_back(username);
        }
    }

    return domenii;
}

vector<string> get_mx_servers(const string& domain)
{
    vector<string> mx_servers;

    unsigned char response[1024];

    res_init();

    int length = res_search(domain.c_str(), ns_c_in, ns_t_mx, response, sizeof(response));

    if (length < 0)
    {
        perror("Could not find the MX servers for the given domain!");
        return mx_servers;
    }

    ns_msg handle;
    if (ns_initparse(response, length, &handle) < 0)
    {
        perror("Error at initializing the DNS parser!");
        return mx_servers;
    }

    int count = ns_msg_count(handle, ns_s_an);

    for (int i = 0; i < count; i++)
    {
        ns_rr rr;

        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0)
            continue;
        
        if (ns_rr_type(rr) == ns_t_mx)
        {
            char host[NS_MAXDNAME];

            //skip the preference bytes
            const unsigned char* rdata = ns_rr_rdata(rr) + 2;

            if (ns_name_unpack(ns_msg_base(handle), ns_msg_end(handle), rdata,
                                (unsigned char*)host, sizeof(host)) >= 0)
            {
                char name[NS_MAXDNAME];

                if (ns_name_ntop((unsigned char*)host, name, sizeof(name)) >= 0)
                    mx_servers.push_back(string(name));
            }
        }
    }

    return mx_servers;
}