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


void error(int code)
{
    if (code == -1)
        perror("Error send/receive fail!\n");
    return;
}

void check_error(char* response)
{
    char *p = strtok(response, " ");

    if (strncmp(p, "250", 3) != 0 && strncmp(p, "354", 3) != 0 && strncmp(p, "220", 3) != 0)
    {
        string error = string(p) + " bad response!\n";
        cerr << error;
        return;
    }
}

void send_mail(int sockfd, email mail, string smtp_domain)
{
    int code;
    char response[1024];

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), NULL);
    error(code);

    check_error(response);

    //Init connection
    string init = "EHLO " + smtp_domain + "\r\n";
    send(sockfd, init.c_str(), init.length(), NULL);
    error(code);
    cout << "[SERVER] Sent EHLO\n";

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), NULL);
    error(code);

    check_error(response);

    cout << "[SERVER] Starting TLS...\n";

    //Starting TLS
    code = send(sockfd, "STARTTLS\r\n", 10, NULL);
    error(code);

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), NULL);
    error(code);

    check_error(response);

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    SSL* ssl = SSL_new(ctx);

    SSL_set_fd(ssl, sockfd);
    
    if (SSL_connect(ssl) <= 0)
    {
        perror("TLS handshake has failed!\n");
        return;
    }

    cout << "[SERVER] SSL configured\n";

    code = SSL_write(ssl, init.c_str(), init.length());
    error(code);

    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response));
    error(code);
    
    check_error(response);

    //Sending sender
    char cmd[256];
    sprintf(cmd, "MAIL FROM:<%s>\r\n", mail.anvelopa.sender.c_str());
    code = SSL_write(ssl, cmd, strlen(cmd));
    error(code);
    
    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response));
    error(code);

    check_error(response);

    //Sendind recipient(s)
    for (const auto& rec : mail.anvelopa.recipients)
    {
        char from[512];

        sprintf(from, "RCPT TO:<%s>\r\n", rec.c_str());

        code = SSL_write(ssl, from, strlen(from));
        error(code);

        memset(response, 0, sizeof(response));
        code = SSL_read(ssl, response, sizeof(response));
        error(code);

        check_error(response);
    }

    cout << "[SERVER] Sent recipients and sender\n";

    //Sending DATA command
    code = SSL_write(ssl, "DATA\r\n", 6);
    error(code);

    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response));
    error(code);

    check_error(response);
    
    //Sending headers
    for (const auto& pair : mail.corp.headers)
    {
        char mess[1024];

        sprintf(mess, "%s: %s\r\n", pair.first.c_str(), pair.second.c_str());

        code = SSL_write(ssl, mess, strlen(mess));
        error(code);
    }

    cout << "[SERVER] Sent headers\n";

    //Sending body
    code = SSL_write(ssl, "\r\n", 2);
    error(code);

    char message[1024];
    sprintf(message, "%s\r\n", mail.corp.body.c_str());

    code = SSL_write(ssl, message, strlen(message));
    error(code);

    code = SSL_write(ssl, ".\r\n", 3);
    error(code);

    cout << "[SERVER] Sent body\n";

    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response));
    error(code);

    check_error(response);

    //Closing connection
    code = SSL_write(ssl, "QUIT\r\n", 6);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    cout << "[SERVER] Closed socket connection\n";
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

void load_env(const string& filename = ".env")
{
    ifstream file(filename);

    if (!file.is_open())
    {
        perror("Could not open .env file!\n");
        return;
    }

    string line;
    while(getline(file, line))
    {
        if (line.empty() || line[0] == '#')
            continue;

        size_t delimitator = line.find('=');
        if (delimitator == std::string::npos)
            continue;
        
        string key = line.substr(0, delimitator);
        string value = line.substr(delimitator + 1);

        setenv(key.c_str(), value.c_str(), 1);
    }
}

string get_date()
{
    time_t now = time(nullptr);
    tm* now_tm = localtime(&now);

    char time[64];

    strftime(time, sizeof(time), "%a, %d %b %Y %H:%M:%S %z", now_tm);

    return string(time);
}