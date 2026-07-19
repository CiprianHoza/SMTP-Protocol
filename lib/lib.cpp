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

extern "C" {
    #include <spf2/spf.h>
}

struct SPFvalidation
{
    bool is_valid;
    string error_response = "";
    string observation = "";
};

struct MAILaddress
{
    string domain = "";
    string username = "";
};

SPFvalidation address_validity(const char* auxx, int sockfd);
string extract_address(string response);
vector<string> get_mx_servers(const string& domain);
MAILaddress split_address(const char* auxx);


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

SPFvalidation is_ehlo_good(char response[])
{
    char *p = strtok(response, " \r\n");

    SPFvalidation res;

    if (p == NULL)
    {
        res.is_valid = false;
        res.error_response = "500 Bad syntax\r\n";

        return res;
    }

    if (strncasecmp(p, "EHLO", 4) != 0)
    {
        res.is_valid = false;
        res.error_response = "501 Syntax: Not EHLO\r\n";

        return res;
    }

    p = strtok(NULL, " \r\n");
    if (p == NULL)
    {
        res.is_valid = false;
        res.error_response = "501 Syntax: EHLO requires an argument\r\n";

        return res;
    }
    
    return res;
}

email receive_email(int sockfd, SSL_CTX* ctx, string smtp_domain)
{
    int code;
    char response[1024];
    email mail;

    string mess = "220 " + smtp_domain + " ESMTP\r\n";

    code = send(sockfd, mess.c_str(), mess.length(), NULL);
    error(code);

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response) - 1, NULL);
    error(code);

    SPFvalidation val = is_ehlo_good(response);
    if (!val.is_valid)
    {
        code = send(sockfd, val.error_response.c_str(), val.error_response.length(), NULL);
        error(code);
        close(sockfd);
        return email();
    }

    mess.clear();
    mess = "250-" + smtp_domain + " Hello\r\n250 STARTTLS\r\n";
    
    code = send(sockfd, mess.c_str(), mess.length(), NULL);
    error(code);

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response) - 1, NULL);

    if (strncasecmp(response, "STARTTLS\r\n", 8) != 0)
    {
        mess.clear();
        mess = "450 TLS Encryption required\r\n";
        code = send(sockfd, mess.c_str(), mess.length(), NULL);

        error(code);
        close(sockfd);
        return email();
    }

    mess.clear();
    mess = "220 2.0.0 Ready to start TLS\r\n";
    code = send(sockfd, mess.c_str(), mess.length(), NULL);
    error(code);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    code = SSL_accept(ssl);

    if (code <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);

        return email();
    }

    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response) - 1);
    error(code);

    val = is_ehlo_good(response);
    if (!val.is_valid)
    {
        code = SSL_write(ssl, val.error_response.c_str(), val.error_response.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        return email();
    }

    mess.clear();
    mess = "250 OK\r\n";
    
    code = SSL_write(ssl, mess.c_str(), mess.length());
    error(code);

    //MAIL FROM
    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response) - 1);
    error(code);

    string address = extract_address(std::string(response));

    if (address == "")
    {
        perror("Error trying to parse the sender's address\n");
        mess.clear();
        mess = "501 Unable to fetch the sender\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        return email();
    }

    val = address_validity(address.c_str(), sockfd);

    if (!val.is_valid)
    {
        code = SSL_write(ssl, val.error_response.c_str(), val.error_response.length());
        SSL_free(ssl);
        close(sockfd);

        return email();
    }

    mail.anvelopa.sender = address;

    mess.clear();
    mess = "250 2.1.0 OK\r\n";
    code = SSL_write(ssl, mess.c_str(), mess.length());
    error(code);

    //RCPT TO WILL NOT HAVE A DATABASE JUST NOW (ONLY TESTING THE RECEIVING MECHANISM)
    MAILaddress adresa;

    do
    {
        memset(response, 0, sizeof(response));
        code = SSL_read(ssl, response, sizeof(response) - 1);
        error(code);
        
        if (strncasecmp(response, "DATA", 4) == 0)
            break;
        
        address = extract_address(string(response));

        if (address == "")
        {
            perror("Error trying to parse the recipient's address\n");
            mess.clear();
            mess = "501 Unable to fetch the recipient\r\n";
            code = SSL_write(ssl, mess.c_str(), mess.length());
            error(code);

            SSL_free(ssl);
            close(sockfd);
            return email();
        }

        adresa.domain.clear();
        adresa.username.clear();
        adresa = split_address(address.c_str());

        if (adresa.domain != smtp_domain)
        {
            mess.clear();
            mess = "550 This server does not operate with the given domain\r\n";
            code = SSL_write(ssl, mess.c_str(), mess.length());
            error(code);

            SSL_free(ssl);
            close(sockfd);
            return email();
        }

        mail.anvelopa.recipients.push_back(string(address));

        mess.clear();
        mess = "250 2.1.5 Recipient OK\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

    } while (strcasestr(response, "RCPT TO") != NULL);

    //to do DATA
}

string extract_address(string response)
{
    size_t start = response.find('<');
    size_t stop = response.find('>');

    if (start != std::string::npos && stop != std::string::npos && stop > start)
        return response.substr(start + 1, stop - start - 1);

    size_t colon = response.find(':');
    if (colon != std::string::npos)
    {
        string suff = response.substr(colon + 1);
        suff.erase(suff.find_last_not_of(" \r\n") + 1);
        suff.erase(0, suff.find_first_not_of(" \r\n"));

        return suff;
    }
    
    return "";
}

SPFvalidation address_validity(const char* auxx, int sockfd)
{
    SPFvalidation res;
    MAILaddress adresa;

    vector<string> mx_servers;
    struct sockaddr_in addr;
    socklen_t len;

    SPF_server_t* spf_server = nullptr;
    SPF_request_t* spf_request = nullptr;
    SPF_response_t* spf_response = nullptr;
    SPF_errcode_t err;
    SPF_result_t result;

    char hostname[NI_MAXHOST];
    struct addrinfo hints;
    struct addrinfo* res_addr = nullptr;
    bool rdns_match = false;

    char ip[INET_ADDRSTRLEN];

    //Address syntax check

    adresa = split_address(auxx);

    if (adresa.domain == "" && adresa.username == "")
    {
        res.is_valid = false;
        res.error_response = "501 5.1.7 Bad sender address syntax\r\n";
        goto cleanup;
    }
    
    /*
    END SYNTAX CHECK
    SPF validation
    */
    mx_servers = get_mx_servers(std::string(adresa.domain));
    
    if (mx_servers.size() == 0)
    {
        res.is_valid = false;
        res.error_response = "450 4.1.8 Sender address rejected: Domain not found\r\n";
        goto cleanup;
    }
    
    len = sizeof(addr);
    if (getpeername(sockfd, (struct sockaddr*)&addr, &len) < 0)
    {
        perror("Could not get the IP address of the client!\n");
        res.is_valid = false;
        res.error_response = "550 Error trying to verify the SPF authentication\r\n";
        goto cleanup;
    }

    spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
    if (spf_server == nullptr) {
        res.is_valid = false;
        res.error_response = "550 Internal SPF server error\r\n";
        goto cleanup;
    }

    spf_request = SPF_request_new(spf_server);
    if (spf_request == nullptr) {
        res.is_valid = false;
        res.error_response = "550 Internal SPF request error\r\n";
        goto cleanup;
    }

    SPF_request_set_helo_dom(spf_request, adresa.domain.c_str());

    inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN);
    SPF_request_set_ipv4_str(spf_request, ip);

    err = SPF_request_query_mailfrom(spf_request, &spf_response);

    if (err != SPF_E_SUCCESS)
    {
        perror("Error trying to verify the SPF authentication\n");
        res.is_valid = false;
        res.error_response = "550 Error trying to verify the SPF authentication\r\n";

        goto cleanup;
    }

    result = SPF_response_result(spf_response);

    if (result == SPF_RESULT_FAIL)
    {
        res.is_valid = false;
        res.error_response = "550 5.7.1 SPF authentication failed\r\n";
        goto cleanup;
    }
    else if (result != SPF_RESULT_PASS)
        res.observation = "SPF result unsure";
    
    /*
    END SPF VALIDATION
    Reverse DNS check
    */

    if (getnameinfo((struct sockaddr*)&addr, len, hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD) != 0)
    {
        res.observation += "\nReverse DNS failed: No PTR record found";
        goto cleanup;
    }
    else
    {
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname, NULL, &hints, &res_addr) == 0)
        {
            struct addrinfo* curr;

            for (curr = res_addr; curr != nullptr; curr = curr -> ai_next)
            {
                struct sockaddr_in* saddr = (struct sockaddr_in*)curr->ai_addr;
                
                if (saddr->sin_addr.s_addr == addr.sin_addr.s_addr)
                {
                    rdns_match = true;
                    break;
                }
            }

            freeaddrinfo(res_addr);
        }

        if (!rdns_match)
        {
            res.observation += "\nFCrDNS mismatch: " + string(hostname) + " does not point back to the client IP";
            goto cleanup;
        }
    }
    //END rDNS CHECK

    res.is_valid = true;

    cleanup:
        if (spf_response) SPF_response_free(spf_response);
        if (spf_request) SPF_request_free(spf_request);
        if (spf_server) SPF_server_free(spf_server);
        return res;
}

MAILaddress split_address(const char* auxx)
{
    char *user = (char*)malloc((strlen(auxx) + 1) * sizeof(char));
    char *domain = (char*)malloc((strlen(auxx) + 1) * sizeof(char));
    char *aux;
    char* address = (char*)malloc((strlen(auxx) + 1) * sizeof(char));

    MAILaddress adresa;

    strcpy(address, auxx);

    if (strchr(address, '@') == NULL)
        goto cleanup;

    aux = strtok(address, "@");
    if (aux == NULL)
        goto cleanup;

    strcpy(user, aux);
    aux = strtok(NULL, "@");
    if (aux == NULL)
        goto cleanup;

    strcpy(domain, aux);

    aux = strtok(NULL, "@");
    if (aux != NULL)
        goto cleanup;

    adresa.domain = string(domain);
    adresa.username = string(user);

    cleanup:
        free(user);
        free(domain);
        free(address);
        return adresa;
}

SSL_CTX* init_server_ssl_context()
{
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx)
    {
        perror("Couldn't create SSL context!");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, "/etc/letsencrypt/live/chmail.test-projects.dev/fullchain.pem") <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/etc/letsencrypt/live/chmail.test-projects.dev/privkey.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key doesn't match with the certificate!\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
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