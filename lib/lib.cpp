#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <ranges>
#include <string_view>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <fstream>
#include <ctime>
#include <stdexcept>
#include <mysql/mysql.h>
#include <crypt.h>


#include "include/packet.h"
#include "include/lib.h"

extern "C" {
    #include <spf2/spf.h>
}

struct SPFvalidation
{
    bool is_valid;
    string error_response = "";
    string observation = "";
};

struct DMARCresult
{
    bool pass;
    string policy;
    string reason;
};

struct MAILaddress
{
    string domain = "";
    string username = "";
};

struct db_config
{
    string host = "127.0.0.1";
    string user = "";
    string password = "";
    string db_name = "";
    unsigned int port = 3306;
};

SPFvalidation address_validity(const char* auxx, int sockfd);
string extract_address(string response);
vector<string> get_mx_servers(const string& domain);
MAILaddress split_address(const char* auxx);
bool valid_email(string address, db_config& db);
email recv_email_wthehl(int sockfd, SSL* ssl, string mail_domain, bool is_auth);
string base64_decode(string input);
string base64_encode(const unsigned char* data, size_t len);
string clear_clr(string resp);
void print_err_ssl();
string canonicalize_header_relaxed(const string& header_name, const string& header_value);
string canonicalize_body_relaxed(const string& body);
string sign_dkim_openssl(const email& mail, const string& domain, const string& selector, const string& key_path);
bool verify_dkim(const email& mail);
DMARCresult verify_dmarc(const email& mail, bool spf_pass, const string& spf_domain, bool dkim_pass, const string& dkim_domain);


void error(int code)
{
    if (code <= 0)
    {
        sprint("Error send/receive fail!", '\n');
        throw std::runtime_error("Network I/O failure");
    }
}

void check_error(char* response)
{
    if (!response || strlen(response) < 3)
        throw std::runtime_error("Invalid response");

    char* saveptr;
    char *p = strtok_r(response, " ", &saveptr);

    if (strncmp(p, "250", 3) != 0 && strncmp(p, "354", 3) != 0 && strncmp(p, "220", 3) != 0)
    {
        string error = string(p) + " bad response!\n";
        sprint(error);
        throw std::runtime_error("SMTP error");
    }
}

void send_mail(int sockfd, email mail, string smtp_domain)
{
    int code;
    char response[1024];

    SSL* ssl = nullptr;
    SSL_CTX* ctx = nullptr;

    try
    {
        memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), 0);
    error(code);

    check_error(response);

    //Init connection
    string init = "EHLO " + smtp_domain + "\r\n";
    send(sockfd, init.c_str(), init.length(), 0);
    error(code);
    sprint("[CLIENT ", this_thread::get_id(), "] Sent EHLO", '\n');

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), 0);
    error(code);

    check_error(response);

    sprint("[CLIENT ", this_thread::get_id(), "] Starting TLS...", '\n');

    //Starting TLS
    code = send(sockfd, "STARTTLS\r\n", 10, 0);
    error(code);

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response), 0);
    error(code);

    check_error(response);

    const SSL_METHOD* method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    ssl = SSL_new(ctx);

    SSL_set_fd(ssl, sockfd);
    
    if (SSL_connect(ssl) <= 0)
    {
        sprint("[CLIENT ", this_thread::get_id(), "] TLS handshake has failed!", '\n');
        return;
    }

    sprint("[CLIENT ", this_thread::get_id(), "] SSL configured", '\n');

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

    sprint("[CLIENT ", this_thread::get_id(), "] Sent recipients and sender", '\n');

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

    sprint("[CLIENT ", this_thread::get_id(), "] Sent headers", '\n');

    //Sending body
    code = SSL_write(ssl, "\r\n", 2);
    error(code);

    string full_body = mail.corp.body + "\r\n";
    code = SSL_write(ssl, full_body.c_str(), full_body.length());
    error(code);

    code = SSL_write(ssl, ".\r\n", 3);
    error(code);

    sprint("[CLIENT ", this_thread::get_id(), "] Sent body", '\n');

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

    sprint("[CLIENT ", this_thread::get_id(), "] Closed socket connection", '\n');
    }
    catch(const std::exception& e)
    {
        sprint("[MTA Client error ", this_thread::get_id(), "] ", e.what(), '\n');

        if (ssl)
        {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }
        close(sockfd);
    }   
}

SPFvalidation is_ehlo_good(char response[])
{
    char *saveptr;
    char *p = strtok_r(response, " \r\n", &saveptr);

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

    p = strtok_r(NULL, " \r\n", &saveptr);
    if (p == NULL)
    {
        res.is_valid = false;
        res.error_response = "501 Syntax: EHLO requires an argument\r\n";

        return res;
    }

    res.is_valid = true;
    
    return res;
}

email receive_from_ua(int sockfd, SSL_CTX* ctx, string smtp_domain, string mail_domain)
{
    int code;
    char response[1024];
    email mail;

    SSL* ssl = nullptr;

    string mess = "220 " + smtp_domain + " ESMTP Server Ready\r\n";

    try
    {
    code = send(sockfd, mess.c_str(), mess.length(), 0);
    error(code);
    
    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response) - 1, 0);
    error(code);

    SPFvalidation val;

    val = is_ehlo_good(response);

    if (!val.is_valid)
    {
        code = send(sockfd, val.error_response.c_str(), val.error_response.length(), 0);
        error(code);

        close(sockfd);

        return email();
    }

    mess.clear();
    mess = "250-" + smtp_domain + " Hello\r\n250-STARTTLS\r\n250 AUTH LOGIN\r\n";
    code = send(sockfd, mess.c_str(), mess.length(), 0);
    error(code);

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response) - 1, 0);
    error(code);

    if (strncasecmp(response, "STARTTLS", 8) != 0)
    {
        mess.clear();
        mess = "450 TLS Encryption required\r\n";
        code = send(sockfd, mess.c_str(), mess.length(), 0);

        error(code);
        close(sockfd);
        return email();
    }

    mess.clear();
    mess = "220 2.0.0 Ready to start TLS\r\n";
    code = send(sockfd, mess.c_str(), mess.length(), 0);
    error(code);

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    code = SSL_accept(ssl);

    if (code <= 0)
    {
        print_err_ssl();
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
    mess = "250-Hello\r\n250 AUTH LOGIN\r\n";
    code = SSL_write(ssl, mess.c_str(), mess.length());
    error(code);

    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response) - 1);
    error(code);

    mess.clear();
    mess = "334 VXNlcm5hbWU6\r\n";
    code = SSL_write(ssl, mess.c_str(), mess.length());
    error(code);

    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response) - 1);
    error(code);

    string clean_user = clear_clr(string(response));
    string username = base64_decode(clean_user);

    mess.clear();
    mess = "334 UGFzc3dvcmQ6\r\n";
    code = SSL_write(ssl, mess.c_str(), mess.length());
    error(code);

    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response) - 1);
    error(code);

    string clean_pass = clear_clr(string(response));
    string password = base64_decode(clean_pass);

    MYSQL* conn = mysql_init(NULL);

    if (conn == NULL)
    {
        sprint("[CLIENT ", this_thread::get_id(), "] Error trying to establish mysql connection", '\n');
        mess.clear();
        mess = "550 Error trying to acces the database. Try again later\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        return email();
    }

    db_config db;

    const char* env_user = getenv("DB_USER");
    const char* env_pass = getenv("DB_PASS");
    const char* env_table = getenv("DB_TABLE");

    db.db_name = string(env_table);
    db.user = string(env_user);
    db.password = string(env_pass);

    if (mysql_real_connect(conn,
                           db.host.c_str(),
                           db.user.c_str(),
                           db.password.c_str(),
                           db.db_name.c_str(),
                           db.port, NULL, 0) == NULL)
    {
        sprint("[CLIENT ", this_thread::get_id(), "] Error trying to connect to the database: ", mysql_error(conn), '\n');
        mess.clear();
        mess = "550 Error trying to acces the database. Try again later\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        mysql_close(conn);
        return email();
    }

    char escaped_email[256] = {0};
    mysql_real_escape_string(conn, escaped_email, username.c_str(), username.length());

    string query = "SELECT Password FROM " + db.db_name + " WHERE Username = '" + string(escaped_email) + "' LIMIT 1;";

    if (mysql_query(conn, query.c_str()) != 0)
    {
        sprint("[CLIENT ", this_thread::get_id(), "] Error MYSQL qeury: ", mysql_error(conn), '\n');
        
        mess.clear();
        mess = "550 Error trying to acces the database. Try again later\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        mysql_close(conn);
        return email();
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (result == NULL)
    {
        mess.clear();
        mess = "550 Error trying to acces the database. Try again later\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        mysql_close(conn);
        return email();
    }

    string password_db = "";
    MYSQL_ROW row = mysql_fetch_row(result);

    if (row && row[0])
        password_db = row[0];
    
    mysql_free_result(result);
    mysql_close(conn);

    struct crypt_data data;
    data.initialized = 0;

    if (password_db.empty())
    {
        mess.clear();
        mess = "535 5.7.8 Authentication failed\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        return email();
    }

    char* gen_hash = crypt_r(password.c_str(), password_db.c_str(), &data);

    if (gen_hash == nullptr)
    {
        sprint("[CLIENT ", this_thread::get_id(), "] Error trying to verify the hashes", '\n');
        mess.clear();
        mess = "550 Error trying to verify the hashes. Try again later\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        return email();
    }

    if (password_db != string(gen_hash))
    {
        sprint("[CLIENT ", this_thread::get_id(), "] Error: Passwords do not match", '\n');

        mess.clear();
        mess = "535 5.7.8 Authentication failed\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        return email();
    }

    mess.clear();
    mess = "235 2.7.0 Authentication successful\r\n";
    code = SSL_write(ssl, mess.c_str(), mess.length());
    error(code);  
    }
    catch(const std::exception& e)
    {
        sprint("[MTA Client error ", this_thread::get_id(), e.what(), '\n');

        if (ssl)
            SSL_free(ssl);
        close(sockfd);

        return email();
    }
    
    return recv_email_wthehl(sockfd, ssl, mail_domain, true);
}

email receive_email(int sockfd, SSL_CTX* ctx, string smtp_domain, string mail_domain)
{
    int code;
    char response[1024];
    email mail;

    SSL* ssl = nullptr;

    string mess = "220 " + smtp_domain + " ESMTP\r\n";

    try
    {
        code = send(sockfd, mess.c_str(), mess.length(), 0);
    error(code);

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response) - 1, 0);
    error(code);

    sprint("[SERVER ", this_thread::get_id(), "] Sent hello message", '\n');

    SPFvalidation val = is_ehlo_good(response);
    if (!val.is_valid)
    {
        code = send(sockfd, val.error_response.c_str(), val.error_response.length(), 0);
        error(code);
        close(sockfd);
        return email();
    }

    mess.clear();
    mess = "250-" + smtp_domain + " Hello\r\n250 STARTTLS\r\n";
    
    code = send(sockfd, mess.c_str(), mess.length(), 0);
    error(code);

    memset(response, 0, sizeof(response));
    code = recv(sockfd, response, sizeof(response) - 1, 0);

    if (strncasecmp(response, "STARTTLS\r\n", 8) != 0)
    {
        mess.clear();
        mess = "450 TLS Encryption required\r\n";
        code = send(sockfd, mess.c_str(), mess.length(), 0);

        error(code);
        close(sockfd);
        return email();
    }

    mess.clear();
    mess = "220 2.0.0 Ready to start TLS\r\n";
    code = send(sockfd, mess.c_str(), mess.length(), 0);
    error(code);

    sprint("[SERVER ", this_thread::get_id(), "] Starting TLS...", '\n');

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    code = SSL_accept(ssl);

    if (code <= 0)
    {
        print_err_ssl();
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

    sprint("[SERVER ", this_thread::get_id(), "] TLS established", '\n');
    }
    catch(const std::exception& e)
    {
        sprint("[MTA Server error ", this_thread::get_id(), "] ", e.what(), '\n');

        if (ssl)
            SSL_free(ssl);
        close(sockfd);

        return email();
    }

    return recv_email_wthehl(sockfd, ssl, mail_domain, false);
}

email recv_email_wthehl(int sockfd, SSL* ssl, string mail_domain, bool is_auth)
{
    char response[1024];
    int code;

    email mail;
    string mess;

    try
    {
    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response) - 1);
    error(code);

    string address = extract_address(std::string(response));

    if (address == "")
    {
        sprint("[SERVER ", this_thread::get_id(), "] Error trying to parse the sender's address", '\n');
        mess.clear();
        mess = "501 Unable to fetch the sender\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        return email();
    }

    SPFvalidation val;
    if (!is_auth)
        val = address_validity(address.c_str(), sockfd);

    if (!val.is_valid && !is_auth)
    {
        code = SSL_write(ssl, val.error_response.c_str(), val.error_response.length());
        SSL_free(ssl);
        close(sockfd);

        return email();
    }

    sprint("[SERVER ", this_thread::get_id(), "] Sender received!", '\n');

    if (!is_auth)
    {
        if (val.observation != "")
        {
            mail.corp.headers["X-SPF-Status"] = "FAIL / UNSURE";
            mail.corp.headers["X-SPF-Mess"] = val.observation;
        }
        else
            mail.corp.headers["X-SPF-Status"] = "PASS";
    }

    bool spf_pass = val.is_valid && val.observation.empty();


    mail.anvelopa.sender = address;

    mess.clear();
    mess = "250 2.1.0 OK\r\n";
    code = SSL_write(ssl, mess.c_str(), mess.length());
    error(code);

    MAILaddress adresa;
    db_config db;

    do
    {
        memset(response, 0, sizeof(response));
        code = SSL_read(ssl, response, sizeof(response) - 1);
        error(code);
        
        if (strncasecmp(response, "DATA", 4) == 0 || strncasecmp(response, "QUIT", 4) == 0)
            break;
        
        address = extract_address(string(response));

        if (address == "")
        {
            sprint("[SERVER ", this_thread::get_id(), "] Error trying to parse the recipient's address", '\n');
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

        if (adresa.domain != mail_domain && !is_auth)
        {
            mess.clear();
            mess = "550 This server does not operate with the given domain\r\n";
            code = SSL_write(ssl, mess.c_str(), mess.length());
            error(code);

            SSL_free(ssl);
            close(sockfd);
            return email();
        }

        if (adresa.domain == mail_domain && !valid_email(address, db))
        {
            mess.clear();
            mess = "550 5.1.1 <" + address + "> User unknown\r\n";
            code = SSL_write(ssl, mess.c_str(), mess.length());
            error(code);

            continue;
        }

        mail.anvelopa.recipients.push_back(string(address));

        mess.clear();
        mess = "250 2.1.5 Recipient OK\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

    } while (strcasestr(response, "RCPT TO") != NULL);

    if (strncasecmp(response, "QUIT", 4) == 0)
    {
        mess.clear();
        mess = "221 2.0.0 Bye\r\n";

        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        
        return email();
    }

    sprint("[SERVER ", this_thread::get_id(), "] Recipients received!", '\n');

    mess.clear();
    mess = "354 Start mail input; end with <CR><LF>.<CR><LF>\r\n";
    code = SSL_write(ssl, mess.c_str(), mess.length());
    error(code);

    string raw_email = "";
    char chunk[4096];

    size_t dot_pos;
    while(true)
    {
        memset(chunk, 0, sizeof(chunk));
        code = SSL_read(ssl, chunk, sizeof(chunk) - 1);
        error(code);

        raw_email.append(chunk, code);

        dot_pos = raw_email.find("\r\n.\r\n");
        if (dot_pos != string::npos)
        {
            raw_email.erase(dot_pos);
            break;
        }
    }


    mail.corp.raw_mail = raw_email;

    sprint("[SERVER ", this_thread::get_id(), "] Raw email received!", '\n');

    //EMAIL PARSING

    size_t header_end = raw_email.find("\r\n\r\n");

    if (header_end == string::npos)
    {
        sprint("[SERVER ", this_thread::get_id(), "] Email structure is wrong", '\n');

        mess.clear();
        mess = "450 Email structure is wrong\r\n";
        code = SSL_write(ssl, mess.c_str(), mess.length());
        error(code);

        SSL_free(ssl);
        close(sockfd);
        return email();
    }

    string headers = "";
    string body = "";

    if (header_end != string::npos)
    {
        headers = raw_email.substr(0, header_end);
        body = raw_email.substr(header_end + 4);
    }

    stringstream ss(headers);
    string line;
    string last_key = "";

    while(getline(ss, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        
        if ((line[0] == ' ' || line[0] == '\t') && !last_key.empty())
        {
            size_t start = line.find_first_not_of(" \t");
            if (start != string::npos)
                mail.corp.headers[last_key] += " " + line.substr(start);

            continue;
        }

        size_t colon = line.find(':');

        if (colon != string::npos)
        {
            string key = line.substr(0, colon);
            string value = line.substr(colon + 1);

            size_t val_start = value.find_first_not_of(" \t");
            if (val_start != string::npos)
                value = value.substr(val_start);
            else
                value = "";
            
            last_key = key;
            mail.corp.headers[key] = value;
        }
    }

    mail.corp.body = body;

    if (!is_auth)
    {
        bool dkim_ok = verify_dkim(mail);
    if (dkim_ok)
        mail.corp.headers["X-DKIM-Status"] = "PASS";
    else
        mail.corp.headers["X-DKIM-Status"] = "FAIL";

    MAILaddress sender_mail = split_address(mail.anvelopa.sender.c_str());
    string dkim_domain = "";

    auto dkim_it = mail.corp.headers.find("DKIM-Signature");
    if (dkim_it != mail.corp.headers.end())
    {
        size_t d_pos = dkim_it->second.find("d=");
        if (d_pos != string::npos)
        {
            dkim_domain = dkim_it->second.substr(d_pos + 2);
            size_t end_d = dkim_domain.find_first_of("; ");
            if (end_d != string::npos)
                dkim_domain = dkim_domain.substr(0, end_d);
        }
    }

    DMARCresult dmarc = verify_dmarc(mail, spf_pass, sender_mail.domain, dkim_ok, dkim_domain);
    sprint("[SERVER ", this_thread::get_id(), "] DMARC Status: ", (dmarc.pass ? "PASS" : "FAIL"), 
           " (Policy: ", dmarc.policy, ")\n");
        
    if (!dmarc.pass)
    {
        if (dmarc.policy == "reject")
        {
           sprint("[SERVER ", this_thread::get_id(), "] Rejecting email due to DMARC policy 'reject'\n");
           mess.clear();
           mess = "550 5.7.1 Email rejected per DMARC policy\r\n";
           code = SSL_write(ssl, mess.c_str(), mess.length());
           error(code);

           SSL_free(ssl);
           close(sockfd);
           return email();
        }

        else if (dmarc.policy == "quarantine")
        {
            mail.corp.headers["X-Spam-Flag"] = "YES";
            mail.corp.headers["X-DMARC-Status"] = "FAIL (Quarantine)";
            mail.corp.headers["X-DMARC-Mess"] = dmarc.reason;
        }
        else
        {
            if (!spf_pass)
            {
                mail.corp.headers["X-Spam-Flag"] = "YES";
                mail.corp.headers["X-Spam-Mess"] = val.observation;
            }
            else
                mail.corp.headers["X-Spam-Flag"] = "NO";
            
            mail.corp.headers["X-DMARC-Status"] = "FAIL (None)";
        }
    }
    else
    {
        mail.corp.headers["X-DMARC-Status"] = "PASS";
        mail.corp.headers["X-Spam-Flag"] = "NO";
    }
    }

    mess.clear();
    mess = "250 2.0.0 OK (Mail accepted for delivery)\r\n";
    code = SSL_write(ssl, mess.c_str(), mess.length());
    error(code);

    sprint("[SERVER ", this_thread::get_id(), "] Mail accepted!", '\n');

    memset(response, 0, sizeof(response));
    code = SSL_read(ssl, response, sizeof(response) - 1);
    error(code);

    mess.clear();
    mess = "221 2.0.0 Bye\r\n";

    code = SSL_write(ssl, mess.c_str(), mess.length());
    error(code);

    SSL_free(ssl);
    close(sockfd);
    }
    catch(const std::exception& e)
    {
        sprint("[MTA Server error ", this_thread::get_id(), "] ", e.what(), '\n');

        if (ssl)
            SSL_free(ssl);
        close(sockfd);

        return email();
    }
    
    return mail;
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
        sprint("[ERROR ", this_thread::get_id(), "] Could not get the IP address of the client!", '\n');
        res.is_valid = false;
        res.error_response = "550 Error trying to verify the SPF authentication\r\n";
        goto cleanup;
    }

    spf_server = SPF_server_new(SPF_DNS_RESOLV, 0);
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
        sprint("[ERROR ", this_thread::get_id(), "] Error trying to verify the SPF authentication", '\n');
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

    char *saveptr;
    aux = strtok_r(address, "@", &saveptr);
    if (aux == NULL)
        goto cleanup;

    strcpy(user, aux);
    aux = strtok_r(NULL, "@", &saveptr);
    if (aux == NULL)
        goto cleanup;

    strcpy(domain, aux);

    aux = strtok_r(NULL, "@", &saveptr);
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
        sprint("[ERROR ", this_thread::get_id(), "] Couldn't create SSL context!", '\n');
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, "/etc/letsencrypt/live/chmail.test-projects.dev/fullchain.pem") <= 0)
    {
        print_err_ssl();
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/etc/letsencrypt/live/chmail.test-projects.dev/privkey.pem", SSL_FILETYPE_PEM) <= 0)
    {
        print_err_ssl();
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        sprint("[ERROR ", this_thread::get_id(), "] Private ket doesn't match with the certificate!", '\n');
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void print_err_ssl()
{
    unsigned long err_code = ERR_get_error();

    if (err_code)
    {
        char err_buff[256];
        ERR_error_string_n(err_code, err_buff, sizeof(err_buff));
        sprint("[ERROR ", this_thread::get_id(), "] OpenSSL error: ", err_buff);
    }
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

    struct __res_state stat;
    memset(&stat, 0, sizeof(stat));
    if (res_ninit(&stat) != 0)
        return mx_servers;

    int length = res_nsearch(&stat, domain.c_str(), ns_c_in, ns_t_mx, response, sizeof(response));

    if (length < 0)
    {
        sprint("[ERROR ", this_thread::get_id(), "] Could not find the MX servers for the given domain!", '\n');
        res_nclose(&stat);
        return mx_servers;
    }

    ns_msg handle;
    if (ns_initparse(response, length, &handle) < 0)
    {
        sprint("[ERROR ", this_thread::get_id(), "] Error at initializing the DNS parser!", '\n');
        res_nclose(&stat);
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

    res_nclose(&stat);
    return mx_servers;
}

void load_env(const string& filename)
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
    tm now_tm;
    localtime_r(&now, &now_tm);

    char time[64];

    strftime(time, sizeof(time), "%a, %d %b %Y %H:%M:%S %z", &now_tm);

    return string(time);
}

string read_lmtp_response(int lmtp_fd)
{
    char buffer[1024] = {0};
    int bytes_read = recv(lmtp_fd, buffer, sizeof(buffer) - 1, 0);

    if (bytes_read > 0)
        return string(buffer, bytes_read);
    return "";
}

bool deliver_to_dovecot_lmtp(email& mail)
{
    int lmtp_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lmtp_fd < 0)
        return false;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/var/run/dovecot/lmtp", sizeof(addr.sun_path) - 1);

    if (connect(lmtp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        sprint("[ERROR ", this_thread::get_id(), "] Error trying to connect to the Dovecot socket", '\n');
        close(lmtp_fd);
        return false;
    }

    read_lmtp_response(lmtp_fd);

    auto send_cmd = [lmtp_fd](const string& cmd) 
    {
        send(lmtp_fd, cmd.c_str(), cmd.length(), 0);
        return read_lmtp_response(lmtp_fd);
    };

    send_cmd("LHLO localhost\r\n");
    send_cmd("MAIL FROM:<" + mail.anvelopa.sender + ">\r\n");

    size_t rcpt_count = mail.anvelopa.recipients.size();

    for (const auto& rcpt : mail.anvelopa.recipients)
        send_cmd("RCPT TO:<" + rcpt + ">\r\n");
    
    string data_resp = send_cmd("DATA\r\n");
    if (data_resp.substr(0, 3) != "354")
    {
        close(lmtp_fd);
        return false;
    }

    string payload = mail.corp.raw_mail;

    if (payload.length() < 2 || payload.substr(payload.length() - 2) != "\r\n")
        payload += "\r\n";
    
    payload += ".\r\n";

    send(lmtp_fd, payload.c_str(), payload.length(), 0);

    bool ok = true;
    for (size_t i = 0; i < rcpt_count; i++)
    {
        string resp = read_lmtp_response(lmtp_fd);

        if (resp.substr(0, 3) != "250")
            ok = false;
    }

    send_cmd("QUIT\r\n");
    close(lmtp_fd);

    return ok;
}

bool valid_email(string address, db_config& db)
{
    MYSQL* conn = mysql_init(NULL);

    if (conn == NULL)
    {
        sprint("[ERROR ", this_thread::get_id(), "] Error trying to establish mysql connection", '\n');
        return false;
    }

    const char* env_user = getenv("DB_USER");
    const char* env_pass = getenv("DB_PASS");
    const char* env_table = getenv("DB_TABLE");

    db.db_name = string(env_table);
    db.user = string(env_user);
    db.password = string(env_pass);

    if (mysql_real_connect(conn,
                           db.host.c_str(),
                           db.user.c_str(),
                           db.password.c_str(),
                           db.db_name.c_str(),
                           db.port, NULL, 0) == NULL)
    {
        sprint("[ERROR ", this_thread::get_id(), "] Error trying to connect to the database: ", mysql_error(conn), '\n');
        mysql_close(conn);
        return false;
    }

    char escaped_email[256] = {0};
    mysql_real_escape_string(conn, escaped_email, address.c_str(), address.length());

    string query = "SELECT 1 FROM " + db.db_name + " WHERE Username = '" + string(escaped_email) + "' LIMIT 1;";

    if (mysql_query(conn, query.c_str()) != 0)
    {
        sprint("[ERROR ", this_thread::get_id(), "] Error MYSQL query: ", mysql_error(conn), '\n');
        mysql_close(conn);

        return false;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    bool ok = false;

    if (result)
    {
        if (mysql_num_rows(result) == 1)
            ok = true;
        mysql_free_result(result);
    }

    mysql_close(conn);

    return ok;
}

string base64_decode(string input)
{
    BIO *bio, *b64;
    int decodeLen = input.length();

    vector<char> buffer(decodeLen);

    bio = BIO_new_mem_buf(input.data(), input.length());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    int len = BIO_read(bio, buffer.data(), input.length());
    BIO_free_all(bio);

    return (len > 0) ? string(buffer.data(), len) : "";
}

string base64_encode(const unsigned char* data, size_t len)
{
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return result;
}

string canonicalize_header_relaxed(const string& key, const string& val) 
{
    string k = key;
    transform(k.begin(), k.end(), k.begin(), ::tolower);
    
    k.erase(k.find_last_not_of(" \t\r\n") + 1);

    string v = val;
    string v_clean = "";
    bool last_was_space = false;

    for (char c : v) {
        if (c == '\r' || c == '\n' || c == '\t' || c == ' ') {
            if (!last_was_space) {
                v_clean += ' ';
                last_was_space = true;
            }
        } else {
            v_clean += c;
            last_was_space = false;
        }
    }

    size_t start = v_clean.find_first_not_of(" ");
    size_t end = v_clean.find_last_not_of(" ");
    
    if (start != string::npos && end != string::npos) {
        v_clean = v_clean.substr(start, end - start + 1);
    } else {
        v_clean = "";
    }

    return k + ": " + v_clean;
}

string canonicalize_body_relaxed(const string& body)
{
    string result = body;

    while (!result.empty() && (result.back() == '\r' || result.back() == '\n'))
        result.pop_back();

    vector<string> lines;
    stringstream ss(result);
    string line;
    while (getline(ss, line))
    {
        size_t end = line.find_last_not_of(" \t\r\n");
        if (end != string::npos)
            line = line.substr(0, end + 1);
        else
            line = "";

        lines.push_back(line);
    }

    while (!lines.empty() && lines.back().empty())
        lines.pop_back();

    string canonical;
    for (size_t i = 0; i < lines.size(); ++i)
    {
        canonical += lines[i];
        if (i < lines.size() - 1)
            canonical += "\r\n";
    }
    if (canonical.empty())
        return "\r\n";

    return canonical + "\r\n";
}

string sign_dkim_openssl(const email& mail, const string& domain, const string& selector, const string& key_path)
{
    try
    {
        FILE* key_file = fopen(key_path.c_str(), "r");
        if (!key_file)
        {
            sprint("[ERROR ", this_thread::get_id(), "] Could not open DKIM key file: ", key_path, '\n');
            return "";
        }

        EVP_PKEY* pkey = PEM_read_PrivateKey(key_file, nullptr, nullptr, nullptr);
        fclose(key_file);

        if (!pkey)
        {
            sprint("[ERROR ", this_thread::get_id(), "] Could not read DKIM private key", '\n');
            return "";
        }

        string headers_to_sign;
        vector<string> header_list;
        for (const auto& pair : mail.corp.headers)
        {
            string canonical = canonicalize_header_relaxed(pair.first, pair.second);
            headers_to_sign += canonical + "\r\n";
            header_list.push_back(pair.first);
        }

        if (!headers_to_sign.empty() && headers_to_sign.length() >= 2)
            headers_to_sign = headers_to_sign.substr(0, headers_to_sign.length() - 2);

        string canonical_body = canonicalize_body_relaxed(mail.corp.body);

        unsigned char header_hash[EVP_MAX_MD_SIZE];
        unsigned int header_hash_len = 0;
        EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();
        EVP_DigestInit(hash_ctx, EVP_sha256());
        EVP_DigestUpdate(hash_ctx, (unsigned char*)headers_to_sign.c_str(), headers_to_sign.length());
        EVP_DigestFinal(hash_ctx, header_hash, &header_hash_len);

        unsigned char body_hash[EVP_MAX_MD_SIZE];
        unsigned int body_hash_len = 0;
        EVP_DigestInit(hash_ctx, EVP_sha256());
        EVP_DigestUpdate(hash_ctx, (unsigned char*)canonical_body.c_str(), canonical_body.length());
        EVP_DigestFinal(hash_ctx, body_hash, &body_hash_len);
        EVP_MD_CTX_free(hash_ctx);

        string body_hash_b64 = base64_encode(body_hash, body_hash_len);

        time_t now = time(nullptr);
        string sig_header = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + domain + "; s=" + selector +
                           "; t=" + to_string(now) + "; bh=" + body_hash_b64 + "; h=";

        for (size_t i = 0; i < header_list.size(); ++i)
        {
            string h = header_list[i];
            transform(h.begin(), h.end(), h.begin(), ::tolower);
            sig_header += h;
            if (i < header_list.size() - 1)
                sig_header += ":";
        }

        sig_header += "; b=";

        string data_to_sign = headers_to_sign + "\r\n" + canonicalize_header_relaxed("DKIM-Signature", sig_header);

        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx)
        {
            sprint("[ERROR ", this_thread::get_id(), "] Could not create EVP context", '\n');
            EVP_PKEY_free(pkey);
            return "";
        }

        if (EVP_SignInit(md_ctx, EVP_sha256()) != 1)
        {
            sprint("[ERROR ", this_thread::get_id(), "] Could not initialize signing", '\n');
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            return "";
        }

        EVP_SignUpdate(md_ctx, (unsigned char*)data_to_sign.c_str(), data_to_sign.length());

        unsigned char signature[512];
        unsigned int sig_len = 0;

        if (EVP_SignFinal(md_ctx, signature, &sig_len, pkey) != 1)
        {
            sprint("[ERROR ", this_thread::get_id(), "] Signing failed", '\n');
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            return "";
        }

        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);

        string sig_b64 = base64_encode(signature, sig_len);

        string dkim_sig = "DKIM-Signature: " + sig_header + sig_b64;

        sprint("[CLIENT ", this_thread::get_id(), "] DKIM signature generated successfully", '\n');
        return dkim_sig;
    }
    catch (const exception& e)
    {
        sprint("[ERROR ", this_thread::get_id(), "] DKIM signing error: ", e.what(), '\n');
        return "";
    }
}

string clear_clr(string resp)
{
    size_t last = resp.find_last_not_of(" \r\n");
    if (last != string::npos)
        return resp.substr(0, last + 1);
    return resp;
}

string sign_dkim(const email& email, const string& domain, const string& selector, const string& key_path)
{
    return sign_dkim_openssl(email, domain, selector, key_path);
}

string get_dkim_pkey(const string& domain, const string& selector)
{
    string dkim_dns = selector + "._domainkey." + domain;
    unsigned char response[2048];

    struct __res_state stat;
    memset(&stat, 0, sizeof(stat));
    if (res_ninit(&stat) != 0)
        return "";
    
    int length = res_nsearch(&stat, dkim_dns.c_str(), ns_c_in, ns_t_txt, response, sizeof(response));
    if (length < 0)
    {
        res_nclose(&stat);
        return "";
    }

    ns_msg handle;
    if (ns_initparse(response, length, &handle) < 0)
    {
        res_nclose(&stat);
        return "";
    }

    string txt_record = "";
    int count = ns_msg_count(handle, ns_s_an);
    
    for (int i = 0; i < count; i++)
    {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0)
            continue;
        
        if (ns_rr_type(rr) == ns_t_txt)
        {
            const unsigned char* rdata = ns_rr_rdata(rr);
            int rdlength = ns_rr_rdlen(rr);
            int off = 0;

            // Reconstruim tot record-ul TXT chiar dacă este fragmentat în bucăți de 255 octeți
            while (off < rdlength) {
                int len = rdata[off];
                off++;
                if (off + len <= rdlength) {
                    txt_record.append((const char*)(rdata + off), len);
                }
                off += len;
            }
            break;
        }
    }

    res_nclose(&stat);

    if (txt_record.empty())
        return "";

    // Căutăm p= în textul asamblat
    size_t pos = txt_record.find("p=");
    if (pos == string::npos)
        return "";

    string pkey = txt_record.substr(pos + 2);
    
    // Tăiem până la primul punct și virgulă dacă există
    size_t end_p = pkey.find(';');
    if (end_p != string::npos)
        pkey = pkey.substr(0, end_p);

    // SANITIZARE CRUCIALĂ PENTRU OPENSSL:
    // Eliminăm spațiile, newline-urile, tab-urile și GHILIMELELE (")
    string clean_pkey = "";
    for (char c : pkey) {
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != '"' && c != '\'') {
            clean_pkey += c;
        }
    }
    
    return clean_pkey;
}

bool verify_dkim(const email& mail)
{
    try
    {
        size_t header_end = mail.corp.raw_mail.find("\r\n\r\n");
        if (header_end == string::npos) {
            header_end = mail.corp.raw_mail.find("\n\n");
        }

        string raw_headers_str = (header_end != string::npos) ? mail.corp.raw_mail.substr(0, header_end) : mail.corp.raw_mail;
        struct RawHeader {
            string key;
            string value;
            bool used_for_dkim = false;
        };
        vector<RawHeader> parsed_headers;

        stringstream raw_ss(raw_headers_str);
        string line;
        while (getline(raw_ss, line)) {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
                if (!parsed_headers.empty()) {
                    // unfold continuation: replace CRLF + WSP with single space
                    size_t start = line.find_first_not_of(" \t");
                    if (start != string::npos)
                        parsed_headers.back().value += " " + line.substr(start);
                    else
                        parsed_headers.back().value += " ";
                }
            } else {
                size_t colon_pos = line.find(':');
                if (colon_pos != string::npos) {
                    string k = line.substr(0, colon_pos);
                    string v = (colon_pos + 1 < line.size()) ? line.substr(colon_pos + 1) : string();
                    // trim leading whitespace from value
                    size_t vs = v.find_first_not_of(" \t");
                    if (vs != string::npos)
                        v = v.substr(vs);
                    else
                        v = "";
                    parsed_headers.push_back({k, v, false});
                }
            }
        }

        string dkim_val = "";
        for (auto it = parsed_headers.rbegin(); it != parsed_headers.rend(); ++it) {
            if (strcasecmp(it->key.c_str(), "DKIM-Signature") == 0) {
                dkim_val = it->value;
                break;
            }
        }

        if (dkim_val.empty()) {
            sprint("[SERVER DKIM ", this_thread::get_id(), "] No DKIM-Signature header found!", '\n');
            return false;
        }

        map<string, string> tags;
        stringstream ss(dkim_val);
        string token;
        while (getline(ss, token, ';')) {
            size_t eq = token.find('=');
            if (eq != string::npos) {
                string key = token.substr(0, eq);
                string val = token.substr(eq + 1);

                key.erase(0, key.find_first_not_of(" \t\r\n"));
                key.erase(key.find_last_not_of(" \t\r\n") + 1);
                val.erase(0, val.find_first_not_of(" \t\r\n"));
                val.erase(val.find_last_not_of(" \t\r\n") + 1);

                tags[key] = val;
            }
        }

        if (tags["d"].empty() || tags["s"].empty() || tags["b"].empty() || tags["bh"].empty() || tags["h"].empty()) {
            sprint("[SERVER DKIM ", this_thread::get_id(), "] Missing required DKIM tags!", '\n');
            return false;
        }

        string pkey = get_dkim_pkey(tags["d"], tags["s"]);
        if (pkey.empty()) {
            sprint("[SERVER DKIM ", this_thread::get_id(), "] Error couldn't fetch public key from DNS!", '\n');
            return false;
        }

        string pem_key = "-----BEGIN PUBLIC KEY-----\n";
        for (size_t i = 0; i < pkey.length(); i += 64)
            pem_key += pkey.substr(i, 64) + "\n";
        pem_key += "-----END PUBLIC KEY-----\n";

        BIO* bio = BIO_new_mem_buf(pem_key.data(), pem_key.length());
        EVP_PKEY* p_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!p_key) {
            sprint("[SERVER DKIM ", this_thread::get_id(), "] Failed to parse public key in OpenSSL", '\n');
            return false;
        }

        string canonical_body = canonicalize_body_relaxed(mail.corp.body);
        unsigned char computed_bh[EVP_MAX_MD_SIZE];
        unsigned int bh_len = 0;

        const EVP_MD* md_type = (tags["a"] == "rsa-sha1") ? EVP_sha1() : EVP_sha256();

        EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();
        EVP_DigestInit(hash_ctx, md_type);
        EVP_DigestUpdate(hash_ctx, (unsigned char*)canonical_body.c_str(), canonical_body.length());
        EVP_DigestFinal(hash_ctx, computed_bh, &bh_len);
        EVP_MD_CTX_free(hash_ctx);

        string computed_bh_b64 = base64_encode(computed_bh, bh_len);
        if (computed_bh_b64 != tags["bh"]) {
            sprint("[SERVER DKIM ", this_thread::get_id(), "] Body Hash Missmatch!", '\n');
            EVP_PKEY_free(p_key);
            return false;
        }

        stringstream h_ss(tags["h"]);
        string header_name;
        string headers_to_verify = "";

        while (getline(h_ss, header_name, ':')) {
            header_name.erase(0, header_name.find_first_not_of(" \t\r\n"));
            header_name.erase(header_name.find_last_not_of(" \t\r\n") + 1);

            bool found = false;
            for (auto it = parsed_headers.rbegin(); it != parsed_headers.rend(); ++it) {
                if (!it->used_for_dkim && strcasecmp(it->key.c_str(), header_name.c_str()) == 0) {
                    headers_to_verify += canonicalize_header_relaxed(it->key, it->value) + "\r\n";
                    it->used_for_dkim = true;
                    found = true;
                    break;
                }
            }
            if (!found) {
                sprint("[SERVER DKIM ", this_thread::get_id(), "] Could not find header instance for h= list: ", header_name, '\n');
                EVP_PKEY_free(p_key);
                return false;
            }
        }

        // remove trailing CRLF added in the loop to match signing behavior
        if (!headers_to_verify.empty() && headers_to_verify.size() >= 2)
            headers_to_verify = headers_to_verify.substr(0, headers_to_verify.size() - 2);

        size_t b_pos = dkim_val.find("b=");
        string dkim_no_b = dkim_val.substr(0, b_pos + 2);

        string data_to_verify = headers_to_verify + "\r\n" + canonicalize_header_relaxed("DKIM-Signature", dkim_no_b);

        string sig_raw = base64_decode(tags["b"]);

        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        EVP_VerifyInit(md_ctx, md_type);
        cout << "--- HEADERS TO VERIFY ---" << endl;
        cout << data_to_verify;
        cout << "-------------------------" << endl;
        EVP_VerifyUpdate(md_ctx, (unsigned char*)data_to_verify.c_str(), data_to_verify.length());

        int res = EVP_VerifyFinal(md_ctx, (unsigned char*)sig_raw.c_str(), sig_raw.length(), p_key);

        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(p_key);

        if (res == 1) {
            sprint("[SERVER DKIM ", this_thread::get_id(), "] Success: DKIM Signature Validated!", '\n');
            return true;
        } else {
            sprint("[SERVER DKIM ", this_thread::get_id(), "] Fail: Signature Verification Failed!", '\n');
            return false;
        }
    }
    catch (const exception& e) {
        sprint("[SERVER DKIM ", this_thread::get_id(), "] Error: ", e.what(), '\n');
        return false;
    }
}

string get_dmarc_policy(const string& domain)
{
    string dmarc_dns = "_dmarc." + domain;
    unsigned char response[2048];

    struct __res_state stat;
    memset(&stat, 0, sizeof(stat));
    if (res_ninit(&stat) != 0)
        return "none";
    
    int length = res_nsearch(&stat, dmarc_dns.c_str(), ns_c_in, ns_t_txt, response, sizeof(response));
    if (length < 0)
    {
        res_nclose(&stat);
        return "none";
    }

    ns_msg handle;
    if (ns_initparse(response, length, &handle) < 0)
    {
        res_nclose(&stat);
        return "none";
    }

    string policy = "none";
    int count = ns_msg_count(handle, ns_s_an);
    for (int i = 0; i < count; i++)
    {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0)
            continue;
        
        if (ns_rr_type(rr) == ns_t_txt)
        {
            const unsigned char* data = ns_rr_rdata(rr);
            int txt_len = data[0];

            string txt_record((const char*)(data + 1), txt_len);

            size_t pos = txt_record.find("p=");
            if (pos != string::npos)
            {
                string p_val = txt_record.substr(pos + 2);
                size_t end_p = p_val.find_first_of("; ");
                if (end_p != string::npos)
                    p_val = p_val.substr(0, end_p);
                policy = p_val;
                break;
            }
        }
    }

    res_nclose(&stat);
    return policy;
}

DMARCresult verify_dmarc(const email& mail, bool spf_pass, const string& spf_domain, bool dkim_pass, const string& dkim_domain)
{
    DMARCresult result;
    result.pass = false;
    result.policy = "none";

    auto it = mail.corp.headers.find("From");
    if (it == mail.corp.headers.end())
    {
        result.reason = "Missing From header";
        return result;
    }

    string from_address = extract_address(it->second);
    MAILaddress from_mail = split_address(from_address.c_str());
    string from_domain = from_mail.domain;

    transform(from_domain.begin(), from_domain.end(), from_domain.begin(), ::tolower);

    if (from_domain.empty())
    {
        result.reason = "Invalid From domain";
        return result;
    }

    result.policy = get_dmarc_policy(from_domain);

    string spf_dom_clean = spf_domain;
    transform(spf_dom_clean.begin(), spf_dom_clean.end(), spf_dom_clean.begin(), ::tolower);
    bool spf_aligned = spf_pass && (from_domain == spf_dom_clean || from_domain.ends_with("." + spf_dom_clean));

    string dkim_dom_clean = dkim_domain;
    transform(dkim_dom_clean.begin(), dkim_dom_clean.end(), dkim_dom_clean.begin(), ::tolower);
    bool dkim_aligned = dkim_pass && (from_domain == dkim_dom_clean || from_domain.ends_with("." + dkim_dom_clean));

    if (spf_aligned || dkim_aligned)
    {
        result.pass = true;
        result.reason = "DMARC passed (SPF aligned: " + string(spf_aligned ? "yes" : "no") + 
                        ", DKIM aligned: " + string(dkim_aligned ? "yes" : "no") + ")";
    }
    else
    {
        result.pass = false;
        result.reason = "DMARC failed alignment";
    }
    
    return result;
}