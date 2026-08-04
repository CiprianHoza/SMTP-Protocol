#ifndef _LIB_H
#define _LIB_H

#include "packet.h"
#include <thread>
#include <mutex>
#include <utility>

//safe print method for multithreading
class ThreadPrint
{
    private:
        static inline mutex mtx;
    
    public:
        template <typename... Args>
        void operator()(Args&&... args) const 
        {
            lock_guard<mutex> lock(mtx);
            (cout << ... << forward<Args>(args)) << '\n';
        }
};

inline constexpr ThreadPrint sprint;

//send email
extern void send_mail(int sockfd, email mail, string smtp_domain);

//receive email
extern email receive_email(int sockfd, SSL_CTX* ctx, string smtp_domain, string mail_domain);

//error function after send/recv
extern void error(int code);

//check_error function for response server
extern void check_error(char* response);

//parse email addresses
extern map<string, vector<string>> domains(vector<string> recipients);

//get mx servers from given domain
extern vector<string> get_mx_servers(const string& domain);

//parse .env file
extern void load_env(const string& filename = ".env");

//get local date
extern string get_date();

//initiate SSL context
extern SSL_CTX* init_server_ssl_context();

//deliver mail to Dovecot to store on database
extern bool deliver_to_dovecot_lmtp(email& mail);

//receive email from user agent
extern email receive_from_ua(int sockfd, SSL_CTX* ctx, string smtp_domain, string mail_domain);

#endif