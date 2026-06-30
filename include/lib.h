#ifndef _LIB_H
#define _LIB_H

#include "packet.h"

//send email
extern void send_mail(int sockfd, email mail);

//error function after send/recv
extern void error(int code);

//check_error function for response server
extern void check_error(char* response);

//parse email addresses
extern map<string, vector<string>> domains(vector<string> recipients);

//get mx servers from given domain
extern vector<string> get_mx_servers(const string& domain);

#endif