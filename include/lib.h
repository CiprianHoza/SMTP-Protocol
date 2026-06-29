#ifndef _LIB_H
#define _LIB_H

#include "packet.h"

//send email
extern void send_mail(int sockfd, email mail);

//error function after send/recv
extern void error(int code);

//check_error function for response server
extern void check_error(char* response);

#endif