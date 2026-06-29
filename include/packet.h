#ifndef PACKET_H
#define PACKET_H

#include <bits/stdc++.h>

using namespace std;

typedef struct 
{
    string sender;
    vector<string> recipients;
}envelope;

typedef struct
{
    map<string, string> headers;
    string body;
}emailData;

typedef struct
{
    envelope anvelopa;
    emailData corp;
}email;

#endif