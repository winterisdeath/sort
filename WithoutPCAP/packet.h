#ifndef PACKET_H
#define PACKET_H
#include <string>
#include <QString>

struct service_type
{
public:
    unsigned int priority;
    unsigned int delay;
    unsigned int throughput;
    unsigned int reliability;
    unsigned int ECN;
};

struct flags
{
    unsigned int reserved;
    unsigned int fragment;
    unsigned int more_fragments;
};
struct ip_address
{
    unsigned int x1;
    unsigned int x2;
    unsigned int x3;
    unsigned int x4;
};

class packet
{
public:
    service_type service;
    flags flag;
    ip_address sourse;
    ip_address destination;
    unsigned int total_len;
    unsigned int identification;
    unsigned int fragment_offset;
    unsigned int ttl;
    unsigned int protocol;
    unsigned int checksum;
    unsigned int source_int();
    QString source_string();
    unsigned int destination_int();
    QString destination_string();
    QString out();
    packet();
    ~packet();
};

#endif // PACKET_H
