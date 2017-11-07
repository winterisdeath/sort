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
public:
    unsigned int reserved;
    unsigned int fragment;
    unsigned int more_fragments;
};
struct ip_address
{
public:
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
    QString source_string();
    QString destination_string();
    QString out();
    packet();
    packet(const packet& temp);
    ~packet();
    packet& operator = (const packet& temp);
    bool operator < (const packet& temp);
};

#endif // PACKET_H
