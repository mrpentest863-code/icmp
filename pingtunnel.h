#ifndef PINGTUNNEL_H
#define PINGTUNNEL_H

#include <cstdint>
#include <vector>
#include <string>
#include <netinet/in.h>

struct MyMsg {
    std::string id;
    int32_t type = 0;
    std::string target;
    std::vector<uint8_t> data;
    int32_t rproto = 0;
    int32_t magic = 0;
    int32_t key = 0;
    int32_t timeout = 0;
    int32_t tcpmode = 0;
    int32_t tcpmode_buffersize = 0;
    int32_t tcpmode_maxwin = 0;
    int32_t tcpmode_resend_timems = 0;
    int32_t tcpmode_compress = 0;
    int32_t tcpmode_stat = 0;
    std::string username;
    std::string password;
};

constexpr int SEND_PROTO = 8;
constexpr int RECV_PROTO = 0;
constexpr int32_t MyMsg_MAGIC = 57005;
constexpr int32_t MyMsg_DATA = 0;
constexpr int32_t MyMsg_PING = 1;
constexpr int32_t MyMsg_KICK = 2;

std::vector<uint8_t> marshalMyMsg(const MyMsg& msg);
bool unmarshalMyMsg(const std::vector<uint8_t>& data, MyMsg& msg);

#endif
