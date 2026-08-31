#include "pingtunnel.h"
#include <cstring>

std::vector<uint8_t> marshalMyMsg(const MyMsg& msg) {
    std::vector<uint8_t> out;
    auto appendStr = [&](const std::string& s) {
        uint32_t len = s.size();
        out.push_back(len & 0xFF);
        out.push_back((len >> 8) & 0xFF);
        out.push_back((len >> 16) & 0xFF);
        out.push_back((len >> 24) & 0xFF);
        out.insert(out.end(), s.begin(), s.end());
    };
    auto appendInt32 = [&](int32_t v) {
        out.push_back(v & 0xFF);
        out.push_back((v >> 8) & 0xFF);
        out.push_back((v >> 16) & 0xFF);
        out.push_back((v >> 24) & 0xFF);
    };
    auto appendBytes = [&](const std::vector<uint8_t>& d) {
        uint32_t len = d.size();
        appendInt32(static_cast<int32_t>(len));
        out.insert(out.end(), d.begin(), d.end());
    };

    appendStr(msg.id);
    appendInt32(msg.type);
    appendStr(msg.target);
    appendBytes(msg.data);
    appendInt32(msg.rproto);
    appendInt32(msg.magic);
    appendInt32(msg.key);
    appendInt32(msg.timeout);
    appendInt32(msg.tcpmode);
    appendInt32(msg.tcpmode_buffersize);
    appendInt32(msg.tcpmode_maxwin);
    appendInt32(msg.tcpmode_resend_timems);
    appendInt32(msg.tcpmode_compress);
    appendInt32(msg.tcpmode_stat);
    appendStr(msg.username);
    appendStr(msg.password);
    return out;
}

bool unmarshalMyMsg(const std::vector<uint8_t>& data, MyMsg& msg) {
    size_t pos = 0;
    auto readStr = [&](std::string& s) -> bool {
        if (pos + 4 > data.size()) return false;
        uint32_t len = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
        pos += 4;
        if (pos + len > data.size()) return false;
        s.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    };
    auto readInt32 = [&](int32_t& v) -> bool {
        if (pos + 4 > data.size()) return false;
        v = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
        pos += 4;
        return true;
    };
    auto readBytes = [&](std::vector<uint8_t>& d) -> bool {
        int32_t len;
        if (!readInt32(len) || len < 0 || pos + len > data.size()) return false;
        d.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    };

    return readStr(msg.id) &&
           readInt32(msg.type) &&
           readStr(msg.target) &&
           readBytes(msg.data) &&
           readInt32(msg.rproto) &&
           readInt32(msg.magic) &&
           readInt32(msg.key) &&
           readInt32(msg.timeout) &&
           readInt32(msg.tcpmode) &&
           readInt32(msg.tcpmode_buffersize) &&
           readInt32(msg.tcpmode_maxwin) &&
           readInt32(msg.tcpmode_resend_timems) &&
           readInt32(msg.tcpmode_compress) &&
           readInt32(msg.tcpmode_stat) &&
           readStr(msg.username) &&
           readStr(msg.password);
}
