#include <iostream>
#include <thread>
#include <atomic>
#include <cstring>
#include <vector>
#include <map>
#include <mutex>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "pingtunnel.h"

std::atomic<bool> running{true};
int icmp_sock;
sockaddr_in server_addr;
std::string username, password;
int sequence = 0;
std::map<std::string, int> tcp_conns;
std::mutex conns_mutex;

void send_icmp(const std::string& conn_id, const std::vector<uint8_t>& data, int type) {
    MyMsg msg;
    msg.id = conn_id;
    msg.type = type;
    msg.data = data;
    msg.magic = MyMsg_MAGIC;
    msg.key = 0;
    msg.username = username;
    msg.password = password;

    std::vector<uint8_t> mb = marshalMyMsg(msg);

    size_t total_len = sizeof(struct icmphdr) + mb.size();
    std::vector<uint8_t> packet(total_len);
    struct icmphdr* hdr = reinterpret_cast<struct icmphdr*>(packet.data());
    hdr->type = ICMP_ECHO;
    hdr->code = 0;
    hdr->checksum = 0;
    hdr->un.echo.id = htons(0x1234);
    hdr->un.echo.sequence = htons(sequence++);
    std::copy(mb.begin(), mb.end(), packet.begin() + sizeof(struct icmphdr));

    uint32_t sum = 0;
    for (size_t i = 0; i < packet.size(); i += 2) {
        uint16_t word = packet[i];
        if (i + 1 < packet.size()) word = (word << 8) | packet[i + 1];
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    hdr->checksum = ~static_cast<uint16_t>(sum);

    sendto(icmp_sock, packet.data(), packet.size(), 0,
           reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr));
}

void recv_icmp_loop() {
    std::vector<uint8_t> buffer(4096);
    while (running) {
        sockaddr_in src{};
        socklen_t len = sizeof(src);
        ssize_t n = recvfrom(icmp_sock, buffer.data(), buffer.size(), 0,
                             reinterpret_cast<struct sockaddr*>(&src), &len);
        if (n <= 8) continue;

        std::vector<uint8_t> payload(buffer.begin() + 8, buffer.begin() + n);
        MyMsg msg;
        if (!unmarshalMyMsg(payload, msg)) continue;
        if (msg.magic != MyMsg_MAGIC) continue;

        if (msg.type == MyMsg_DATA) {
            std::lock_guard<std::mutex> lock(conns_mutex);
            auto it = tcp_conns.find(msg.id);
            if (it != tcp_conns.end()) {
                send(it->second, msg.data.data(), msg.data.size(), 0);
            }
        }
    }
}

void handle_tcp_conn(int client_fd) {
    uint8_t buffer[256];
    recv(client_fd, buffer, 2, 0);
    int nmethods = buffer[1];
    recv(client_fd, buffer, nmethods, 0);
    buffer[0] = 5; buffer[1] = 0;
    send(client_fd, buffer, 2, 0);

    recv(client_fd, buffer, 4, 0);
    int atyp = buffer[3];
    std::string target_addr;
    if (atyp == 1) {
        uint8_t ip[4]; recv(client_fd, ip, 4, 0);
        uint16_t port; recv(client_fd, &port, 2, 0);
        port = ntohs(port);
        target_addr = std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." +
                      std::to_string(ip[2]) + "." + std::to_string(ip[3]) + ":" + std::to_string(port);
    } else if (atyp == 3) {
        uint8_t len; recv(client_fd, &len, 1, 0);
        std::vector<char> domain(len); recv(client_fd, domain.data(), len, 0);
        uint16_t port; recv(client_fd, &port, 2, 0);
        port = ntohs(port);
        target_addr = std::string(domain.begin(), domain.end()) + ":" + std::to_string(port);
    } else {
        close(client_fd);
        return;
    }

    buffer[0] = 5; buffer[1] = 0; buffer[2] = 0; buffer[3] = 1;
    uint8_t resp[] = {0,0,0,0,0,0};
    send(client_fd, buffer, 4, 0);
    send(client_fd, resp, 6, 0);

    std::string conn_id = std::to_string(client_fd);
    {
        std::lock_guard<std::mutex> lock(conns_mutex);
        tcp_conns[conn_id] = client_fd;
    }

    while (running) {
        ssize_t n = recv(client_fd, buffer, sizeof(buffer), 0);
        if (n <= 0) break;
        std::vector<uint8_t> data(buffer, buffer + n);
        send_icmp(conn_id, data, MyMsg_DATA);
    }

    close(client_fd);
    std::lock_guard<std::mutex> lock(conns_mutex);
    tcp_conns.erase(conn_id);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <user> <pass>\n";
        return 1;
    }
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &server_addr.sin_addr);
    username = argv[2];
    password = argv[3];

    icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) { perror("socket icmp"); return 1; }

    std::thread(recv_icmp_loop).detach();

    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(1080);
    local.sin_addr.s_addr = INADDR_ANY;
    bind(tcp_sock, (struct sockaddr*)&local, sizeof(local));
    listen(tcp_sock, 5);

    std::cout << "Client C++ en écoute sur 1080" << std::endl;

    while (running) {
        int fd = accept(tcp_sock, nullptr, nullptr);
        if (fd >= 0) std::thread(handle_tcp_conn, fd).detach();
    }

    close(tcp_sock);
    close(icmp_sock);
    return 0;
}
