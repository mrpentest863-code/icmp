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
#include <fcntl.h>
#include "pingtunnel.h"

std::atomic<bool> running{true};
int icmp_sock;
sockaddr_in server_addr;
std::string username, password;
int sequence = 0;
int vpn_fd = -1;

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

void vpn_to_icmp_loop() {
    std::vector<uint8_t> buffer(4096);
    while (running) {
        ssize_t n = read(vpn_fd, buffer.data(), buffer.size());
        if (n <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        // Encapsuler chaque paquet IP dans un message ICMP
        std::string conn_id = "vpn"; // identifiant de connexion simplifié
        std::vector<uint8_t> data(buffer.begin(), buffer.begin() + n);
        send_icmp(conn_id, data, MyMsg_DATA);
    }
}

void icmp_to_vpn_loop() {
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
            write(vpn_fd, msg.data.data(), msg.data.size());
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <user> <pass> <vpn_fd>\n";
        return 1;
    }
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &server_addr.sin_addr);
    username = argv[2];
    password = argv[3];
    vpn_fd = std::stoi(argv[4]);

    icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) { perror("socket icmp"); return 1; }

    std::thread(vpn_to_icmp_loop).detach();
    std::thread(icmp_to_vpn_loop).detach();

    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    close(icmp_sock);
    return 0;
}
